"""Derived labels for news items, rebuilt from the raw items with the rules in rules.json.

Raw items are never changed. This module writes one derived table,
    derived/news/enriched.parquet
with, for each item: the type of event, whether the text reports exploitation, how firm
the claim is, the sectors mentioned, and the story it belongs to.

A story groups items from *different feeds* that report the same thing: same language,
titles sharing several words, published within three days. The grouping is approximate. The same story in Italian
and in English is still two stories; that needs a multilingual model and comes later.

Labels come from keyword rules. They are deliberately simple and will be wrong on some
items; `rules_version` is stored so every label can be traced to the rules that made it.
No country or actor is extracted, by design.
"""

import json
import os
import re
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from .. import state
from ..config import Settings
from ..sources import SOURCES

RULES_FILE = Path(__file__).with_name("rules.json")
STORY_WINDOW = timedelta(hours=72)
# Tuned on the first real collection (341 press and advisory items, 12 Nov 2026): at 0.6 only
# near-identical headlines matched; at 0.3 with four shared words, 10 pairs matched and about
# 8 were the same story. Headlines that share fewer words are still missed.
STORY_SIMILARITY = 0.3
STORY_MIN_SHARED = 4
STORY_MIN_TOKENS = 4

SCHEMA = pa.schema(
    [
        ("item_id", pa.string()),
        ("event_type", pa.string()),
        ("exploitation_signal", pa.bool_()),
        ("claim_status", pa.string()),
        ("target_sectors", pa.list_(pa.string())),
        ("story_id", pa.string()),
        ("story_feeds", pa.int32()),
        ("rules_version", pa.string()),
    ]
)

_TOKEN = re.compile(r"[a-z0-9àèéìíòóùú]+")
_STOPWORDS = frozenset(
    """the and for with from that this are was were has have had its their into over after about new
    how why what when who will can could more than not but you your all out now says said amid via
    per con del della dello dei degli delle dal dalla dai nel nella nei nelle sul sulla sui che non
    una uno gli alla alle allo agli come anche dopo più tra fra sono stato stata era gli suo sua loro
    ecco cosa perché""".split()
)


@lru_cache
def load_rules() -> dict:
    raw = json.loads(RULES_FILE.read_text(encoding="utf-8"))

    def compile_all(patterns: list[str]) -> re.Pattern:
        return re.compile("|".join(f"(?:\\b(?:{p}))" for p in patterns))

    return {
        "version": raw["version"],
        "event_types": [(r["id"], compile_all(r["patterns"])) for r in raw["event_types"]],
        "target_sectors": [(r["id"], compile_all(r["patterns"])) for r in raw["target_sectors"]],
        "exploitation": compile_all(raw["exploitation"]),
        "disclosure": compile_all(raw["disclosure"]),
        "unverified": compile_all(raw["unverified"]),
    }


def classify(title: str, summary: str, source_kind: str, cve_ids: list[str]) -> dict:
    rules = load_rules()
    text = f"{title} {summary}".casefold()
    exploited = bool(rules["exploitation"].search(text))

    event = next((eid for eid, pattern in rules["event_types"] if pattern.search(text)), None)
    if event is None:
        if exploited:
            event = "vulnerability_exploitation"
        elif cve_ids or rules["disclosure"].search(text):
            event = "vulnerability_disclosure"
        else:
            event = "other"

    if source_kind == "primary":
        claim = "official"
    elif rules["unverified"].search(text):
        claim = "unverified"
    else:
        claim = "reported"

    return {
        "event_type": event,
        "exploitation_signal": exploited,
        "claim_status": claim,
        "target_sectors": [sid for sid, pattern in rules["target_sectors"] if pattern.search(text)],
    }


def title_tokens(title: str) -> frozenset[str]:
    return frozenset(t for t in _TOKEN.findall(title.casefold()) if len(t) >= 3 and t not in _STOPWORDS)


def assign_stories(items: list[dict]) -> dict[str, tuple[str, int]]:
    """item_id -> (story_id, number of distinct feeds in the story).

    Items are read in time order. Each one joins the best-matching story that another feed
    opened in the last three days, or opens a new story. An item is only ever compared with
    the *first* item of a story, so a story cannot drift from one subject to another.
    """
    prepared = sorted(((item, title_tokens(item["title"])) for item in items),
                      key=lambda pair: (pair[0]["when"], pair[0]["item_id"]))
    frequency: dict[str, int] = {}
    for _, tokens in prepared:
        for token in tokens:
            frequency[token] = frequency.get(token, 0) + 1

    story_of: dict[str, str] = {}
    leaders: list[tuple[dict, frozenset[str]]] = []
    postings: dict[str, list[int]] = {}  # word -> positions in `leaders`, oldest first
    for item, tokens in prepared:
        best, best_score = None, 0.0
        if len(tokens) >= STORY_MIN_TOKENS:
            seen: set[int] = set()
            for token in tokens:
                for position in reversed(postings.get(token, [])):
                    leader, leader_tokens = leaders[position]
                    if item["when"] - leader["when"] > STORY_WINDOW:
                        break
                    if position in seen:
                        continue
                    seen.add(position)
                    if leader["feed_id"] == item["feed_id"] or leader["language"] != item["language"]:
                        continue
                    if item["cves"] and leader["cves"] and not (item["cves"] & leader["cves"]):
                        continue  # two different vulnerabilities are never the same story
                    shared = len(tokens & leader_tokens)
                    score = shared / len(tokens | leader_tokens)
                    if shared >= STORY_MIN_SHARED and score >= STORY_SIMILARITY and score > best_score:
                        best, best_score = leader, score
        if best is not None:
            story_of[item["item_id"]] = best["item_id"]
            continue
        story_of[item["item_id"]] = item["item_id"]
        if len(tokens) >= STORY_MIN_TOKENS:
            leaders.append((item, tokens))
            for token in tokens:
                # Very common words would make every item a candidate; they add nothing.
                if frequency[token] <= max(50, len(prepared) // 20):
                    postings.setdefault(token, []).append(len(leaders) - 1)

    feeds: dict[str, set[str]] = {}
    for item, _ in prepared:
        feeds.setdefault(story_of[item["item_id"]], set()).add(item["feed_id"])
    return {item_id: (story, len(feeds[story])) for item_id, story in story_of.items()}


# --- storage -------------------------------------------------------------------
def enriched_path(settings: Settings) -> Path:
    return settings.data_dir / "derived" / "news" / "enriched.parquet"


def _raw_files(settings: Settings) -> list[str]:
    source = SOURCES["news"]
    return [source.curated_path(settings, d).as_posix() for d in source.snapshot_dates(settings)]


def is_current(settings: Settings) -> bool:
    """True when the derived table exists, uses the current rules and covers every raw item."""
    path, files = enriched_path(settings), _raw_files(settings)
    if not files:
        return True
    if not path.exists():
        return False
    con = duckdb.connect()
    try:
        versions = con.execute(
            "SELECT DISTINCT rules_version FROM read_parquet(?)", [path.as_posix()]
        ).fetchall()
        if versions != [(load_rules()["version"],)]:
            return False
        missing = con.execute(
            "SELECT count(*) FROM read_parquet(?) r ANTI JOIN read_parquet(?) e USING (item_id)",
            [files, path.as_posix()],
        ).fetchone()[0]
        return missing == 0
    finally:
        con.close()


def rebuild(settings: Settings) -> int:
    """Recompute every label from the raw items. Returns the number of items labelled."""
    files = _raw_files(settings)
    if not files:
        return 0
    con = duckdb.connect()
    try:
        cursor = con.execute(
            """SELECT item_id, feed_id, source_kind, language, title, summary, cve_ids,
                      epoch(coalesce(published_at, first_seen_at)) AS at
               FROM read_parquet(?)""",
            [files],
        )
        columns = [c[0] for c in cursor.description]
        raw = [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        con.close()

    version = load_rules()["version"]
    for item in raw:
        item["when"] = datetime.fromtimestamp(item["at"], tz=state.utcnow().tzinfo)
        item["cves"] = frozenset(item["cve_ids"] or [])
    stories = assign_stories(raw)
    rows = []
    for item in raw:
        story_id, story_feeds = stories[item["item_id"]]
        rows.append(
            {
                "item_id": item["item_id"],
                **classify(item["title"] or "", item["summary"] or "", item["source_kind"], item["cve_ids"] or []),
                "story_id": story_id,
                "story_feeds": story_feeds,
                "rules_version": version,
            }
        )
    target = enriched_path(settings)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name("enriched.parquet.tmp")
    pq.write_table(pa.Table.from_pylist(rows, schema=SCHEMA), tmp, compression="zstd")
    os.replace(tmp, target)
    return len(rows)
