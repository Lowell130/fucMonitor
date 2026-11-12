"""Derived labels for news items, rebuilt from the raw items with the rules in rules.json.

Raw items are never changed. This module writes one derived table,
    derived/news/enriched.parquet
with, for each item: the type of event, whether the text reports exploitation, how firm
the claim is, the sectors mentioned, and the story it belongs to.

A story groups items from *different feeds* that report the same thing: same language,
titles sharing most of their words, published within three days. The same story in Italian
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
STORY_SIMILARITY = 0.6
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
    """item_id -> (story_id, number of distinct feeds in the story)."""
    parent = {i["item_id"]: i["item_id"] for i in items}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    prepared = []
    frequency: dict[str, int] = {}
    for item in items:
        tokens = title_tokens(item["title"])
        prepared.append((item, tokens))
        for token in tokens:
            frequency[token] = frequency.get(token, 0) + 1
    prepared.sort(key=lambda pair: pair[0]["when"])

    postings: dict[str, list[int]] = {}
    for index, (item, tokens) in enumerate(prepared):
        if len(tokens) < STORY_MIN_TOKENS:
            continue
        # Candidates are found through the item's rarest words, which keeps this fast.
        rare = sorted(tokens, key=lambda t: (frequency[t], t))[:3]
        seen: set[int] = set()
        for token in rare:
            for other_index in reversed(postings.get(token, [])):
                other, other_tokens = prepared[other_index]
                if item["when"] - other["when"] > STORY_WINDOW:
                    break
                if other_index in seen:
                    continue
                seen.add(other_index)
                if other["feed_id"] == item["feed_id"] or other["language"] != item["language"]:
                    continue
                if item["cves"] and other["cves"] and not (item["cves"] & other["cves"]):
                    continue  # two different vulnerabilities are never the same story
                overlap = len(tokens & other_tokens) / len(tokens | other_tokens)
                if overlap >= STORY_SIMILARITY:
                    a, b = find(item["item_id"]), find(other["item_id"])
                    if a != b:
                        parent[max(a, b)] = min(a, b)
        for token in tokens:
            postings.setdefault(token, []).append(index)

    feeds: dict[str, set[str]] = {}
    for item in items:
        feeds.setdefault(find(item["item_id"]), set()).add(item["feed_id"])
    return {i["item_id"]: (find(i["item_id"]), len(feeds[find(i["item_id"])])) for i in items}


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
