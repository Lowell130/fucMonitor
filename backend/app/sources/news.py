"""News harvester: raw collection of RSS/Atom items from the feeds in feeds.json.

What is stored, per item: title, link, a short plain-text summary, publication time,
the time *we* first saw it, feed, language, kind of source, and the CVE IDs it mentions.
Full articles and raw feed files are not stored.

`first_seen_at` is the timestamp that matters for modelling: an article can only be a
feature from the moment we collected it. `published_at` comes from the publisher and is
kept for display.

Items are grouped by the UTC day we first saw them:
    curated/news/snapshot_date=<day>/data.parquet
An item is identified by feed + guid (or link), so re-fetching a feed adds nothing.
The same story reported by two feeds is two items; cross-feed deduplication comes later.

Feed text is third-party data. It is stored and displayed, never interpreted.
"""

import hashlib
import html
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import duckdb
import httpx
import pyarrow as pa
import pyarrow.parquet as pq

from .. import state
from ..config import Settings
from .base import IngestResult, Source

FEEDS_FILE = Path(__file__).with_name("feeds.json")
MAX_FEED_BYTES = 10 * 1024 * 1024
FEED_TIMEOUT = 30.0  # seconds; a slow feed must not hold up the others
KINDS = ("primary", "specialist", "general")

SCHEMA = pa.schema(
    [
        ("item_id", pa.string()),
        ("feed_id", pa.string()),
        ("feed_title", pa.string()),
        ("source_kind", pa.string()),
        ("language", pa.string()),
        ("title", pa.string()),
        ("link", pa.string()),
        ("summary", pa.string()),
        ("published_at", pa.timestamp("s", tz="UTC")),
        ("first_seen_at", pa.timestamp("s", tz="UTC")),
        ("cve_ids", pa.list_(pa.string())),
    ]
)

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_TAG = re.compile(r"<[^>]{0,2000}>")
_SPACE = re.compile(r"\s+")


def load_feeds(settings: Settings) -> dict:
    path = settings.news_feeds_file or FEEDS_FILE
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    seen = set()
    for feed in config["feeds"]:
        if feed["id"] in seen:
            raise ValueError(f"Duplicate feed id '{feed['id']}' in {path}")
        if feed["kind"] not in KINDS:
            raise ValueError(f"Feed '{feed['id']}': unknown kind '{feed['kind']}'")
        seen.add(feed["id"])
    return config


# --- parsing -------------------------------------------------------------------
def clean_text(value: str | None, limit: int) -> str:
    """Plain text from a feed field: tags removed, entities decoded, whitespace collapsed."""
    if not value:
        return ""
    text = html.unescape(_TAG.sub(" ", html.unescape(value)))
    text = _SPACE.sub(" ", _TAG.sub(" ", text)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def parse_date(value: str | None) -> datetime | None:
    if not value or not value.strip():
        return None
    value = value.strip()
    parsed = None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.astimezone(timezone.utc).replace(microsecond=0)
    except (OverflowError, ValueError):
        return None


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def parse_feed(content: bytes) -> list[dict]:
    """Entries of an RSS 2.0, RSS 1.0 (RDF) or Atom document, as plain dicts."""
    content = content.lstrip(b"\xef\xbb\xbf \t\r\n")
    if content[:200].lower().lstrip().startswith((b"<!doctype html", b"<html")):
        raise ValueError("the address returned a web page, not a feed (moved or blocked?)")
    if b"<!ENTITY" in content[:4096]:
        raise ValueError("feed declares XML entities; refused")
    root = ET.fromstring(content)
    entries = []
    for element in root.iter():
        if _local(element.tag) not in ("item", "entry"):
            continue
        fields: dict[str, str] = {}
        for child in element:
            name = _local(child.tag)
            text = (child.text or "").strip()
            if name == "link":
                href = child.attrib.get("href", "").strip()
                rel = child.attrib.get("rel", "alternate")
                if href and rel == "alternate":
                    fields.setdefault("link", href)
                elif text:
                    fields.setdefault("link", text)
            elif name in ("title", "guid", "id") and text:
                fields.setdefault("guid" if name == "id" else name, text)
            elif name in ("pubdate", "published", "date") and text:
                fields.setdefault("published", text)
            elif name == "updated" and text:
                fields.setdefault("updated", text)
            elif name in ("description", "summary") and text:
                fields.setdefault("summary", text)
            elif name in ("content", "encoded") and text:
                fields.setdefault("content", text)
        entries.append(fields)
    return entries


def normalise(entry: dict, feed: dict, seen_at: datetime, keywords: list[str]) -> dict | None:
    title = clean_text(entry.get("title"), 500)
    link = entry.get("link", "").strip()
    if not link.lower().startswith(("http://", "https://")):
        guid = entry.get("guid", "")
        link = guid if guid.lower().startswith(("http://", "https://")) else ""
    key = entry.get("guid") or link or title
    if not key or not (title or link):
        return None
    body = entry.get("summary") or entry.get("content") or ""
    summary = clean_text(body, 600)
    if feed["kind"] == "general":
        haystack = f"{title} {summary}".casefold()
        if not any(k in haystack for k in keywords):
            return None
    published = parse_date(entry.get("published")) or parse_date(entry.get("updated"))
    if published and published > seen_at + timedelta(days=1):
        published = None  # a date in the future is a publisher error
    # CVE IDs are searched in the full text, before the summary is shortened.
    cves = sorted({m.upper() for m in _CVE.findall(f"{title} {html.unescape(body)}")})
    return {
        "item_id": hashlib.sha256(f"{feed['id']}\n{key}".encode()).hexdigest()[:32],
        "feed_id": feed["id"],
        "feed_title": feed["title"],
        "source_kind": feed["kind"],
        "language": feed["language"],
        "title": title,
        "link": link[:2000],
        "summary": summary,
        "published_at": published,
        "first_seen_at": seen_at,
        "cve_ids": cves,
    }


# --- source --------------------------------------------------------------------
class NewsSource(Source):
    name = "news"
    title = "News and advisories (RSS)"
    homepage = "https://github.com/Lowell130/fucMonitor/blob/main/backend/app/sources/feeds.json"
    cadence = "interval"

    def ingest(self, settings: Settings, client: httpx.Client) -> IngestResult:
        config = load_feeds(settings)
        keywords = [k.casefold() for k in config.get("general_keywords", [])]
        feeds = [f for f in config["feeds"] if f.get("enabled", True)]
        previous = state.feed_states(settings.state_db)
        seen_at = state.utcnow().replace(microsecond=0)

        rows: list[dict] = []
        outcomes: list[dict] = []
        total_bytes = 0
        for feed in feeds:
            outcome = {"feed_id": feed["id"], "status": "failed", "message": "", "items_seen": 0}
            before = previous.get(feed["id"], {})
            try:
                headers = {}
                # Conditional requests only when the address is unchanged.
                if before.get("url") == feed["url"]:
                    if before.get("etag"):
                        headers["If-None-Match"] = before["etag"]
                    if before.get("last_modified"):
                        headers["If-Modified-Since"] = before["last_modified"]
                response = client.get(feed["url"], headers=headers, timeout=FEED_TIMEOUT)
                if response.status_code == 304:
                    outcome.update(status="not_modified", etag=before.get("etag"),
                                   last_modified=before.get("last_modified"))
                else:
                    response.raise_for_status()
                    if len(response.content) > MAX_FEED_BYTES:
                        raise ValueError(f"feed larger than {MAX_FEED_BYTES} bytes")
                    total_bytes += len(response.content)
                    items = [n for e in parse_feed(response.content)
                             if (n := normalise(e, feed, seen_at, keywords))]
                    rows.extend(items)
                    outcome.update(status="ok", items_seen=len(items),
                                   etag=response.headers.get("etag"),
                                   last_modified=response.headers.get("last-modified"))
            except Exception as exc:  # noqa: BLE001 - one broken feed must not stop the others
                outcome["message"] = f"{type(exc).__name__}: {exc}"[:300]
            outcomes.append({**outcome, "url": feed["url"]})

        ok = [o for o in outcomes if o["status"] != "failed"]
        failed = [o["feed_id"] for o in outcomes if o["status"] == "failed"]
        if feeds and not ok:
            for outcome in outcomes:
                state.record_feed(settings.state_db, seen_at, outcome, new_items=0)
            raise RuntimeError(f"all {len(feeds)} feeds failed; first error: {outcomes[0]['message']}")

        new_rows = self._store(settings, rows, seen_at.date())
        new_by_feed: dict[str, int] = {}
        for row in new_rows:
            new_by_feed[row["feed_id"]] = new_by_feed.get(row["feed_id"], 0) + 1
        # Feed state (ETag included) is saved only after the items are safely on disk.
        for outcome in outcomes:
            state.record_feed(settings.state_db, seen_at, outcome, new_by_feed.get(outcome["feed_id"], 0))

        message = f"{len(new_rows)} new items; feeds ok {len(ok)}/{len(feeds)}"
        if failed:
            message += f"; failed: {', '.join(failed)}"
        return IngestResult(seen_at.date(), len(new_rows), total_bytes, "", bool(new_rows), message)

    def _known_ids(self, settings: Settings) -> set[str]:
        files = [self.curated_path(settings, d).as_posix() for d in self.snapshot_dates(settings)]
        if not files:
            return set()
        con = duckdb.connect()
        try:
            return {r[0] for r in con.execute("SELECT item_id FROM read_parquet(?)", [files]).fetchall()}
        finally:
            con.close()

    def _store(self, settings: Settings, rows: list[dict], day: date) -> list[dict]:
        known = self._known_ids(settings)
        fresh: dict[str, dict] = {}
        for row in rows:
            if row["item_id"] not in known:
                fresh.setdefault(row["item_id"], row)
        if not fresh:
            return []
        table = pa.Table.from_pylist(list(fresh.values()), schema=SCHEMA)
        target = self.curated_path(settings, day)
        if target.exists():
            table = pa.concat_tables([pq.read_table(target, schema=SCHEMA), table])
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name("data.parquet.tmp")
        pq.write_table(table, tmp, compression="zstd")
        os.replace(tmp, target)
        return list(fresh.values())
