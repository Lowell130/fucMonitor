"""Read-only analytical queries over the curated Parquet files, using in-memory DuckDB.

Every query opens its own in-memory connection, so there is no database file to lock.
"""

from datetime import date
from pathlib import Path

import duckdb

from .config import Settings
from .enrich import news as news_enrich
from .sources import SOURCES


def _file(settings: Settings, source: str, snapshot: date) -> str:
    return SOURCES[source].curated_path(settings, snapshot).as_posix()


def latest(settings: Settings, source: str) -> date | None:
    dates = SOURCES[source].snapshot_dates(settings)
    return dates[-1] if dates else None


def _rows(sql: str, params: list | None = None) -> list[dict]:
    con = duckdb.connect()
    try:
        cur = con.execute(sql, params or [])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        con.close()


def count_rows(path: Path) -> int:
    return _rows("SELECT count(*) AS n FROM read_parquet(?)", [path.as_posix()])[0]["n"]


# --- KEV ---------------------------------------------------------------------
def kev_list(settings: Settings, limit: int, offset: int, search: str | None, since: date | None) -> dict:
    snap = latest(settings, "kev")
    if snap is None:
        return {"snapshot_date": None, "total": 0, "items": []}
    where, params = ["true"], [_file(settings, "kev", snap)]
    if search:
        where.append(
            "(cve_id ILIKE ? OR vendor_project ILIKE ? OR product ILIKE ? OR vulnerability_name ILIKE ?)"
        )
        params += [f"%{search}%"] * 4
    if since:
        where.append("date_added >= ?")
        params.append(since)
    clause = " AND ".join(where)
    total = _rows(f"SELECT count(*) AS n FROM read_parquet(?) WHERE {clause}", params)[0]["n"]
    items = _rows(
        f"""SELECT cve_id, vendor_project, product, vulnerability_name, date_added, due_date,
                   known_ransomware_campaign_use, cwes, short_description
            FROM read_parquet(?) WHERE {clause}
            ORDER BY date_added DESC, cve_id DESC LIMIT ? OFFSET ?""",
        params + [limit, offset],
    )
    return {"snapshot_date": snap, "total": total, "items": items}


def kev_timeline(settings: Settings) -> dict:
    snap = latest(settings, "kev")
    if snap is None:
        return {"snapshot_date": None, "items": []}
    items = _rows(
        """SELECT strftime(date_trunc('month', date_added), '%Y-%m') AS month, count(*) AS added
           FROM read_parquet(?) WHERE date_added IS NOT NULL GROUP BY 1 ORDER BY 1""",
        [_file(settings, "kev", snap)],
    )
    return {"snapshot_date": snap, "items": items}


def kev_top_vendors(settings: Settings, limit: int) -> dict:
    snap = latest(settings, "kev")
    if snap is None:
        return {"snapshot_date": None, "items": []}
    items = _rows(
        """SELECT vendor_project, count(*) AS cves, max(date_added) AS last_added
           FROM read_parquet(?) GROUP BY 1 ORDER BY cves DESC, vendor_project LIMIT ?""",
        [_file(settings, "kev", snap), limit],
    )
    return {"snapshot_date": snap, "items": items}


# --- EPSS --------------------------------------------------------------------
def epss_top(settings: Settings, limit: int) -> dict:
    snap = latest(settings, "epss")
    if snap is None:
        return {"snapshot_date": None, "items": []}
    kev_snap = latest(settings, "kev")
    if kev_snap:
        sql = """SELECT e.cve_id, e.epss, e.percentile, (k.cve_id IS NOT NULL) AS in_kev
                 FROM read_parquet(?) e
                 LEFT JOIN (SELECT DISTINCT cve_id FROM read_parquet(?)) k USING (cve_id)
                 ORDER BY e.epss DESC, e.cve_id LIMIT ?"""
        params = [_file(settings, "epss", snap), _file(settings, "kev", kev_snap), limit]
    else:
        sql = """SELECT cve_id, epss, percentile, NULL::BOOLEAN AS in_kev
                 FROM read_parquet(?) ORDER BY epss DESC, cve_id LIMIT ?"""
        params = [_file(settings, "epss", snap), limit]
    return {"snapshot_date": snap, "items": _rows(sql, params)}


def epss_history(settings: Settings, cve_id: str) -> dict:
    source = SOURCES["epss"]
    files = [source.curated_path(settings, d).as_posix() for d in source.snapshot_dates(settings)]
    if not files:
        return {"cve_id": cve_id, "items": []}
    items = _rows(
        """SELECT score_date, epss, percentile, model_version
           FROM read_parquet(?) WHERE cve_id = ? ORDER BY score_date""",
        [files, cve_id.upper()],
    )
    return {"cve_id": cve_id.upper(), "items": items}


# --- news --------------------------------------------------------------------
def _news_files(settings: Settings) -> list[str]:
    source = SOURCES["news"]
    return [source.curated_path(settings, d).as_posix() for d in source.snapshot_dates(settings)]


def _utc(value) -> str | None:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value is not None else None


_UTC_DAY = "CAST(make_timestamp(CAST(epoch(coalesce(published_at, first_seen_at)) * 1000000 AS BIGINT)) AS DATE)"


def _news_source(settings: Settings) -> tuple[str, list] | None:
    """SQL for the raw items joined with their derived labels, plus its parameters."""
    files = _news_files(settings)
    if not files:
        return None
    enriched = news_enrich.enriched_path(settings)
    if enriched.exists():
        sql = """(SELECT r.*, e.event_type, e.exploitation_signal, e.claim_status, e.target_sectors,
                         coalesce(e.story_id, r.item_id) AS story_id, coalesce(e.story_feeds, 1) AS story_feeds
                  FROM read_parquet(?, hive_partitioning = true) r
                  LEFT JOIN read_parquet(?) e USING (item_id))"""
        return sql, [files, enriched.as_posix()]
    sql = """(SELECT r.*, NULL::VARCHAR AS event_type, NULL::BOOLEAN AS exploitation_signal,
                     NULL::VARCHAR AS claim_status, []::VARCHAR[] AS target_sectors,
                     r.item_id AS story_id, 1 AS story_feeds
              FROM read_parquet(?, hive_partitioning = true) r)"""
    return sql, [files]


def news_list(
    settings: Settings,
    limit: int,
    offset: int,
    search: str | None = None,
    feed: str | None = None,
    language: str | None = None,
    kind: str | None = None,
    has_cve: bool | None = None,
    since: date | None = None,
    event_type: str | None = None,
    claim_status: str | None = None,
    sector: str | None = None,
    exploited: bool | None = None,
    collapse: bool = False,
) -> dict:
    source = _news_source(settings)
    if source is None:
        return {"total": 0, "items": []}
    sql, params = source
    where = ["true"]
    if search:
        where.append("(title ILIKE ? OR summary ILIKE ? OR list_contains(cve_ids, upper(?)))")
        params += [f"%{search}%", f"%{search}%", search.strip()]
    for column, value in (("feed_id", feed), ("language", language), ("source_kind", kind),
                          ("event_type", event_type), ("claim_status", claim_status)):
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    if sector:
        where.append("list_contains(target_sectors, ?)")
        params.append(sector)
    if has_cve is not None:
        where.append("len(cve_ids) > 0" if has_cve else "len(cve_ids) = 0")
    if exploited is not None:
        where.append("exploitation_signal" if exploited else "NOT coalesce(exploitation_signal, false)")
    if since:
        where.append("snapshot_date >= ?")
        params.append(since)
    # One row per story: the earliest item of each story among those that match.
    qualify = (
        "QUALIFY row_number() OVER (PARTITION BY story_id "
        "ORDER BY coalesce(published_at, first_seen_at), item_id) = 1" if collapse else ""
    )
    base = f"SELECT * FROM {sql} WHERE {' AND '.join(where)} {qualify}"
    total = _rows(f"SELECT count(*) AS n FROM ({base})", params)[0]["n"]
    # Timestamps are stored in UTC. epoch() avoids any dependency on the session time zone.
    items = _rows(
        f"""SELECT item_id, feed_id, feed_title, source_kind, language, title, link, summary,
                   make_timestamp(CAST(epoch(published_at) * 1000000 AS BIGINT)) AS published_at,
                   make_timestamp(CAST(epoch(first_seen_at) * 1000000 AS BIGINT)) AS first_seen_at,
                   cve_ids, event_type, exploitation_signal, claim_status, target_sectors,
                   story_id, story_feeds
            FROM ({base})
            ORDER BY coalesce(published_at, first_seen_at) DESC, item_id LIMIT ? OFFSET ?""",
        params + [limit, offset],
    )
    for item in items:
        item["published_at"] = _utc(item["published_at"])
        item["first_seen_at"] = _utc(item["first_seen_at"])
    return {"total": total, "items": items}


def news_trend(settings: Settings, by: str, days: int) -> dict:
    """Distinct stories per day (publication day, UTC) by event type or by sector."""
    source = _news_source(settings)
    if source is None:
        return {"by": by, "days": days, "items": []}
    sql, params = source
    if by == "sector":
        inner = f"SELECT {_UTC_DAY} AS day, unnest(target_sectors) AS key, story_id FROM {sql}"
    else:
        inner = f"SELECT {_UTC_DAY} AS day, event_type AS key, story_id FROM {sql}"
    items = _rows(
        f"""SELECT day, key, count(DISTINCT story_id) AS stories FROM ({inner})
            WHERE key IS NOT NULL AND day > current_date - ?::INTEGER AND day <= current_date + 1
            GROUP BY 1, 2 ORDER BY 1, 2""",
        params + [days],
    )
    return {"by": by, "days": days, "items": items}


def news_daily(settings: Settings) -> dict:
    files = _news_files(settings)
    if not files:
        return {"items": []}
    items = _rows(
        """SELECT snapshot_date AS seen_date, source_kind,
                  count(*) AS items, count(*) FILTER (WHERE len(cve_ids) > 0) AS with_cve
           FROM read_parquet(?, hive_partitioning = true) GROUP BY 1, 2 ORDER BY 1, 2""",
        [files],
    )
    return {"items": items}


# --- cross-source ------------------------------------------------------------
def overview(settings: Settings) -> dict:
    kev_snap, epss_snap = latest(settings, "kev"), latest(settings, "epss")
    out: dict = {
        "kev_snapshot_date": kev_snap,
        "epss_snapshot_date": epss_snap,
        "kev_total": None,
        "kev_added_last_30_days": None,
        "kev_ransomware": None,
        "epss_total": None,
        "epss_high": None,
        "kev_epss": None,
    }
    if kev_snap:
        row = _rows(
            """SELECT count(*) AS total,
                      count(*) FILTER (WHERE date_added >= ?::DATE - INTERVAL 30 DAY) AS recent,
                      count(*) FILTER (WHERE lower(known_ransomware_campaign_use) = 'known') AS ransomware
               FROM read_parquet(?)""",
            [kev_snap, _file(settings, "kev", kev_snap)],
        )[0]
        out.update(
            kev_total=row["total"], kev_added_last_30_days=row["recent"], kev_ransomware=row["ransomware"]
        )
    if epss_snap:
        row = _rows(
            "SELECT count(*) AS total, count(*) FILTER (WHERE epss >= 0.1) AS high FROM read_parquet(?)",
            [_file(settings, "epss", epss_snap)],
        )[0]
        out.update(epss_total=row["total"], epss_high=row["high"])
    if kev_snap and epss_snap:
        # How today's EPSS scores the CVEs already known to be exploited. This is a
        # descriptive check, not an evaluation: EPSS is trained with knowledge of them.
        out["kev_epss"] = _rows(
            """SELECT count(*) AS kev_cves,
                      count(e.cve_id) AS with_epss,
                      median(e.epss) AS median_epss,
                      count(*) FILTER (WHERE e.epss >= 0.1) AS epss_ge_10pct,
                      count(*) FILTER (WHERE e.epss < 0.01) AS epss_lt_1pct
               FROM (SELECT DISTINCT cve_id FROM read_parquet(?)) k
               LEFT JOIN read_parquet(?) e USING (cve_id)""",
            [_file(settings, "kev", kev_snap), _file(settings, "epss", epss_snap)],
        )[0]
    return out
