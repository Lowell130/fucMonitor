"""Read-only analytical queries over the curated Parquet files, using in-memory DuckDB.

Every query opens its own in-memory connection, so there is no database file to lock.
"""

from datetime import date
from pathlib import Path

import duckdb

from .config import Settings
from .enrich import news as news_enrich
from .taxonomy import mapping
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


def _ts(column: str, alias: str | None = None) -> str:
    """Read a UTC timestamp as a plain one: DuckDB needs pytz to return a zoned value."""
    return f"make_timestamp(CAST(epoch({column}) * 1000000 AS BIGINT)) AS {alias or column}"


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
                   {_ts("published_at")}, {_ts("first_seen_at")},
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


# --- NVD ---------------------------------------------------------------------
def nvd_latest() -> str:
    """SQL for the current state of every CVE: its most recently retrieved row.

    Takes one parameter, the list of stored files. Reading "as of" a past day means
    passing only the files up to that day.
    """
    return """SELECT * EXCLUDE (_rank) FROM (
                  SELECT *, row_number() OVER (PARTITION BY cve_id ORDER BY retrieved_at DESC) AS _rank
                  FROM read_parquet(?)
              ) WHERE _rank = 1"""


def _nvd_files(settings: Settings) -> list[str]:
    return SOURCES["nvd"].curated_files(settings)


def nvd_overview(settings: Settings) -> dict:
    files = _nvd_files(settings)
    empty = {"total": None, "with_cvss": None, "with_products": None, "with_exploit_reference": None,
             "retrieved_at": None, "by_year": [], "by_severity": []}
    if not files:
        return empty
    latest = nvd_latest()
    row = _rows(
        f"""SELECT count(*) AS total,
                   count(cvss_score) AS with_cvss,
                   count(*) FILTER (WHERE len(products) > 0) AS with_products,
                   count(*) FILTER (WHERE has_exploit_reference) AS with_exploit_reference,
                   {_ts("max(retrieved_at)", "retrieved_at")}
            FROM ({latest})""",
        [files],
    )[0]
    row["retrieved_at"] = _utc(row["retrieved_at"])
    row["by_year"] = _rows(
        f"""SELECT CAST(year(published) AS INTEGER) AS year, count(*) AS cves FROM ({latest})
            WHERE published IS NOT NULL GROUP BY 1 ORDER BY 1""",
        [files],
    )
    row["by_severity"] = _rows(
        f"""SELECT cvss_severity AS severity, count(*) AS cves FROM ({latest})
            WHERE cvss_severity IS NOT NULL GROUP BY 1 ORDER BY cves DESC""",
        [files],
    )
    return row


def nvd_vendors(settings: Settings, limit: int, since_year: int | None = None) -> dict:
    """Vendors with the most CVE records. A wide product range means more records;
    this is not a measure of how secure a vendor is."""
    files = _nvd_files(settings)
    if not files:
        return {"items": []}
    where = "WHERE len(vendors) > 0"
    params: list = [files]
    if since_year:
        where += " AND year(published) >= ?"
        params.append(since_year)
    items = _rows(
        f"""SELECT vendor, count(DISTINCT cve_id) AS cves, count(DISTINCT product) AS products FROM (
                SELECT cve_id, unnest(vendors) AS vendor, unnest(products) AS product
                FROM ({nvd_latest()}) {where}
            ) GROUP BY 1 ORDER BY cves DESC, vendor LIMIT ?""",
        params + [limit],
    )
    return {"items": items}


# --- public exploits ---------------------------------------------------------
def exploits_overview(settings: Settings) -> dict:
    files = SOURCES["exploits"].curated_files(settings)
    if not files:
        return {"cves": 0, "providers": []}
    total = _rows("SELECT count(DISTINCT cve_id) AS n FROM read_parquet(?)", [files])[0]["n"]
    providers = _rows(
        """SELECT provider, count(*) AS entries, count(DISTINCT cve_id) AS cves,
                  make_timestamp(CAST(epoch(max(first_seen_at)) * 1000000 AS BIGINT)) AS last_seen
           FROM read_parquet(?) GROUP BY 1 ORDER BY provider""",
        [files],
    )
    for provider in providers:
        provider["last_seen"] = _utc(provider["last_seen"])
    return {"cves": total, "providers": providers}


# --- one CVE across every source ----------------------------------------------
def cve_profile(settings: Settings, cve_id: str) -> dict:
    """Everything this system holds about one CVE. Each source is reported separately."""
    cve_id = cve_id.strip().upper()
    out: dict = {"cve_id": cve_id, "nvd": None, "kev": None, "epss": None,
                 "exploits": [], "exploit_providers": [], "news": [], "categories": []}

    files = _nvd_files(settings)
    if files:
        found = _rows(
            f"""SELECT * EXCLUDE (published, last_modified, retrieved_at),
                       {_ts("published")}, {_ts("last_modified")}, {_ts("retrieved_at")}
                FROM ({nvd_latest()}) WHERE cve_id = ?""",
            [files, cve_id],
        )
        if found:
            for column in ("published", "last_modified", "retrieved_at"):
                found[0][column] = _utc(found[0][column])
            out["nvd"] = found[0]

    products_table = _products_table(settings)
    if out["nvd"] and products_table and out["nvd"]["products"]:
        out["categories"] = [
            r["category"]
            for r in _rows(
                "SELECT DISTINCT category FROM read_parquet(?) WHERE product IN ? "
                "AND category <> 'unmapped' ORDER BY category",
                [products_table, out["nvd"]["products"]],
            )
        ]

    kev_snapshot = latest(settings, "kev")
    if kev_snapshot:
        found = _rows(
            """SELECT cve_id, vendor_project, product, vulnerability_name, date_added, due_date,
                      known_ransomware_campaign_use, short_description
               FROM read_parquet(?) WHERE cve_id = ?""",
            [_file(settings, "kev", kev_snapshot), cve_id],
        )
        out["kev"] = found[0] if found else None

    epss_snapshot = latest(settings, "epss")
    if epss_snapshot:
        found = _rows(
            "SELECT cve_id, epss, percentile, score_date FROM read_parquet(?) WHERE cve_id = ?",
            [_file(settings, "epss", epss_snapshot), cve_id],
        )
        out["epss"] = found[0] if found else None

    exploit_files = SOURCES["exploits"].curated_files(settings)
    if exploit_files:
        rows = _rows(
            """SELECT provider, reference_id, title, reference_url, provider_date,
                      make_timestamp(CAST(epoch(first_seen_at) * 1000000 AS BIGINT)) AS first_seen_at
               FROM read_parquet(?) WHERE cve_id = ? ORDER BY provider, reference_id""",
            [exploit_files, cve_id],
        )
        for row in rows:
            row["first_seen_at"] = _utc(row["first_seen_at"])
        out["exploits"] = rows
        out["exploit_providers"] = sorted({r["provider"] for r in rows})

    news_files = _news_files(settings)
    if news_files:
        out["news"] = news_list(settings, 20, 0, search=cve_id)["items"]
    return out


# --- technology categories ----------------------------------------------------
def _products_table(settings: Settings) -> str | None:
    path = mapping.derived_path(settings)
    return path.as_posix() if path.exists() else None


def _category_pairs(settings: Settings) -> tuple[str, list] | None:
    """SQL for one row per (CVE, category). A CVE affecting products in two categories
    appears in both, so category counts add up to more than the number of CVEs."""
    files = _nvd_files(settings)
    products = _products_table(settings)
    if not files or not products:
        return None
    sql = f"""(SELECT DISTINCT n.cve_id, p.category, CAST(n.published AS DATE) AS published_date,
                      n.cisa_exploit_add IS NOT NULL AS in_kev
               FROM ({nvd_latest()}) n, unnest(n.products) AS u(product)
               JOIN read_parquet(?) p ON p.product = u.product)"""
    return sql, [files, products]


def categories_coverage(settings: Settings) -> dict:
    """How much of the catalogue carries a category, by products and by CVEs.
    The CVE figures are what matter: a handful of busy products cover most of them."""
    products = _products_table(settings)
    empty = {"products": 0, "products_mapped": 0, "products_manual": 0, "cves": 0, "cves_mapped": 0,
             "kev_cves": 0, "kev_cves_mapped": 0, "recent_cves": 0, "recent_cves_mapped": 0,
             "rules_version": None}
    if not products:
        return empty
    row = _rows(
        """SELECT count(*) AS products,
                  count(*) FILTER (WHERE category <> 'unmapped') AS products_mapped,
                  count(*) FILTER (WHERE assigned_by = 'manual') AS products_manual,
                  max(rules_version) AS rules_version
           FROM read_parquet(?)""",
        [products],
    )[0]
    pairs = _category_pairs(settings)
    files = _nvd_files(settings)
    if pairs and files:
        counts = _rows(
            f"""WITH mapped AS (
                    SELECT DISTINCT cve_id, published_date, in_kev FROM {pairs[0]} WHERE category <> 'unmapped'
                ), all_cves AS (
                    SELECT cve_id, CAST(published AS DATE) AS published_date,
                           cisa_exploit_add IS NOT NULL AS in_kev
                    FROM ({nvd_latest()}) WHERE len(products) > 0
                )
                SELECT (SELECT count(*) FROM all_cves) AS cves,
                       (SELECT count(*) FROM mapped) AS cves_mapped,
                       (SELECT count(*) FROM all_cves WHERE in_kev) AS kev_cves,
                       (SELECT count(*) FROM mapped WHERE in_kev) AS kev_cves_mapped,
                       (SELECT count(*) FROM all_cves
                         WHERE published_date >= current_date - INTERVAL 730 DAY) AS recent_cves,
                       (SELECT count(*) FROM mapped
                         WHERE published_date >= current_date - INTERVAL 730 DAY) AS recent_cves_mapped""",
            # [files] and not files: the list is one parameter, not one parameter per file.
            pairs[1] + [files],
        )[0]
        row.update(counts)
    return {**empty, **row}


def categories_summary(settings: Settings, since_year: int | None = None) -> dict:
    """Per category: how many CVEs, how many are known exploited, how many are recent."""
    pairs = _category_pairs(settings)
    if not pairs:
        return {"items": []}
    sql, params = pairs
    where = "WHERE category <> 'unmapped'"
    if since_year:
        where += " AND year(published_date) >= ?"
        params = params + [since_year]
    items = _rows(
        f"""SELECT category,
                   count(*) AS cves,
                   count(*) FILTER (WHERE in_kev) AS kev_cves,
                   count(*) FILTER (WHERE published_date >= current_date - INTERVAL 730 DAY) AS recent_cves,
                   max(published_date) AS last_published
            FROM {sql} {where}
            GROUP BY 1 ORDER BY cves DESC""",
        params,
    )
    for item in items:
        item["kev_share"] = round(item["kev_cves"] / item["cves"], 5) if item["cves"] else None
    return {"items": items}


def category_products(
    settings: Settings,
    category: str | None = None,
    assigned_by: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Products with their category. Ordered by how much a wrong answer would cost:
    products behind known-exploited CVEs first, then by how many CVEs they carry."""
    products = _products_table(settings)
    if not products:
        return {"total": 0, "items": []}
    where, params = ["true"], [products]
    if category:
        where.append("category = ?")
        params.append(category)
    if assigned_by:
        where.append("assigned_by = ?")
        params.append(assigned_by)
    if search:
        where.append("product ILIKE ?")
        params.append(f"%{search}%")
    clause = " AND ".join(where)
    total = _rows(f"SELECT count(*) AS n FROM read_parquet(?) WHERE {clause}", params)[0]["n"]
    items = _rows(
        f"""SELECT product, vendor, category, assigned_by, rule_id, cve_count, kev_count,
                   exploit_count, recent_cve_count, last_published
            FROM read_parquet(?) WHERE {clause}
            ORDER BY kev_count DESC, exploit_count DESC, recent_cve_count DESC, cve_count DESC, product
            LIMIT ? OFFSET ?""",
        params + [limit, offset],
    )
    return {"total": total, "items": items}
