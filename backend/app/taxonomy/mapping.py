"""Maps affected products to technology categories, which is what the forecasts are about.

A CVE names its affected products as CPE entries, written `vendor:product`. Categories are
assigned to the *product*, not to the CVE: there are far fewer distinct products than CVEs,
and a decision made once about `fortinet:fortios` holds for every CVE that touches it.

Three ways a product gets a category, in order of authority:

1. a hand-made assignment, stored in the `product_category` table and never overwritten;
2. a keyword rule from rules.json;
3. nothing, and the product stays `unmapped`.

Hand-made assignments come first because the rules are crude and will always be wrong about
some products. The review queue exists for exactly that: it ranks unmapped products by how
much they matter (how many CVEs, and how many of those are known to be exploited), so an
hour of manual work goes where it changes the numbers.

The derived table lives in derived/categories/products.parquet and is rebuilt from scratch
whenever the rules change, the catalogue grows, or someone assigns a category by hand. It
holds no judgement that is not reproducible from those three inputs.
"""

import json
import os
import re
from datetime import date
from functools import lru_cache
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from .. import state
from ..config import Settings
from ..sources import SOURCES

RULES_FILE = Path(__file__).with_name("rules.json")
CATEGORIES_FILE = Path(__file__).with_name("categories.json")
UNMAPPED = "unmapped"

SCHEMA = pa.schema(
    [
        ("product", pa.string()),
        ("vendor", pa.string()),
        ("category", pa.string()),
        ("assigned_by", pa.string()),  # manual, rule or unmapped
        ("rule_id", pa.string()),
        ("cve_count", pa.int32()),
        ("kev_count", pa.int32()),
        ("exploit_count", pa.int32()),
        ("recent_cve_count", pa.int32()),  # published in the last two years
        ("last_published", pa.date32()),
        ("rules_version", pa.string()),
    ]
)


@lru_cache
def load_rules() -> dict:
    raw = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    categories = {c["id"] for c in json.loads(CATEGORIES_FILE.read_text(encoding="utf-8"))["technology_categories"]}
    compiled = []
    for rule in raw["rules"]:
        if rule["category"] not in categories:
            raise ValueError(f"Rule '{rule['id']}' uses unknown category '{rule['category']}'")
        compiled.append((rule["id"], rule["category"], re.compile("|".join(rule["patterns"]))))
    return {"version": raw["version"], "rules": compiled}


def category_ids() -> list[str]:
    data = json.loads(CATEGORIES_FILE.read_text(encoding="utf-8"))
    return [c["id"] for c in data["technology_categories"]]


def classify(product: str) -> tuple[str, str, str]:
    """(category, assigned_by, rule_id) for one `vendor:product`, rules only."""
    text = product.casefold()
    for rule_id, category, pattern in load_rules()["rules"]:
        if pattern.search(text):
            return category, "rule", rule_id
    return UNMAPPED, UNMAPPED, ""


def derived_path(settings: Settings) -> Path:
    return settings.data_dir / "derived" / "categories" / "products.parquet"


def is_current(settings: Settings) -> bool:
    """True when the table exists, was built with the current rules, and covers every product."""
    path = derived_path(settings)
    files = SOURCES["nvd"].curated_files(settings)
    if not files:
        return True
    if not path.exists():
        return False
    con = duckdb.connect()
    try:
        versions = con.execute("SELECT DISTINCT rules_version FROM read_parquet(?)", [path.as_posix()]).fetchall()
        if versions != [(_fingerprint(settings),)]:
            return False
        missing = con.execute(
            f"""SELECT count(*) FROM (
                    SELECT DISTINCT unnest(products) AS product FROM ({_latest_nvd()})
                ) ANTI JOIN read_parquet(?) USING (product)""",
            [files, path.as_posix()],
        ).fetchone()[0]
        return missing == 0
    finally:
        con.close()


def _fingerprint(settings: Settings) -> str:
    """Rules version plus how many hand-made assignments exist, so one new decision
    is enough to make the table stale."""
    return f"{load_rules()['version']}+{state.count_product_categories(settings.state_db)}"


def _sql_list(paths: list[str]) -> str:
    """A SQL array of file paths. DuckDB refuses bound parameters in CREATE VIEW."""
    return "[" + ", ".join("'" + path.replace("'", "''") + "'" for path in paths) + "]"


def _latest_nvd() -> str:
    from ..queries import nvd_latest

    return nvd_latest()


def rebuild(settings: Settings) -> int:
    """Recompute every product's category. Returns the number of products."""
    files = SOURCES["nvd"].curated_files(settings)
    if not files:
        return 0
    kev_files = _kev_file(settings)
    exploit_files = SOURCES["exploits"].curated_files(settings)

    con = duckdb.connect()
    try:
        con.execute(f"CREATE TEMP VIEW nvd AS {_latest_nvd().replace('?', _sql_list(files))}")
        con.execute(
            """CREATE TEMP VIEW pairs AS
               SELECT cve_id, unnest(products) AS product,
                      CAST(published AS DATE) AS published_date,
                      cisa_exploit_add IS NOT NULL AS in_kev
               FROM nvd WHERE len(products) > 0"""
        )
        if kev_files:
            con.execute(
                f"CREATE TEMP VIEW kev AS SELECT DISTINCT cve_id FROM read_parquet({_sql_list([kev_files])})"
            )
        else:
            con.execute("CREATE TEMP VIEW kev AS SELECT NULL::VARCHAR AS cve_id WHERE false")
        if exploit_files:
            con.execute(
                "CREATE TEMP VIEW exploited AS SELECT DISTINCT cve_id FROM read_parquet("
                f"{_sql_list(exploit_files)})"
            )
        else:
            con.execute("CREATE TEMP VIEW exploited AS SELECT NULL::VARCHAR AS cve_id WHERE false")

        rows = con.execute(
            """SELECT p.product,
                      split_part(p.product, ':', 1) AS vendor,
                      count(DISTINCT p.cve_id) AS cve_count,
                      count(DISTINCT CASE WHEN p.in_kev OR k.cve_id IS NOT NULL THEN p.cve_id END) AS kev_count,
                      count(DISTINCT e.cve_id) AS exploit_count,
                      count(DISTINCT CASE WHEN p.published_date >= current_date - INTERVAL 730 DAY
                                          THEN p.cve_id END) AS recent_cve_count,
                      max(p.published_date) AS last_published
               FROM pairs p
               LEFT JOIN kev k USING (cve_id)
               LEFT JOIN exploited e USING (cve_id)
               GROUP BY 1, 2"""
        ).fetchall()
    finally:
        con.close()

    manual = state.product_categories(settings.state_db)
    fingerprint = _fingerprint(settings)
    records = []
    for product, vendor, cves, kev, exploits, recent, last_published in rows:
        if product in manual:
            category, assigned_by, rule_id = manual[product], "manual", ""
        else:
            category, assigned_by, rule_id = classify(product)
        records.append(
            {
                "product": product,
                "vendor": vendor,
                "category": category,
                "assigned_by": assigned_by,
                "rule_id": rule_id,
                "cve_count": cves,
                "kev_count": kev,
                "exploit_count": exploits,
                "recent_cve_count": recent,
                "last_published": last_published,
                "rules_version": fingerprint,
            }
        )

    target = derived_path(settings)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name("products.parquet.tmp")
    pq.write_table(pa.Table.from_pylist(records, schema=SCHEMA), tmp, compression="zstd")
    os.replace(tmp, target)
    return len(records)


def _kev_file(settings: Settings) -> str | None:
    dates = SOURCES["kev"].snapshot_dates(settings)
    return SOURCES["kev"].curated_path(settings, dates[-1]).as_posix() if dates else None
