"""Measures the forecast against what actually happened, month by month.

A forecast nobody has scored is a decoration. This walks a date through the past, asks
each method to predict the next H days using only what was known on that date, and compares
the answer with what the catalogue later recorded. No model trains here and nothing is
fitted: that is the point, because a baseline has to be beaten by something, and first it
has to be measured.

Two methods are scored against each other:

- **recent_rate**: however many vulnerabilities of this category became known-exploited in
  the last year, scaled to the horizon. It assumes next quarter looks like last year.
- **volume_rate**: how many CVEs the category has been getting lately, times how often such
  CVEs are exploited within the horizon. This is what the dashboard shipped first.

They answer slightly different questions, and the comparison is the honest way to find out
which one to put in front of a person. What is counted as truth is the same for both: CVEs
of that category first recorded as exploited inside the window, whenever they were published.

Dates: evaluation stops a full horizon before the last exploitation the catalogue knows
about, because a window that has not finished cannot be scored.
"""

import math
from datetime import date, timedelta

import duckdb

from ..config import Settings
from ..queries import _nvd_files, _products_table, nvd_latest
from ..sources import SOURCES
from .exploitation import HORIZONS, poisson_interval

# How far back each "recent rate" method looks. A short window follows a rising trend
# sooner; a long one is steadier. The backtest decides which wins rather than taste.
LOOKBACKS = (90, 180, 365)
SHARE_WINDOW_DAYS = 730


def _facts_sql(settings: Settings) -> tuple[str, list] | None:
    files = _nvd_files(settings)
    products = _products_table(settings)
    if not files or not products:
        return None
    dates = SOURCES["kev"].snapshot_dates(settings)
    kev = SOURCES["kev"].curated_path(settings, dates[-1]).as_posix() if dates else None
    join = (
        "LEFT JOIN (SELECT cve_id, min(date_added) AS kev_date FROM read_parquet(?) GROUP BY 1) k "
        "ON k.cve_id = n.cve_id"
        if kev
        else "LEFT JOIN (SELECT NULL::VARCHAR AS cve_id, NULL::DATE AS kev_date WHERE false) k "
        "ON k.cve_id = n.cve_id"
    )
    sql = f"""SELECT DISTINCT n.cve_id, p.category,
                     CAST(n.published AS DATE) AS published_date,
                     least(coalesce(n.cisa_exploit_add, k.kev_date), coalesce(k.kev_date, n.cisa_exploit_add))
                         AS exploited_date
              FROM ({nvd_latest()}) n, unnest(n.products) AS u(product)
              JOIN read_parquet(?) p ON p.product = u.product
              {join}
              WHERE p.category <> 'unmapped' AND n.published IS NOT NULL"""
    return sql, [files, products] + ([kev] if kev else [])


def run(settings: Settings, horizon: int = 90, step_days: int = 30, points: int = 24) -> dict:
    """Score both methods at `points` dates, `step_days` apart, ending a horizon ago."""
    if horizon not in HORIZONS:
        raise ValueError(f"horizon must be one of {HORIZONS}")
    facts = _facts_sql(settings)
    if facts is None:
        return {"horizon": horizon, "evaluations": [], "methods": [], "note": "no catalogue yet"}
    sql, params = facts

    con = duckdb.connect()
    try:
        con.execute(f"CREATE TEMP TABLE facts AS {sql}", params)
        last = con.execute("SELECT max(exploited_date) FROM facts").fetchone()[0]
        if last is None:
            return {"horizon": horizon, "evaluations": [], "methods": [], "note": "nothing exploited yet"}
        # A window that has not run its course cannot be scored.
        end = last - timedelta(days=horizon)
        starts = [end - timedelta(days=step_days * i) for i in range(points)][::-1]
        starts = [d for d in starts if d > date(2000, 1, 1)]
        if not starts:
            return {"horizon": horizon, "evaluations": [], "methods": [], "note": "not enough history"}

        con.execute(
            "CREATE TEMP TABLE evaluation_dates AS SELECT unnest(?::DATE[]) AS as_of", [starts]
            # `at` is reserved in SQL (AT TIME ZONE), so the column is named as_of.
        )
        recent_counts = ",\n                   ".join(
            f"count(*) FILTER (WHERE exploited_date >= as_of - INTERVAL {days} DAY "
            f"AND exploited_date < as_of) AS events_{days}"
            for days in LOOKBACKS
        )
        rows = con.execute(
            f"""
            WITH pairs AS (SELECT d.as_of, f.* FROM evaluation_dates d, facts f)
            SELECT as_of, category,
                   -- what was known on the day, and nothing more
                   {recent_counts},
                   count(DISTINCT CASE
                       WHEN published_date >= as_of - INTERVAL 365 DAY AND published_date < as_of
                       THEN cve_id END) AS recent_cves,
                   count(DISTINCT CASE
                       WHEN published_date >= as_of - INTERVAL {SHARE_WINDOW_DAYS} DAY
                        AND published_date <= as_of - INTERVAL {horizon} DAY
                       THEN cve_id END) AS eligible,
                   count(DISTINCT CASE
                       WHEN published_date >= as_of - INTERVAL {SHARE_WINDOW_DAYS} DAY
                        AND published_date <= as_of - INTERVAL {horizon} DAY
                        AND exploited_date IS NOT NULL
                        AND date_diff('day', published_date, exploited_date) <= {horizon}
                       THEN cve_id END) AS exploited_in_window,
                   -- and what actually happened next
                   count(*) FILTER (
                       WHERE exploited_date >= as_of AND exploited_date < as_of + INTERVAL {horizon} DAY
                   ) AS observed
            FROM pairs GROUP BY 1, 2 ORDER BY 1, 2
            """
        ).fetchall()
    finally:
        con.close()

    evaluations = []
    errors: dict[str, list[float]] = {}
    inside: dict[str, list[bool]] = {}
    for row in rows:
        as_of, category = row[0], row[1]
        events = dict(zip(LOOKBACKS, row[2 : 2 + len(LOOKBACKS)]))
        recent_cves, eligible, exploited_in_window, observed = row[2 + len(LOOKBACKS) :]
        share = exploited_in_window / eligible if eligible else 0.0
        predictions = {f"recent_rate_{days}": events[days] * horizon / days for days in LOOKBACKS}
        predictions["volume_rate"] = recent_cves * (horizon / 365) * share
        entry = {"at": as_of.isoformat(), "category": category, "observed": observed, "predictions": {}}
        for method, value in predictions.items():
            errors.setdefault(method, [])
            inside.setdefault(method, [])
            low, high = poisson_interval(value)
            entry["predictions"][method] = {
                "expected": round(value, 2),
                "low": round(low, 2),
                "high": round(high, 2),
                "inside": low <= observed <= high,
            }
            errors[method].append(abs(value - observed))
            inside[method].append(low <= observed <= high)
        evaluations.append(entry)

    methods = []
    for method in errors:
        count = len(errors[method])
        methods.append(
            {
                "method": method,
                "points": count,
                "mean_absolute_error": round(sum(errors[method]) / count, 3) if count else None,
                "rmse": round(math.sqrt(sum(e * e for e in errors[method]) / count), 3) if count else None,
                "interval_coverage": round(sum(inside[method]) / count, 3) if count else None,
            }
        )
    methods.sort(key=lambda m: m["mean_absolute_error"] if m["mean_absolute_error"] is not None else 1e9)
    return {
        "horizon": horizon,
        "step_days": step_days,
        "from": starts[0].isoformat(),
        "to": starts[-1].isoformat(),
        "observed_total": sum(e["observed"] for e in evaluations),
        "methods": methods,
        "evaluations": evaluations,
    }
