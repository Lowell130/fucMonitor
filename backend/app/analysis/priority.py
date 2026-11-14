"""Bringing the two signals together: what is likely to be exploited, and what is being
probed more than usual right now.

The forecast is a measured quantity: how many of a category's vulnerabilities tend to become
known-exploited, scored against history. Scanning pressure is a live hint: more machines than
usual are looking at a category's services today. They answer different questions, and the
honest move is to keep them side by side rather than fold one into the other and pretend the
blend is as solid as the part that was measured.

So `combined` keeps the forecast as the backbone and hangs the live scanning signal beside it
as a flag, and `watch` lists categories under elevated scanning regardless of their forecast
rank. Whether the scanning flag deserves more weight than that is not asserted; it is tested
in `signal_check`, which asks of the actual history: when a category's scanning rose, did more
exploitation follow than usual? Until that check says yes with enough data behind it, scanning
stays a flag, not a multiplier.
"""

from ..config import Settings
from ..queries import _nvd_files, _products_table, _rows, _scan_files, category_scan_pressure, nvd_latest
from ..sources import SOURCES
from .exploitation import forecast

ELEVATED_Z = 2.0


def combined(settings: Settings, horizon: int = 90, baseline_days: int = 30) -> dict:
    """Forecast per category, with the current scanning pressure beside it, plus a watch list."""
    base = forecast(settings, horizon)
    pressure = category_scan_pressure(settings, baseline_days)

    items = []
    for row in base["items"]:
        scan = pressure.get(row["category"])
        items.append(
            {
                **row,
                "scan_z": scan["z"] if scan else None,
                "scan_ratio": scan["ratio"] if scan else None,
                "scan_as_of": str(scan["as_of"]) if scan else None,
                "elevated_scanning": bool(scan and scan["z"] is not None and scan["z"] >= ELEVATED_Z),
            }
        )
    # The forecast order stays; the scanning flag never reorders a measured ranking.
    watch = sorted(
        (
            {"category": cat, **vals}
            for cat, vals in pressure.items()
            if vals["z"] is not None and vals["z"] >= ELEVATED_Z
        ),
        key=lambda r: r["z"],
        reverse=True,
    )
    for entry in watch:
        entry["as_of"] = str(entry["as_of"])
    return {
        "horizon": horizon,
        "generated_for": base["generated_for"],
        "elevated_z": ELEVATED_Z,
        "items": items,
        "watch": watch,
    }


def signal_check(settings: Settings, lead_days: int = 30, threshold: float = 2.0, baseline_days: int = 28) -> dict:
    """Did a rise in a category's scanning precede more exploitation in it?

    For every category-day with a settled scanning baseline, mark the day 'elevated' when that
    day's scanning is `threshold` standard deviations above the category's trailing mean, then
    count how much exploitation followed in the next `lead_days`. Compare the average that
    followed elevated days with the average that followed ordinary ones. A lift above 1 means
    scanning surges were followed by more exploitation than usual; the counts say whether there
    is enough behind the number to believe it.

    Pooled across categories, because exploitation is far too sparse to split one category at a
    time. This is a sanity check on a weak, aggregated signal, not a trained model.
    """
    scan_files = _scan_files(settings)
    nvd = _nvd_files(settings)
    products = _products_table(settings)
    if not scan_files or not nvd or not products:
        return {"verdict": "no data", "lead_days": lead_days, "pairs": []}

    from ..sources.scans import load_ports

    port_pairs = ", ".join(f"({p['port']}, '{p['category']}')" for p in load_ports(settings))
    rows = _rows(
        f"""
        WITH scan_daily AS (
            SELECT m.category, s.observed_date AS day, sum(s.sources) AS sources
            FROM read_parquet(?) s
            JOIN (VALUES {port_pairs}) AS m(port, category) ON m.port = s.port
            GROUP BY 1, 2
        ),
        scored AS (
            SELECT category, day, sources,
                   avg(sources) OVER w AS base_mean,
                   stddev_samp(sources) OVER w AS base_sd,
                   count(*) OVER w AS base_n
            FROM scan_daily
            WINDOW w AS (PARTITION BY category ORDER BY day
                        ROWS BETWEEN {int(baseline_days)} PRECEDING AND 1 PRECEDING)
        ),
        exploited AS (
            SELECT DISTINCT p.category, n.cve_id,
                   coalesce(n.cisa_exploit_add, CAST(n.published AS DATE)) AS expl_date
            FROM ({nvd_latest()}) n, unnest(n.products) AS u(product)
            JOIN read_parquet(?) p ON p.product = u.product
            WHERE p.category <> 'unmapped' AND n.cisa_exploit_add IS NOT NULL
        ),
        horizon AS (SELECT max(expl_date) AS last_day FROM exploited),
        joined AS (
            SELECT s.category, s.day,
                   (s.sources - s.base_mean) / s.base_sd AS z,
                   count(e.cve_id) AS next_events
            FROM scored s, horizon h
            LEFT JOIN exploited e
              ON e.category = s.category
             AND e.expl_date > s.day
             AND e.expl_date <= s.day + INTERVAL {int(lead_days)} DAY
            WHERE s.base_n >= {int(baseline_days)} AND s.base_sd > 0
              AND s.day <= h.last_day - INTERVAL {int(lead_days)} DAY
            GROUP BY s.category, s.day, s.base_mean, s.base_sd, s.sources
        )
        SELECT (z >= {float(threshold)}) AS elevated,
               count(*) AS days, sum(next_events) AS events, avg(next_events) AS mean_next
        FROM joined GROUP BY 1
        """,
        [scan_files, nvd, products],
    )

    groups = {bool(r["elevated"]): r for r in rows}
    elevated = groups.get(True)
    normal = groups.get(False)
    out = {
        "lead_days": lead_days,
        "threshold": threshold,
        "elevated_days": elevated["days"] if elevated else 0,
        "normal_days": normal["days"] if normal else 0,
        "mean_after_elevated": round(elevated["mean_next"], 3) if elevated and elevated["mean_next"] is not None else None,
        "mean_after_normal": round(normal["mean_next"], 3) if normal and normal["mean_next"] is not None else None,
        "events_after_elevated": elevated["events"] if elevated else 0,
    }
    lift = None
    if out["mean_after_elevated"] is not None and out["mean_after_normal"]:
        lift = round(out["mean_after_elevated"] / out["mean_after_normal"], 2)
    out["lift"] = lift
    out["verdict"] = _verdict(out["elevated_days"], out["events_after_elevated"], lift)
    return out


def _verdict(elevated_days: int, events: int, lift: float | None) -> str:
    """Plain words for whether the check means anything yet, erring toward 'not yet'."""
    if elevated_days < 10 or events < 20:
        return "too little history to tell yet"
    if lift is None:
        return "too little history to tell yet"
    if lift >= 1.3:
        return "scanning surges were followed by more exploitation"
    if lift <= 0.8:
        return "no lead found: surges were followed by less, not more"
    return "no clear lead either way"
