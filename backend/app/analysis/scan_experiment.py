"""Separate, dedicated check: does adding the scanning signal to the category forecast help?

The category forecast predicts, per technology category, how many vulnerabilities will become
known-exploited (enter CISA KEV) in the next H days. `priority.signal_check` already asked a
narrower question on the raw history — did a surge in a category's scanning precede more
exploitation? — and found no lead. This is the forecast-level version the project's rules require
before scanning may ever be fused in: it compares the current forecast against a version that
adjusts it by the category's scanning pressure, walk-forward, and measures whether the counts get
better, the intervals stay honest, and the alerts catch more at the same budget.

Point-in-time, with a declared approximation. The exploitation side is point-in-time (publication
and KEV-entry dates as recorded). The scanning side is NOT: the scans source keeps only the latest
(corrected) value per observed day — no first-availability, no revision history — and most of it
was back-filled about a year after the fact (median observed->retrieved lag ~1 year). So the scan
value used at a past date D is the value as corrected later, not what was available on D. DShield
revises mainly the last few days, so for dates well in the past the approximation is reasonable,
but it cannot be verified: this is a retrospective, approximate evaluation. `scans.py` now also
records the first-seen value going forward, so a future run can be checked against what was
actually available at the time.

Methods compared, walk-forward:
- **current**: the recent-rate forecast (events in the last `lookback` days scaled to H).
- **current + scanning**: the same, multiplied by (1 + beta * relu(scanning z-score)), where beta
  is chosen on the TRAINING period only and a final HOLD-OUT period is kept out of that choice and
  used only for the reported metrics.

Metrics on the hold-out: count error (MAE, RMSE), interval reliability (coverage of the Poisson
interval), and alert utility at an equal budget (events caught when the top-k categories per date
are alerted). Scanning is integrated into the forecast only if it helps on all three; otherwise it
stays a flag beside the forecast, as now.
"""

from __future__ import annotations

import math
from datetime import date, timedelta

import duckdb
import numpy as np

from ..config import Settings
from ..sources import SOURCES
from .backtest import _facts_sql
from .exploitation import HORIZONS, poisson_interval

_BETAS = (0.0, 0.1, 0.25, 0.5, 1.0, 2.0)


def _scan_rows(settings: Settings) -> tuple[str, list] | None:
    files = SOURCES["scans"].curated_files(settings)
    if not files:
        return None
    from ..sources.scans import load_ports

    pairs = ", ".join(f"({p['port']}, '{p['category']}')" for p in load_ports(settings))
    sql = f"""SELECT m.category AS category, s.observed_date AS day, sum(s.sources) AS sources
              FROM read_parquet(?) s JOIN (VALUES {pairs}) AS m(port, category) ON m.port = s.port
              GROUP BY 1, 2"""
    return sql, [files]


def run(settings: Settings, horizon: int = 90, lookback: int = 180, step_days: int = 30,
        scan_window: int = 28, scan_baseline: int = 90, holdout_frac: float = 0.35) -> dict:
    """Walk-forward comparison of the forecast with and without scanning, with a held-out tail."""
    if horizon not in HORIZONS:
        raise ValueError(f"horizon must be one of {HORIZONS}")
    facts = _facts_sql(settings)
    scan = _scan_rows(settings)
    if facts is None or scan is None:
        return {"note": "no catalogue or no scan history yet", "methods": []}
    fsql, fparams = facts
    ssql, sparams = scan

    con = duckdb.connect()
    try:
        con.execute("PRAGMA threads=4")
        con.execute(f"CREATE TEMP TABLE facts AS {fsql}", fparams)
        con.execute(f"CREATE TEMP TABLE scan_daily AS {ssql}", sparams)
        last_expl = con.execute("SELECT max(exploited_date) FROM facts").fetchone()[0]
        scan_first = con.execute("SELECT min(day) FROM scan_daily").fetchone()[0]
        if last_expl is None or scan_first is None:
            return {"note": "not enough history", "methods": []}
        # Eval dates: monthly, from when a scan baseline is available to a full horizon before the
        # last known exploitation (so every window is complete).
        start = scan_first + timedelta(days=scan_window + scan_baseline)
        end = last_expl - timedelta(days=horizon)
        days = (end - start).days
        if days < step_days * 4:
            return {"note": f"usable window too short ({days} days between {start} and {end})",
                    "methods": []}
        as_ofs = [start + timedelta(days=step_days * i) for i in range(days // step_days + 1)]
        as_ofs = [d for d in as_ofs if d <= end]

        con.execute("CREATE TEMP TABLE evald AS SELECT unnest(?::DATE[]) AS as_of", [as_ofs])
        rows = con.execute(f"""
            WITH cells AS (SELECT e.as_of, f.category, f.cve_id, f.published_date, f.exploited_date
                           FROM evald e, facts f)
            SELECT as_of, category,
                   count(*) FILTER (WHERE exploited_date >= as_of - INTERVAL {lookback} DAY
                                      AND exploited_date < as_of) AS events_lookback,
                   count(*) FILTER (WHERE exploited_date >= as_of
                                      AND exploited_date < as_of + INTERVAL {horizon} DAY) AS observed
            FROM cells GROUP BY 1, 2 ORDER BY 1, 2
        """).fetchall()

        # Scanning z-score per (as_of, category), point-in-time: recent window vs trailing baseline.
        scan_rows = con.execute(f"""
            WITH r AS (
                SELECT e.as_of, d.category, avg(d.sources) AS recent
                FROM evald e JOIN scan_daily d
                  ON d.day >= e.as_of - INTERVAL {scan_window} DAY AND d.day < e.as_of
                GROUP BY 1, 2),
            b AS (
                SELECT e.as_of, d.category, avg(d.sources) AS base_mean, stddev_samp(d.sources) AS base_sd
                FROM evald e JOIN scan_daily d
                  ON d.day >= e.as_of - INTERVAL {scan_window + scan_baseline} DAY
                 AND d.day < e.as_of - INTERVAL {scan_window} DAY
                GROUP BY 1, 2)
            SELECT r.as_of, r.category,
                   CASE WHEN b.base_sd > 0 THEN (r.recent - b.base_mean) / b.base_sd ELSE 0 END AS z
            FROM r JOIN b ON b.as_of = r.as_of AND b.category = r.category
        """).fetchall()
    finally:
        con.close()

    zmap = {(str(a), c): float(z) for a, c, z in scan_rows}
    cells = []
    for as_of, category, ev, obs in rows:
        z = zmap.get((str(as_of), category), 0.0)
        pred_a = ev * horizon / lookback
        cells.append((as_of, category, pred_a, float(obs), max(0.0, z)))
    if not cells:
        return {"note": "no evaluable category-date cells", "methods": []}

    as_of_sorted = sorted({c[0] for c in cells})
    cut = as_of_sorted[int(len(as_of_sorted) * (1 - holdout_frac))] if len(as_of_sorted) > 2 else as_of_sorted[-1]
    train = [c for c in cells if c[0] < cut]
    holo = [c for c in cells if c[0] >= cut]
    if not train or not holo:
        return {"note": "not enough cells to split train/hold-out", "methods": []}

    # Choose beta on TRAIN only, minimising count MAE of the scanning-adjusted forecast.
    def mae(cells_, beta):
        return float(np.mean([abs(pa * (1 + beta * zr) - ob) for _, _, pa, ob, zr in cells_]))
    beta = min(_BETAS, key=lambda b: mae(train, b))

    def metrics(cells_, beta):
        pa = np.array([c[2] for c in cells_])
        ob = np.array([c[3] for c in cells_])
        zr = np.array([c[4] for c in cells_])
        pred = pa * (1 + beta * zr)
        ae = np.abs(pred - ob)
        inside = 0
        for p, o in zip(pred, ob):
            low, high = poisson_interval(p)
            inside += int(low <= o <= high)
        return {"mae": round(float(ae.mean()), 4), "rmse": round(float(np.sqrt((ae ** 2).mean())), 4),
                "interval_coverage": round(inside / len(cells_), 4), "cells": len(cells_)}

    def alert_capture(cells_, beta, budgets):
        by_date = {}
        for as_of, cat, pa, ob, zr in cells_:
            by_date.setdefault(as_of, []).append((pa * (1 + beta * zr), ob))
        out = {}
        total_events = sum(ob for _, _, _, ob, _ in cells_)
        for k in budgets:
            caught = 0
            for lst in by_date.values():
                lst_sorted = sorted(lst, key=lambda t: -t[0])[:k]
                caught += sum(o for _, o in lst_sorted)
            out[k] = {"events_caught": round(caught, 1),
                      "recall": round(caught / total_events, 4) if total_events else None}
        return out

    budgets = (1, 2, 3, 5)
    base = {"method": "current (recent_rate)", **metrics(holo, 0.0),
            "alerts": alert_capture(holo, 0.0, budgets)}
    aug = {"method": "current + scanning", "beta_chosen_on_train": beta, **metrics(holo, beta),
           "alerts": alert_capture(holo, beta, budgets)}

    better_mae = aug["mae"] < base["mae"] - 1e-9
    better_cov = aug["interval_coverage"] >= base["interval_coverage"] - 1e-9
    better_alert = any(aug["alerts"][k]["events_caught"] > base["alerts"][k]["events_caught"] + 1e-9
                       for k in budgets)
    if beta == 0.0:
        verdict = ("Training chose beta = 0: scanning does not reduce the count error even in "
                   "training, so it adds nothing. Keep scanning as a flag beside the forecast, not "
                   "fused into it.")
    elif better_mae and better_cov and better_alert:
        verdict = ("On the held-out tail, adding scanning lowers the count error, keeps interval "
                   "coverage and catches more at equal budget. A measurable benefit — candidate for "
                   "integration, still as a dedicated, separately-evaluated signal.")
    else:
        verdict = ("No measurable benefit on the held-out tail (not better on all of count error, "
                   "interval coverage and equal-budget alerts). Keep scanning as a flag beside the "
                   "forecast; do not fuse it in.")

    return {
        "experiment": "scanning added to the category forecast (dedicated check)",
        "horizon_days": horizon, "lookback_days": lookback, "step_days": step_days,
        "scan_window_days": scan_window, "scan_baseline_days": scan_baseline,
        "walk_forward": {"as_of_dates": len(as_of_sorted), "first": str(as_of_sorted[0]),
                         "last": str(as_of_sorted[-1]), "train_dates": len(sorted({c[0] for c in train})),
                         "holdout_dates": len(sorted({c[0] for c in holo})),
                         "holdout_from": str(cut), "cells_holdout": len(holo),
                         "events_holdout": int(sum(c[3] for c in holo))},
        "selection": "beta chosen on training only (min count MAE); the hold-out tail is used only "
                     "for the metrics below.",
        "methods": {"current": base, "current_plus_scanning": aug},
        "verdict": verdict,
        "limits": [
            "Retrospective and APPROXIMATE on the scanning side: only the latest (corrected) scan "
            "value is stored (no first-availability, no revision history), and most of it was "
            "back-filled ~1 year after the observed day, so the value used at a past date is the "
            "later-corrected one, not what was available then. Not verifiable; scans.py now records "
            "the first-seen value going forward for a future, verifiable run.",
            "Category is taken from the current NVD products and mapping, not as-of the past date "
            "(same reconstruction limit as the forecast backtest).",
            "Short history: scanning starts 2024-11, so few evaluable dates and a small hold-out.",
            "Measures anticipation of KEV listing, not of all real exploitation.",
        ],
    }
