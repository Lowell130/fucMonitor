"""Silent prospective evaluation: freeze today's predictions, score them only once their window
has actually closed AND the data covers it.

Every experiment so far is retrospective — it reconstructs the past and can be argued with on
what was knowable when. This is the opposite and the honest gold standard: each day we write down
what the live experimental model AND raw EPSS rank highest now, tagged with the issue date, the
model version and a reference to the inputs seen, and we never touch it again. When a prediction's
horizon has fully elapsed and KEV data covers the whole window, we compare both rankings with what
really happened (did the CVE enter CISA KEV in the window?). Nothing is scored before its window
closes and is covered; a new day's snapshot never overwrites an old one.

This logs the single-CVE KEV-ranking model only. The category forecast is a different unit and
keeps its own backtest; the two are kept separate on purpose.

The log lives under data/derived/predictions (recalculable, gitignored): one JSON file per
(kind, horizon, issue-date), append-only, written atomically with a backup copy. A `_runs.jsonl`
beside it records every daily run — logged, skipped, stale data, or error — so gaps are visible.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import duckdb

from ..config import Settings
from ..sources import SOURCES

_KIND = "cve_kev_ranking"
_STALE_AFTER_DAYS = 3  # EPSS older than this at issue time is flagged as stale input


def _log_dir(settings: Settings) -> Path:
    return Path(settings.data_dir) / "derived" / "predictions"


def _snapshot_path(settings: Settings, horizon: int, day: date) -> Path:
    return _log_dir(settings) / f"{_KIND}_h{horizon}_{day.isoformat()}.json"


def _atomic_write(path: Path, text: str) -> None:
    """Write to a temp file in the same dir, then replace: a crash never leaves a half file, and an
    existing file is swapped in one step. A timestamped backup copy is kept beside it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    backup_dir = path.parent / "_backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, backup_dir / path.name)


def _record_run(settings: Settings, entry: dict) -> None:
    """Append one line to the run log. Best-effort: a failed record never breaks the pipeline."""
    try:
        d = _log_dir(settings)
        d.mkdir(parents=True, exist_ok=True)
        entry = {"ran_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), **entry}
        with open(d / "_runs.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def _skipped_days(settings: Settings, horizon: int, today: date) -> list[str]:
    """Days between the most recent earlier snapshot and today that have no snapshot file."""
    d = _log_dir(settings)
    if not d.exists():
        return []
    prior = []
    for p in d.glob(f"{_KIND}_h{horizon}_*.json"):
        try:
            prior.append(date.fromisoformat(p.name.rsplit("_", 1)[1].removesuffix(".json")))
        except ValueError:
            continue
    prior = [x for x in prior if x < today]
    if not prior:
        return []
    last = max(prior)
    return [str(last + timedelta(days=i)) for i in range(1, (today - last).days)]


def snapshot_predictions(settings: Settings, horizon: int = 30, top: int = 200) -> dict:
    """Freeze today's model AND raw-EPSS top rankings for later scoring. Idempotent per day: if
    today's snapshot already exists it is kept untouched (never overwrite a recorded prediction)."""
    from ..state import utcnow
    from . import epss_experiment as ex

    today = utcnow().date()
    path = _snapshot_path(settings, horizon, today)
    if path.exists():
        _record_run(settings, {"status": "already_logged", "horizon": horizon, "issued_at": str(today)})
        return {"status": "already_logged", "issued_at": str(today), "path": path.name}

    epss_dates = ex._epss_dates(settings)
    data_as_of = epss_dates[-1] if epss_dates else None
    stale = bool(data_as_of is None or (today - data_as_of).days > _STALE_AFTER_DAYS)

    pred = ex.score_current(settings, horizon=horizon, top=top)
    # Union of the model's top-N and EPSS's top-N, each row carrying both scores, so a later
    # comparison ranks each method on its own complete top-N over the same frozen population.
    merged: dict[str, dict] = {}
    for it in pred["items"] + pred.get("epss_items", []):
        merged.setdefault(it["cve_id"], {"cve_id": it["cve_id"], "model_score": it["score"],
                                         "epss": it["epss"]})
    record = {
        "kind": _KIND,
        "unit": "single CVE (KEV-listing ranking)",
        "issued_at": str(today),
        "horizon_days": horizon,
        "window_closes": str(today + timedelta(days=horizon)),
        "model": pred["model"],
        "model_version": ex._EXPERIMENT_VERSION,
        "inputs_signature": ex._inputs_signature(settings, horizon),
        "data_as_of": str(data_as_of),
        "stale_inputs": stale,
        "top_n_each": top,
        "population_at_issue": pred["population"],
        "trained_on_test_dates": pred["trained_on_test_dates"],
        "items": list(merged.values()),  # each: cve_id, model_score, epss
    }
    try:
        _atomic_write(path, json.dumps(record, indent=2))
    except OSError as exc:
        _record_run(settings, {"status": "error", "horizon": horizon, "error": str(exc)})
        return {"status": "error", "error": str(exc)}
    _record_run(settings, {"status": "logged", "horizon": horizon, "issued_at": str(today),
                           "window_closes": record["window_closes"], "n_predicted": len(record["items"]),
                           "stale_inputs": stale, "data_as_of": str(data_as_of),
                           "skipped_days": _skipped_days(settings, horizon, today)})
    return {"status": "logged", "issued_at": str(today), "window_closes": record["window_closes"],
            "n_predicted": len(record["items"]), "stale_inputs": stale}


def daily_snapshot(settings: Settings) -> None:
    """Scheduler hook: take today's snapshot, recording failures/skips/stale data to the run log
    and never raising, so a failed snapshot cannot disturb ingestion. Silent by design."""
    try:
        snapshot_predictions(settings, horizon=30)
    except Exception as exc:  # noqa: BLE001 - a prediction log must never break the pipeline
        _record_run(settings, {"status": "error", "horizon": 30, "error": repr(exc)})


def _load_snapshots(settings: Settings, horizon: int) -> list[dict]:
    d = _log_dir(settings)
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob(f"{_KIND}_h{horizon}_*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (ValueError, OSError):
            continue
    return out


def _precision_at_k(items: list[dict], key: str, ks, entered) -> dict:
    ranked = sorted(items, key=lambda it: -it.get(key, 0.0))
    out = {}
    for k in ks:
        topk = ranked[:k]
        hits = sum(1 for it in topk if entered(it["cve_id"]))
        out[int(k)] = {"hits": hits, "precision": round(hits / len(topk), 4) if topk else None}
    return out


def score_prospective(settings: Settings, horizon: int = 30, ks=(10, 20, 50, 100)) -> dict:
    """Score logged snapshots whose window has closed AND whose window is covered by KEV data,
    comparing the model ranking with the raw-EPSS ranking. Windows that are not yet closed, or not
    yet covered by observed KEV data, are reported as pending and NOT scored."""
    from ..state import utcnow

    today = utcnow().date()
    snaps = _load_snapshots(settings, horizon)
    if not snaps:
        return {"kind": _KIND, "horizon_days": horizon, "closed_scored": 0, "pending": 0,
                "note": "no snapshots logged yet; the daily job accumulates them going forward."}

    kev_files = SOURCES["kev"].curated_files(settings)
    kev: dict[str, date] = {}
    kev_max: date | None = None
    if kev_files:
        con = duckdb.connect()
        try:
            for cve, d in con.execute(
                "SELECT cve_id, min(date_added) FROM read_parquet(?) GROUP BY 1", [kev_files]
            ).fetchall():
                kev[cve] = d
                if d is not None and (kev_max is None or d > kev_max):
                    kev_max = d
        finally:
            con.close()

    per_snapshot = []
    pending = pending_uncovered = 0
    pooled = {"model": {int(k): [0, 0] for k in ks}, "epss": {int(k): [0, 0] for k in ks}}
    for s in snaps:
        issued = date.fromisoformat(s["issued_at"])
        closes = date.fromisoformat(s["window_closes"])
        if closes > today:
            pending += 1
            continue
        if kev_max is None or kev_max < closes:
            # window has elapsed on the calendar but our KEV data does not yet reach its end
            pending_uncovered += 1
            continue

        def entered(cve: str) -> bool:
            d = kev.get(cve)
            return d is not None and issued < d <= closes
        items = s["items"]
        n_window = sum(1 for cve, d in kev.items() if issued < d <= closes)
        mp = _precision_at_k(items, "model_score", ks, entered)
        ep = _precision_at_k(items, "epss", ks, entered)
        for k in ks:
            pooled["model"][int(k)][0] += mp[int(k)]["hits"]; pooled["model"][int(k)][1] += min(k, len(items))
            pooled["epss"][int(k)][0] += ep[int(k)]["hits"]; pooled["epss"][int(k)][1] += min(k, len(items))
        per_snapshot.append({
            "issued_at": s["issued_at"], "window_closes": s["window_closes"],
            "model_version": s.get("model_version"), "stale_inputs": s.get("stale_inputs"),
            "kev_entries_in_window": n_window,
            "precision_at_k": {"model": {k: v["precision"] for k, v in mp.items()},
                               "epss": {k: v["precision"] for k, v in ep.items()}}})

    def pooled_prec(side):
        return {k: (round(h / n, 4) if n else None) for k, (h, n) in pooled[side].items()}

    closed = len(per_snapshot)
    return {
        "kind": _KIND,
        "unit": "single CVE (KEV-listing ranking); kept separate from the category forecast",
        "horizon_days": horizon,
        "comparison": "model (EPSS+age) vs raw EPSS, same frozen population, prospective",
        "closed_scored": closed,
        "pending_window_open": pending,
        "pending_data_not_covering_window": pending_uncovered,
        "per_snapshot": per_snapshot,
        "pooled_precision_at_k": {"model": pooled_prec("model"), "epss": pooled_prec("epss")} if closed else None,
        "note": (
            "Genuine prospective evaluation: predictions were frozen at issue and scored only after "
            "their window closed and KEV data covered it, so there is no retrospective "
            "reconstruction. " + (f"{closed} window(s) scored; {pending} still open, "
            f"{pending_uncovered} elapsed but not yet covered by KEV data."
            if closed else f"Nothing scored yet; {pending} open, {pending_uncovered} awaiting KEV "
            "coverage. Precision@k (model vs EPSS) appears once the first window closes and is covered.")),
    }
