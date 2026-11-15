"""Silent prospective evaluation: freeze today's predictions, score them only once their window
has actually closed.

Every experiment so far is retrospective — it reconstructs the past and can be argued with on
what was knowable when. This is the opposite and the honest gold standard: each day we write down
what the live experimental model predicts now, tagged with the issue date, the model version and
a reference to the inputs it saw, and we never touch it again. When a prediction's horizon has
fully elapsed we compare it with what really happened (did the CVE enter CISA KEV in the window?).
Nothing is scored before its window closes, and a new day's snapshot never overwrites an old one.

This logs the single-CVE KEV-ranking model only. The category forecast is a different unit and
gets its own log if and when we want one; the two are kept separate on purpose.

The log lives under data/derived/predictions (recalculable, gitignored): one JSON file per
(kind, horizon, issue-date), append-only.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import duckdb

from ..config import Settings
from ..sources import SOURCES

_KIND = "cve_kev_ranking"


def _log_dir(settings: Settings) -> Path:
    return Path(settings.data_dir) / "derived" / "predictions"


def _snapshot_path(settings: Settings, horizon: int, day: date) -> Path:
    return _log_dir(settings) / f"{_KIND}_h{horizon}_{day.isoformat()}.json"


def snapshot_predictions(settings: Settings, horizon: int = 30, top: int = 200) -> dict:
    """Freeze today's EPSS+age ranking for later scoring. Idempotent per day: if today's snapshot
    already exists it is kept untouched (never overwrite a recorded prediction)."""
    from ..state import utcnow
    from . import epss_experiment as ex

    today = utcnow().date()
    path = _snapshot_path(settings, horizon, today)
    if path.exists():
        return {"status": "already_logged", "issued_at": str(today), "path": path.name}

    pred = ex.score_current(settings, horizon=horizon, top=top)
    record = {
        "kind": _KIND,
        "unit": "single CVE (KEV-listing ranking)",
        "issued_at": str(today),
        "horizon_days": horizon,
        "window_closes": str(today + timedelta(days=horizon)),
        "model": pred["model"],
        "model_version": ex._EXPERIMENT_VERSION,
        "inputs_signature": ex._inputs_signature(settings, horizon),
        "data_as_of": pred["as_of"],
        "population_at_issue": pred["population"],
        "trained_on_test_dates": pred["trained_on_test_dates"],
        "items": [{"cve_id": it["cve_id"], "score": it["score"]} for it in pred["items"]],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    except OSError as exc:
        return {"status": "error", "error": str(exc)}
    return {"status": "logged", "issued_at": str(today), "window_closes": record["window_closes"],
            "n_predicted": len(record["items"])}


def daily_snapshot(settings: Settings) -> None:
    """Scheduler hook: take today's snapshot, swallowing any error (numpy missing, etc.) so a
    failed snapshot never disturbs ingestion. Silent by design."""
    try:
        snapshot_predictions(settings, horizon=30)
    except Exception:  # noqa: BLE001 - a prediction log must never break the pipeline
        pass


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


def score_prospective(settings: Settings, horizon: int = 30, ks=(10, 20, 50, 100)) -> dict:
    """Score every logged snapshot whose window has closed against real KEV entries. Snapshots
    whose window is still open are reported as pending and NOT scored."""
    from ..state import utcnow

    today = utcnow().date()
    snaps = _load_snapshots(settings, horizon)
    if not snaps:
        return {"kind": _KIND, "horizon_days": horizon, "closed": 0, "pending": 0,
                "note": "no snapshots logged yet; the daily job accumulates them going forward."}

    kev_files = SOURCES["kev"].curated_files(settings)
    kev = {}
    if kev_files:
        con = duckdb.connect()
        try:
            for cve, d in con.execute(
                "SELECT cve_id, min(date_added) FROM read_parquet(?) GROUP BY 1", [kev_files]
            ).fetchall():
                kev[cve] = d
        finally:
            con.close()

    per_snapshot = []
    pending = 0
    pooled = {int(k): {"hits": 0, "slots": 0} for k in ks}
    pooled_window_entries = 0
    for s in snaps:
        issued = date.fromisoformat(s["issued_at"])
        closes = date.fromisoformat(s["window_closes"])
        if closes > today:
            pending += 1
            continue
        items = s["items"]
        # a prediction is correct if the CVE first entered KEV within (issued, closes]
        def entered(cve: str) -> bool:
            d = kev.get(cve)
            return d is not None and issued < d <= closes
        n_window_entries = sum(1 for cve, d in kev.items() if issued < d <= closes)
        pooled_window_entries += n_window_entries
        row = {"issued_at": s["issued_at"], "window_closes": s["window_closes"],
               "model_version": s.get("model_version"), "n_predicted": len(items),
               "kev_entries_in_window": n_window_entries, "precision_at_k": {}}
        for k in ks:
            topk = items[:k]
            hits = sum(1 for it in topk if entered(it["cve_id"]))
            row["precision_at_k"][int(k)] = round(hits / len(topk), 4) if topk else None
            pooled[int(k)]["hits"] += hits
            pooled[int(k)]["slots"] += len(topk)
        per_snapshot.append(row)

    pooled_prec = {k: (round(v["hits"] / v["slots"], 4) if v["slots"] else None) for k, v in pooled.items()}
    closed = len(per_snapshot)
    return {
        "kind": _KIND,
        "unit": "single CVE (KEV-listing ranking); kept separate from the category forecast",
        "horizon_days": horizon,
        "closed": closed,
        "pending": pending,
        "per_snapshot": per_snapshot,
        "pooled_precision_at_k": pooled_prec if closed else None,
        "total_kev_entries_in_closed_windows": pooled_window_entries,
        "note": (
            "Genuine prospective evaluation: predictions were frozen at issue and scored only "
            "after their window closed, so there is no retrospective reconstruction here. "
            + (f"{closed} window(s) scored, {pending} still open."
               if closed else f"Nothing scored yet; {pending} snapshot(s) pending. "
               "Precision@k will appear once the first 30-day window closes.")),
    }
