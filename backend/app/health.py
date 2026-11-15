"""Collection reliability: a daily, at-a-glance check that every source and the prediction log
are up to date, and that any failure is visible rather than silent.

For each source it reports the latest stored snapshot, how old it is, the outcome of the last
ingestion run, and whether that is within the cadence we expect (daily sources should have a
snapshot from today or yesterday; the interval source — news — should have run within a couple of
hours). It also surfaces the prediction log's last run. `ok` is true only when nothing is stale and
no last run failed; `problems` lists what to look at, so errors are not buried.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import state
from .config import Settings
from .sources import SOURCES

_DAILY_STALE_DAYS = 2        # a daily source with no snapshot for >2 days is stale
_INTERVAL_STALE_HOURS = 3    # the interval source (news) should have run within a few hours


def _parse_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _prediction_log_last(settings: Settings) -> dict | None:
    path = Path(settings.data_dir) / "derived" / "predictions" / "_runs.jsonl"
    if not path.exists():
        return None
    try:
        last = None
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        return json.loads(last) if last else None
    except (OSError, ValueError):
        return None


def collection_report(settings: Settings) -> dict:
    from .state import utcnow

    now = utcnow()
    today = now.date()
    sources = []
    problems = []
    for name, src in sorted(SOURCES.items()):
        snaps = src.snapshot_dates(settings)
        latest = snaps[-1] if snaps else None
        age_days = (today - latest).days if latest else None
        last = state.last_run(settings.state_db, name)
        last_status = last.get("status") if last else None
        last_finished = _parse_ts(last.get("finished_at") or last.get("started_at")) if last else None
        cadence = getattr(src, "cadence", "daily")

        stale = False
        if cadence == "interval":
            stale = last_finished is None or (now - last_finished) > timedelta(hours=_INTERVAL_STALE_HOURS)
        else:
            stale = latest is None or age_days > _DAILY_STALE_DAYS
        failed = last_status not in (None, "success", "running")  # 'running' is normal, in-progress

        entry = {
            "source": name, "cadence": cadence,
            "latest_snapshot": str(latest) if latest else None,
            "age_days": age_days,
            "last_run_status": last_status,
            "last_run_finished": str(last.get("finished_at")) if last and last.get("finished_at") else None,
            "last_error": last.get("message") if failed and last else None,
            "stale": bool(stale),
        }
        sources.append(entry)
        if stale:
            problems.append(f"{name}: stale (latest {entry['latest_snapshot']}, age {age_days}d)")
        if failed:
            problems.append(f"{name}: last run {last_status} — {entry['last_error']}")

    pred = _prediction_log_last(settings)
    pred_block = None
    if pred is not None:
        pred_block = {"last_run": pred.get("ran_at"), "status": pred.get("status"),
                      "issued_at": pred.get("issued_at"), "stale_inputs": pred.get("stale_inputs"),
                      "skipped_days": pred.get("skipped_days"), "error": pred.get("error")}
        if pred.get("status") == "error":
            problems.append(f"prediction snapshot: error — {pred.get('error')}")
        if pred.get("stale_inputs"):
            problems.append("prediction snapshot: inputs were stale at issue")
        if pred.get("skipped_days"):
            problems.append(f"prediction snapshot: skipped days {pred.get('skipped_days')}")

    return {
        "checked_at": now.replace(microsecond=0).isoformat(),
        "ok": len(problems) == 0,
        "problems": problems,
        "sources": sources,
        "prediction_log": pred_block,
    }
