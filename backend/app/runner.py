"""Runs an ingestion and records the outcome. Used by the API, the scheduler and the CLI."""

import logging
import threading
from datetime import date

import httpx

from . import state
from .config import Settings
from .sources import SOURCES, IngestResult

log = logging.getLogger("fucmonitor.runner")

_locks = {name: threading.Lock() for name in SOURCES}


class AlreadyRunning(RuntimeError):
    pass


def http_client(settings: Settings) -> httpx.Client:
    return httpx.Client(
        timeout=settings.http_timeout,
        follow_redirects=True,
        headers={"User-Agent": settings.user_agent},
    )


def is_running(name: str) -> bool:
    return _locks[name].locked()


def run_source(
    settings: Settings,
    name: str,
    trigger: str = "manual",
    backfill_day: date | None = None,
    client: httpx.Client | None = None,
) -> dict:
    """Ingest one source. Never raises for source errors: the failure is stored and returned."""
    source = SOURCES[name]
    lock = _locks[name]
    if not lock.acquire(blocking=False):
        raise AlreadyRunning(name)
    run_id = state.start_run(settings.state_db, name, trigger)
    owns_client = client is None
    client = client or http_client(settings)
    try:
        if backfill_day is not None:
            result: IngestResult = source.backfill(settings, client, backfill_day)  # type: ignore[attr-defined]
        else:
            result = source.ingest(settings, client)
        state.finish_run(
            settings.state_db,
            run_id,
            "success",
            snapshot_date=result.snapshot_date.isoformat(),
            rows=result.rows,
            bytes=result.bytes,
            sha256=result.sha256,
            changed=result.changed,
            message=result.message,
        )
        log.info("%s: %s, %s rows, snapshot %s", name, result.message, result.rows, result.snapshot_date)
    except Exception as exc:  # noqa: BLE001 - every failure must end up in the job history
        log.exception("%s: ingestion failed", name)
        state.finish_run(
            settings.state_db, run_id, "failed", message=f"{type(exc).__name__}: {exc}"[:1000]
        )
    finally:
        if owns_client:
            client.close()
        lock.release()
    return state.get_run(settings.state_db, run_id)


def run_all(settings: Settings, trigger: str = "schedule", only_if_missing_today: bool = False) -> None:
    today = state.utcnow().date()
    for name, source in SOURCES.items():
        if only_if_missing_today and today in source.snapshot_dates(settings):
            continue
        try:
            run_source(settings, name, trigger)
        except AlreadyRunning:
            log.info("%s: already running, skipped", name)
