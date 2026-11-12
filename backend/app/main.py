"""fucMonitor API. The API is the only door to the data: dashboards never read files directly."""

import json
import logging
import threading
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query

from . import queries, runner, state
from .config import get_settings
from .sources import SOURCES
from .sources.news import load_feeds

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("fucmonitor")

TAXONOMY = Path(__file__).parent / "taxonomy" / "categories.json"
VERSION = "0.1.0"


def _schedule(settings) -> BackgroundScheduler | None:
    if not settings.scheduler_enabled:
        return None
    scheduler = BackgroundScheduler(timezone="UTC")
    for slot in settings.schedule_times_utc.split(","):
        hour, minute = slot.strip().split(":")
        scheduler.add_job(
            runner.run_all,
            CronTrigger(hour=int(hour), minute=int(minute), timezone="UTC"),
            args=[settings],
            id=f"ingest-{slot.strip()}",
            misfire_grace_time=3600,
            coalesce=True,
        )
    scheduler.add_job(
        runner.run_all,
        IntervalTrigger(minutes=max(5, settings.news_interval_minutes), timezone="UTC"),
        kwargs={"settings": settings, "cadence": "interval"},
        id="ingest-interval",
        misfire_grace_time=600,
        coalesce=True,
    )
    scheduler.start()
    return scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    state.mark_interrupted(settings.state_db)
    scheduler = _schedule(settings)
    if settings.scheduler_enabled and settings.run_on_startup:
        threading.Thread(
            target=runner.run_startup, args=[settings], daemon=True, name="startup-ingest"
        ).start()
    app.state.scheduler = scheduler
    yield
    if scheduler:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="fucMonitor API",
    version=VERSION,
    description="Exploitation trends by technology category. Trends, not attribution.",
    lifespan=lifespan,
)


def _source(name: str):
    if name not in SOURCES:
        raise HTTPException(404, f"Unknown source '{name}'. Known: {', '.join(SOURCES)}")
    return SOURCES[name]


@app.get("/health", tags=["system"])
def health() -> dict:
    return {"status": "ok", "version": VERSION, "time_utc": state.iso(state.utcnow())}


# --- sources and jobs --------------------------------------------------------
def _source_status(settings, name: str) -> dict:
    source = SOURCES[name]
    dates = source.snapshot_dates(settings)
    latest = dates[-1] if dates else None
    last_ok = state.last_run(settings.state_db, name, "success")
    today = state.utcnow().date()
    return {
        "name": name,
        "title": source.title,
        "homepage": source.homepage,
        "cadence": source.cadence,
        "running": runner.is_running(name),
        "snapshots": len(dates),
        "first_snapshot_date": dates[0] if dates else None,
        "latest_snapshot_date": latest,
        "latest_snapshot_age_days": (today - latest).days if latest else None,
        "latest_rows": queries.count_rows(source.curated_path(settings, latest)) if latest else None,
        "last_run": state.last_run(settings.state_db, name),
        "last_success_at": last_ok["finished_at"] if last_ok else None,
    }


@app.get("/api/v1/sources", tags=["pipeline"])
def list_sources() -> dict:
    settings = get_settings()
    scheduler = app.state.scheduler
    daily = [j.next_run_time for j in scheduler.get_jobs() if j.id != "ingest-interval"] if scheduler else []
    next_run = min(daily, default=None)
    return {
        "scheduler_enabled": settings.scheduler_enabled,
        "schedule_times_utc": settings.schedule_times_utc,
        "news_interval_minutes": max(5, settings.news_interval_minutes),
        "next_scheduled_run": state.iso(next_run) if next_run else None,
        "sources": [_source_status(settings, name) for name in SOURCES],
    }


@app.post("/api/v1/sources/{name}/run", status_code=202, tags=["pipeline"])
def run_source(name: str, background: BackgroundTasks) -> dict:
    _source(name)
    if runner.is_running(name):
        raise HTTPException(409, f"Source '{name}' is already running")
    background.add_task(_run_quietly, name, None)
    return {"accepted": True, "source": name}


@app.post("/api/v1/sources/epss/backfill", status_code=202, tags=["pipeline"])
def backfill_epss(
    background: BackgroundTasks,
    start: date = Query(..., description="First day, YYYY-MM-DD"),
    end: date = Query(..., description="Last day, inclusive"),
) -> dict:
    """Download historical EPSS days that are not stored yet. One request per day, in order."""
    days = (end - start).days + 1
    if days < 1 or days > 400:
        raise HTTPException(422, "The range must cover between 1 and 400 days")
    have = set(SOURCES["epss"].snapshot_dates(get_settings()))
    todo = [d for d in (date.fromordinal(start.toordinal() + i) for i in range(days)) if d not in have]
    background.add_task(_backfill, todo)
    return {"accepted": True, "days_requested": days, "days_to_download": len(todo)}


def _run_quietly(name: str, day: date | None) -> None:
    try:
        runner.run_source(get_settings(), name, "backfill" if day else "manual", backfill_day=day)
    except runner.AlreadyRunning:
        log.info("%s: already running, request dropped", name)


def _backfill(days: list[date]) -> None:
    for day in days:
        _run_quietly("epss", day)


@app.get("/api/v1/jobs", tags=["pipeline"])
def list_jobs(source: str | None = None, limit: int = Query(50, ge=1, le=500)) -> dict:
    if source:
        _source(source)
    return {"items": state.list_runs(get_settings().state_db, source, limit)}


# --- data --------------------------------------------------------------------
@app.get("/api/v1/overview", tags=["data"])
def overview() -> dict:
    return queries.overview(get_settings())


@app.get("/api/v1/kev", tags=["data"])
def kev(
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    search: str | None = Query(None, description="Matches CVE, vendor, product or name"),
    since: date | None = Query(None, description="Only entries added on or after this date"),
) -> dict:
    return queries.kev_list(get_settings(), limit, offset, search, since)


@app.get("/api/v1/kev/timeline", tags=["data"])
def kev_timeline() -> dict:
    return queries.kev_timeline(get_settings())


@app.get("/api/v1/kev/vendors", tags=["data"])
def kev_vendors(limit: int = Query(20, ge=1, le=200)) -> dict:
    return queries.kev_top_vendors(get_settings(), limit)


@app.get("/api/v1/epss/top", tags=["data"])
def epss_top(limit: int = Query(100, ge=1, le=2000)) -> dict:
    return queries.epss_top(get_settings(), limit)


@app.get("/api/v1/epss/{cve_id}", tags=["data"])
def epss_history(cve_id: str) -> dict:
    return queries.epss_history(get_settings(), cve_id)


@app.get("/api/v1/news", tags=["data"])
def news(
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    search: str | None = Query(None, description="Matches title, summary or CVE"),
    feed: str | None = Query(None, description="Feed id"),
    language: str | None = None,
    kind: str | None = Query(None, description="primary, specialist or general"),
    has_cve: bool | None = Query(None, description="Only items that mention a CVE"),
    since: date | None = Query(None, description="First seen on or after this date (UTC)"),
    event_type: str | None = Query(None, description="Event type id from the taxonomy"),
    claim_status: str | None = Query(None, description="official, reported or unverified"),
    sector: str | None = Query(None, description="Target sector id from the taxonomy"),
    exploited: bool | None = Query(None, description="Text reports exploitation"),
    collapse: bool = Query(False, description="One row per story instead of one per item"),
) -> dict:
    return queries.news_list(
        get_settings(), limit, offset, search, feed, language, kind, has_cve, since,
        event_type, claim_status, sector, exploited, collapse,
    )


@app.get("/api/v1/news/trend", tags=["data"])
def news_trend(
    by: str = Query("event_type", pattern="^(event_type|sector)$"),
    days: int = Query(30, ge=1, le=365),
) -> dict:
    """Distinct stories per publication day. Labels come from keyword rules."""
    return queries.news_trend(get_settings(), by, days)


@app.post("/api/v1/news/relabel", tags=["pipeline"])
def news_relabel() -> dict:
    """Recompute event type, claim status, sectors and stories for every stored item."""
    return {"items": runner.refresh_news_labels(get_settings(), force=True) or 0}


@app.get("/api/v1/news/daily", tags=["data"])
def news_daily() -> dict:
    """Items per day we first saw them, by kind of source."""
    return queries.news_daily(get_settings())


@app.get("/api/v1/news/feeds", tags=["pipeline"])
def news_feeds() -> dict:
    settings = get_settings()
    states = state.feed_states(settings.state_db)
    blank = {"last_fetch_at": None, "last_status": None, "last_message": None, "last_success_at": None,
             "items_seen": 0, "items_new": 0, "total_items": 0, "consecutive_failures": 0}
    items = []
    for feed in load_feeds(settings)["feeds"]:
        saved = states.get(feed["id"], {})
        items.append({**feed, "enabled": feed.get("enabled", True),
                      **{k: saved.get(k, v) for k, v in blank.items()}})
    return {"items": items}


@app.get("/api/v1/taxonomy", tags=["data"])
def taxonomy() -> dict:
    return json.loads(TAXONOMY.read_text(encoding="utf-8"))
