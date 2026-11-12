"""Renders every page in both languages against a fake API and fails on any exception."""

from pathlib import Path

import httpx
import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "app.py")
RUN = {"id": 1, "source": "kev", "trigger": "manual", "status": "success", "started_at": "2026-11-12T06:15:00Z",
       "finished_at": "2026-11-12T06:15:02Z", "snapshot_date": "2026-11-12", "rows": 2, "bytes": 10,
       "sha256": "ab", "changed": True, "message": "stored"}
FAILED = {**RUN, "id": 2, "source": "epss", "status": "failed", "message": "HTTPStatusError: 503", "rows": None}


def source(name, **over):
    base = {"name": name, "title": name.upper(), "homepage": "https://example.org", "running": False,
            "snapshots": 2, "first_snapshot_date": "2026-11-11", "latest_snapshot_date": "2026-11-12",
            "latest_snapshot_age_days": 0, "latest_rows": 1234, "last_run": RUN, "last_success_at": "x"}
    return {**base, **over}


FULL = {
    "/health": {"status": "ok"},
    "/api/v1/overview": {
        "kev_snapshot_date": "2026-11-12", "epss_snapshot_date": "2026-11-12", "kev_total": 1500,
        "kev_added_last_30_days": 12, "kev_ransomware": 300, "epss_total": 300000, "epss_high": 9000,
        "kev_epss": {"kev_cves": 1500, "with_epss": 1490, "median_epss": 0.42, "epss_ge_10pct": 900, "epss_lt_1pct": 150},
    },
    "/api/v1/kev/timeline": {"snapshot_date": "2026-11-12", "items": [{"month": "2026-10", "added": 9}, {"month": "2026-11", "added": 4}]},
    "/api/v1/kev/vendors": {"snapshot_date": "2026-11-12", "items": [{"vendor_project": "Acme", "cves": 5, "last_added": "2026-11-10"}]},
    "/api/v1/sources": {"scheduler_enabled": True, "schedule_times_utc": "06:15,18:15", "next_scheduled_run": "2026-11-12T18:15:00Z",
                        "sources": [source("kev"), source("epss", last_run=FAILED, running=True)]},
    "/api/v1/jobs": {"items": [FAILED, RUN]},
    "/api/v1/kev": {"snapshot_date": "2026-11-12", "total": 1, "items": [
        {"cve_id": "CVE-2024-0001", "vendor_project": "Acme", "product": "Gateway", "vulnerability_name": "X",
         "date_added": "2026-11-10", "due_date": "2026-12-01", "known_ransomware_campaign_use": "Known",
         "cwes": ["CWE-78", "CWE-20"], "short_description": "d"}]},
    "/api/v1/epss/top": {"snapshot_date": "2026-11-12", "items": [{"cve_id": "CVE-2024-0001", "epss": 0.94, "percentile": 0.999, "in_kev": True}]},
}
EMPTY = {
    "/health": {"status": "ok"},
    "/api/v1/overview": {"kev_snapshot_date": None, "epss_snapshot_date": None, "kev_total": None,
                         "kev_added_last_30_days": None, "kev_ransomware": None, "epss_total": None,
                         "epss_high": None, "kev_epss": None},
    "/api/v1/sources": {"scheduler_enabled": False, "schedule_times_utc": "", "next_scheduled_run": None,
                        "sources": [source("kev", snapshots=0, latest_snapshot_date=None, latest_snapshot_age_days=None,
                                           latest_rows=None, last_run=None)]},
    "/api/v1/jobs": {"items": []},
    "/api/v1/kev": {"snapshot_date": None, "total": 0, "items": []},
    "/api/v1/epss/top": {"snapshot_date": None, "items": []},
}


@pytest.mark.parametrize("responses", [FULL, EMPTY], ids=["full", "empty"])
@pytest.mark.parametrize("lang", ["en", "it"])
@pytest.mark.parametrize("page", ["overview", "pipeline", "kev", "epss"])
def test_page_renders(monkeypatch, responses, lang, page):
    def fake(method, url, params=None, timeout=None):
        path = httpx.URL(url).path
        return httpx.Response(200, json=responses[path], request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", fake)
    at = AppTest.from_file(APP, default_timeout=30)
    at.session_state["lang"] = lang
    at.run()
    at.sidebar.radio[0].set_value(page).run()
    assert not at.exception, at.exception
    visible = " ".join(str(e.value) for e in [*at.header, *at.subheader, *at.caption, *at.info])
    for prefix in ("nav.", "overview.", "pipeline.", "common.", "epss.", "kev.", "app."):
        assert prefix not in visible, visible


def test_api_down_shows_a_message_instead_of_a_traceback(monkeypatch):
    def boom(*args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "request", boom)
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception and len(at.error) == 1
