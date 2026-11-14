"""Renders every page in both languages against a fake API and fails on any exception."""

from pathlib import Path

import httpx
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "app.py")
RUN = {"id": 1, "source": "kev", "trigger": "manual", "status": "success", "started_at": "2026-11-12T06:15:00Z",
       "finished_at": "2026-11-12T06:15:02Z", "snapshot_date": "2026-11-12", "rows": 2, "bytes": 10,
       "sha256": "ab", "changed": True, "message": "stored"}
FAILED = {**RUN, "id": 2, "source": "epss", "status": "failed", "message": "HTTPStatusError: 503", "rows": None}


TAXONOMY = {
    "event_types": [{"id": "hoax_disruption", "en": "Hoax", "it": "Falsi allarmi"},
                    {"id": "vulnerability_exploitation", "en": "Exploitation", "it": "Sfruttamento"},
                    {"id": "vulnerability_disclosure", "en": "Disclosure", "it": "Divulgazione"}],
    "target_sectors": [{"id": "education", "en": "Schools", "it": "Scuole"}],
    "technology_categories": [{"id": "web_cms", "en": "Web and CMS", "it": "Web e CMS"},
                              {"id": "firewall_security_appliance", "en": "Firewalls", "it": "Firewall"}],
    "claim_statuses": [{"id": "reported", "en": "Reported", "it": "Riportato"}],
}


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
    "/api/v1/sources": {"scheduler_enabled": True, "schedule_times_utc": "06:15,18:15", "news_interval_minutes": 60, "next_scheduled_run": "2026-11-12T18:15:00Z",
                        "sources": [source("kev"), source("epss", last_run=FAILED, running=True)]},
    "/api/v1/jobs": {"items": [FAILED, RUN]},
    "/api/v1/kev": {"snapshot_date": "2026-11-12", "total": 1, "items": [
        {"cve_id": "CVE-2024-0001", "vendor_project": "Acme", "product": "Gateway", "vulnerability_name": "X",
         "date_added": "2026-11-10", "due_date": "2026-12-01", "known_ransomware_campaign_use": "Known",
         "cwes": ["CWE-78", "CWE-20"], "short_description": "d"}]},
    "/api/v1/news": {"total": 2, "items": [
        {"item_id": "a", "feed_id": "rss", "feed_title": "Sec", "source_kind": "specialist", "language": "en",
         "title": "Flaw exploited", "link": "https://example.org/a", "summary": "s", "published_at": "2026-11-12T08:00:00Z",
         "first_seen_at": "2026-11-12T09:00:00Z", "cve_ids": ["CVE-2026-1234"], "event_type": "vulnerability_exploitation",
         "exploitation_signal": True, "claim_status": "reported", "target_sectors": [], "story_id": "a", "story_feeds": 2},
        {"item_id": "b", "feed_id": "gen", "feed_title": "Gen", "source_kind": "general", "language": "it",
         "title": "Allarme", "link": "", "summary": "", "published_at": None,
         "first_seen_at": "2026-11-12T09:00:00Z", "cve_ids": [], "event_type": None,
         "exploitation_signal": None, "claim_status": None, "target_sectors": None, "story_id": "b", "story_feeds": 1}]},
    "/api/v1/news/trend": {"by": "event_type", "days": 14, "items": [
        {"day": "2026-11-11", "key": "hoax_disruption", "stories": 4}, {"day": "2026-11-12", "key": "hoax_disruption", "stories": 7},
        {"day": "2026-11-12", "key": "education", "stories": 3}]},
    "/api/v1/taxonomy": TAXONOMY,
    "/api/v1/news/feeds": {"items": [
        {"id": "rss", "title": "Sec", "url": "https://x/rss", "language": "en", "kind": "specialist", "enabled": True,
         "last_fetch_at": "2026-11-12T09:00:00Z", "last_status": "ok", "last_message": "", "last_success_at": "x",
         "items_seen": 3, "items_new": 1, "total_items": 3, "consecutive_failures": 0},
        {"id": "gen", "title": "Gen", "url": "https://x/gen", "language": "it", "kind": "general", "enabled": True,
         "last_fetch_at": "2026-11-12T09:00:00Z", "last_status": "failed", "last_message": "HTTPStatusError: 404",
         "last_success_at": None, "items_seen": 0, "items_new": 0, "total_items": 0, "consecutive_failures": 2}]},
    "/api/v1/nvd/overview": {"total": 310000, "with_cvss": 290000, "with_products": 250000,
                             "with_exploit_reference": 41000, "retrieved_at": "2026-11-13T06:20:00Z",
                             "by_year": [{"year": 2025, "cves": 40000}, {"year": 2026, "cves": 38000}],
                             "by_severity": [{"severity": "HIGH", "cves": 100}, {"severity": "CRITICAL", "cves": 50}]},
    "/api/v1/nvd/vendors": {"items": [{"vendor": "acme", "cves": 120, "products": 14}]},
    "/api/v1/categories/coverage": {"products": 9000, "products_mapped": 6000, "products_manual": 12,
                                    "cves": 250000, "cves_mapped": 190000, "kev_cves": 1700,
                                    "kev_cves_mapped": 1600, "recent_cves": 80000,
                                    "recent_cves_mapped": 60000, "rules_version": "2026.11.13-1+12"},
    "/api/v1/analysis/forecast": {"horizon": 90, "lookback_days": 365, "method": "recent_rate",
        "generated_for": "2026-11-13", "items": [
        {"category": "firewall_security_appliance", "expected": 3.4, "low": 1.1, "high": 7.2,
         "recent_events": 14, "recent_cves": 120, "last_exploited": "2026-11-01",
         "share": 0.11, "median_days": 12}]},
    "/api/v1/analysis/backtest": {"horizon": 90, "step_days": 30, "from": "2024-09-21",
        "to": "2026-08-12", "observed_total": 1502,
        "methods": [{"method": "recent_rate_365", "points": 336, "mean_absolute_error": 2.409,
                     "rmse": 3.262, "interval_coverage": 0.827},
                    {"method": "volume_rate", "points": 336, "mean_absolute_error": 2.639,
                     "rmse": 3.62, "interval_coverage": 0.786}],
        "evaluations": [{"at": "2024-09-21", "category": "firewall_security_appliance", "observed": 4,
                         "predictions": {"recent_rate_365": {"expected": 3.1, "low": 1.0, "high": 7.0,
                                                             "inside": True},
                                         "volume_rate": {"expected": 1.2, "low": 0.1, "high": 5.0,
                                                         "inside": True}}}]},
    "/api/v1/analysis/rates": {"horizons": [30, 90, 365], "items": [
        {"category": "firewall_security_appliance", "horizons": {"90": {
            "eligible": 100, "exploited": 11, "share": 0.11, "share_low": 0.05,
            "share_high": 0.2, "median_days": 12}}}]},
    "/api/v1/analysis/time-to-exploit": {"items": [
        {"category": "firewall_security_appliance", "exploited": 11, "median_days": 12, "p25_days": 3,
         "p75_days": 40, "within_7": 4, "within_30": 8, "share_within_7": 0.36, "share_within_30": 0.72}]},
    "/api/v1/scans/surges": {"baseline_days": 30, "min_z": 2.0, "surges": [
        {"port": 445, "category": "operating_system", "service": "SMB", "as_of": "2026-11-13",
         "latest_sources": 60000, "baseline_mean": 15000.0, "baseline_sd": 3000.0, "baseline_days": 29,
         "z": 15.0, "ratio": 4.0}],
        "all": [{"port": 445, "category": "operating_system", "service": "SMB", "as_of": "2026-11-13",
         "latest_sources": 60000, "baseline_mean": 15000.0, "baseline_sd": 3000.0, "baseline_days": 29,
         "z": 15.0, "ratio": 4.0}]},
    "/api/v1/scans/trend": {"by": "category", "days": 90, "metric": "sources", "items": [
        {"day": "2026-11-12", "key": "operating_system", "value": 15000},
        {"day": "2026-11-13", "key": "operating_system", "value": 60000},
        {"day": "2026-11-13", "key": "web_cms", "value": 30000}]},
    "/api/v1/categories/summary": {"items": [
        {"category": "web_cms", "cves": 50000, "kev_cves": 300, "kev_share": 0.006,
         "recent_cves": 20000, "last_published": "2026-11-12"},
        {"category": "firewall_security_appliance", "cves": 4000, "kev_cves": 200, "kev_share": 0.05,
         "recent_cves": 1200, "last_published": "2026-11-11"}]},
    "/api/v1/categories/products": {"total": 3000, "items": [
        {"product": "acme:gizmotron", "vendor": "acme", "category": "unmapped", "assigned_by": "unmapped",
         "rule_id": "", "cve_count": 42, "kev_count": 3, "exploit_count": 2, "recent_cve_count": 10,
         "last_published": "2026-10-01"},
        {"product": "other:thing", "vendor": "other", "category": "web_cms", "assigned_by": "manual",
         "rule_id": "", "cve_count": 7, "kev_count": 0, "exploit_count": 0, "recent_cve_count": 1,
         "last_published": "2026-09-01"}]},
    "/api/v1/exploits/overview": {"cves": 9000, "providers": [
        {"provider": "metasploit", "entries": 3500, "cves": 3400, "last_seen": "2026-11-13T06:20:00Z"}]},
    "/api/v1/epss/top": {"snapshot_date": "2026-11-12", "items": [{"cve_id": "CVE-2024-0001", "epss": 0.94, "percentile": 0.999, "in_kev": True}]},
}
EMPTY = {
    "/health": {"status": "ok"},
    "/api/v1/overview": {"kev_snapshot_date": None, "epss_snapshot_date": None, "kev_total": None,
                         "kev_added_last_30_days": None, "kev_ransomware": None, "epss_total": None,
                         "epss_high": None, "kev_epss": None},
    "/api/v1/sources": {"scheduler_enabled": False, "schedule_times_utc": "", "news_interval_minutes": 60, "next_scheduled_run": None,
                        "sources": [source("kev", snapshots=0, latest_snapshot_date=None, latest_snapshot_age_days=None,
                                           latest_rows=None, last_run=None)]},
    "/api/v1/jobs": {"items": []},
    "/api/v1/kev": {"snapshot_date": None, "total": 0, "items": []},
    "/api/v1/epss/top": {"snapshot_date": None, "items": []},
    "/api/v1/nvd/overview": {"total": None, "with_cvss": None, "with_products": None,
                             "with_exploit_reference": None, "retrieved_at": None, "by_year": [], "by_severity": []},
    "/api/v1/nvd/vendors": {"items": []},
    "/api/v1/categories/coverage": {"products": 0, "products_mapped": 0, "products_manual": 0, "cves": 0,
                                    "cves_mapped": 0, "kev_cves": 0, "kev_cves_mapped": 0,
                                    "recent_cves": 0, "recent_cves_mapped": 0, "rules_version": None},
    "/api/v1/analysis/forecast": {"horizon": 90, "lookback_days": 365, "method": "recent_rate",
                                  "generated_for": None, "items": []},
    "/api/v1/analysis/backtest": {"horizon": 90, "evaluations": [], "methods": [], "observed_total": 0},
    "/api/v1/analysis/rates": {"horizons": [30, 90, 365], "items": []},
    "/api/v1/analysis/time-to-exploit": {"items": []},
    "/api/v1/scans/surges": {"baseline_days": 30, "min_z": 2.0, "surges": [], "all": []},
    "/api/v1/scans/trend": {"by": "category", "days": 90, "metric": "sources", "items": []},
    "/api/v1/categories/summary": {"items": []},
    "/api/v1/categories/products": {"total": 0, "items": []},
    "/api/v1/exploits/overview": {"cves": 0, "providers": []},
    "/api/v1/news": {"total": 0, "items": []},
    "/api/v1/news/trend": {"by": "event_type", "days": 14, "items": []},
    "/api/v1/taxonomy": TAXONOMY,
    "/api/v1/news/feeds": {"items": [
        {"id": "rss", "title": "Sec", "url": "https://x/rss", "language": "en", "kind": "specialist", "enabled": True,
         "last_fetch_at": None, "last_status": None, "last_message": None, "last_success_at": None,
         "items_seen": 0, "items_new": 0, "total_items": 0, "consecutive_failures": 0}]},
}


@pytest.mark.parametrize("responses", [FULL, EMPTY], ids=["full", "empty"])
@pytest.mark.parametrize("lang", ["en", "it"])
@pytest.mark.parametrize("page", ["overview", "forecast", "scans", "pipeline", "news", "vulns", "categories", "kev", "epss"])
def test_page_renders(monkeypatch, responses, lang, page):
    def fake(method, url, params=None, json=None, timeout=None):
        path = httpx.URL(url).path
        return httpx.Response(200, json=responses[path], request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", fake)
    st.cache_data.clear()  # the app caches reads: one case must not answer for another
    at = AppTest.from_file(APP, default_timeout=30)
    at.session_state["lang"] = lang
    at.run()
    at.sidebar.radio[0].set_value(page).run()
    assert not at.exception, at.exception
    visible = " ".join(str(e.value) for e in [*at.header, *at.subheader, *at.caption, *at.info])
    for prefix in ("nav.", "overview.", "pipeline.", "common.", "epss.", "kev.", "app.", "news.", "kind.", "vulns.", "categories.", "assigned.", "forecast.", "scans."):
        assert prefix not in visible, visible


def test_api_down_shows_a_message_instead_of_a_traceback(monkeypatch):
    def boom(*args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "request", boom)
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception and len(at.error) == 1
