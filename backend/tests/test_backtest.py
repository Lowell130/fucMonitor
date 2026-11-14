"""Scoring the forecast against what happened."""

from datetime import date, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from app import runner
from app.analysis import backtest
from app.main import app

from .test_categories import nvd_entry
from .test_nvd import payload

TODAY = date.today()


def iso(offset: int) -> str:
    return (TODAY - timedelta(days=offset)).isoformat()


@pytest.fixture
def history(settings, monkeypatch):
    """A firewall category exploited at a steady pace, and a CMS never exploited."""
    monkeypatch.setenv("FUC_NVD_DELAY_SECONDS", "0")
    from app.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    entries = []
    # one firewall CVE published every 10 days for three years; every fifth is exploited
    for index in range(110):
        published = 1100 - index * 10
        exploited = iso(published - 20) if index % 5 == 0 else None
        entries.append(nvd_entry(f"CVE-2024-1{index:03d}", ["fortinet:fortios"],
                                 published=iso(published) + "T00:00:00.000", kev=exploited))
    for index in range(40):
        entries.append(nvd_entry(f"CVE-2024-2{index:03d}", ["wordpress:wordpress"],
                                 published=iso(1000 - index * 20) + "T00:00:00.000"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=payload(entries, len(entries)))

    runner.run_source(settings, "nvd", client=httpx.Client(transport=httpx.MockTransport(handler)))
    return settings


def test_it_only_uses_what_was_known_on_the_day(history):
    """The whole point: a prediction made with hindsight is worthless."""
    out = backtest.run(history, horizon=90, step_days=60, points=6)
    assert out["evaluations"], out
    first = out["evaluations"][0]["at"]
    # No evaluation date may sit inside the last unfinished window.
    assert out["to"] <= iso(90)
    assert first < out["to"]
    assert all(e["observed"] >= 0 for e in out["evaluations"])


def test_a_steady_pace_is_predicted_well_and_an_empty_category_is_predicted_as_empty(history):
    out = backtest.run(history, horizon=90, step_days=45, points=8)
    firewall = [e for e in out["evaluations"] if e["category"] == "firewall_security_appliance"]
    cms = [e for e in out["evaluations"] if e["category"] == "web_cms"]
    assert firewall and cms

    # one exploitation every 50 days, so about 1.8 in 90 days
    predicted = [e["predictions"]["recent_rate"]["expected"] for e in firewall]
    assert 1.0 <= sum(predicted) / len(predicted) <= 2.6
    assert all(e["observed"] == 0 for e in cms)
    assert all(e["predictions"]["recent_rate"]["expected"] == 0 for e in cms)

    scores = {m["method"]: m for m in out["methods"]}
    assert set(scores) == {"recent_rate", "volume_rate"}
    assert all(0 <= s["interval_coverage"] <= 1 for s in scores.values())
    assert out["methods"][0]["mean_absolute_error"] <= out["methods"][-1]["mean_absolute_error"]


def test_the_endpoint_reports_both_methods(history):
    with TestClient(app) as api:
        out = api.get("/api/v1/analysis/backtest", params={"horizon": 90, "points": 6}).json()
        assert [m["method"] for m in out["methods"]]
        assert out["observed_total"] >= 0
        assert api.get("/api/v1/analysis/backtest", params={"horizon": 45}).status_code == 422


def test_it_says_so_when_there_is_nothing_to_score(settings):
    assert backtest.run(settings, horizon=90)["evaluations"] == []
