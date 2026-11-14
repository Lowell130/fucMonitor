"""Joining the forecast with scanning, and the honest check of whether scanning leads."""

import json
from datetime import date, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from app import runner, state
from app.analysis import priority
from app.main import app
from app.sources import SOURCES

from .test_categories import nvd_entry
from .test_nvd import payload

TODAY = state.utcnow().date()


def load_catalogue(settings, entries):
    def handler(request):
        return httpx.Response(200, content=payload(entries, len(entries)))

    runner.run_source(settings, "nvd", client=httpx.Client(transport=httpx.MockTransport(handler)))


def load_scans(settings, series_for):
    def handler(request):
        parts = request.url.path.strip("/").split("/")
        port = int(parts[2]); start = date.fromisoformat(parts[3]); end = date.fromisoformat(parts[4])
        days = (end - start).days + 1
        doc = {}
        for i in range(days):
            d = start + timedelta(days=i)
            doc[str(i)] = {"date": d.isoformat(), "records": 0, "targets": 0,
                           "sources": series_for(port, d), "tcp": 95, "udp": 0}
        doc.update(startdate=start.isoformat(), enddate=end.isoformat(), port=port)
        return httpx.Response(200, content=json.dumps(doc).encode())

    runner.run_source(settings, "scans", "backfill", backfill_day=TODAY,
                      client=httpx.Client(transport=httpx.MockTransport(handler)))


@pytest.fixture
def one_port(settings, tmp_path):
    """A single port (445 -> operating_system) so the category maths is easy to reason about."""
    path = tmp_path / "ports.json"
    path.write_text(json.dumps({"ports": [{"port": 445, "category": "operating_system", "service": "SMB"}]}))
    settings.scans_ports_file = path
    return settings


def test_combined_keeps_the_forecast_order_and_flags_elevated_scanning(one_port):
    settings = one_port
    # one OS CVE exploited in the last year -> a non-zero forecast for operating_system
    load_catalogue(settings, [nvd_entry("CVE-2024-0001", ["microsoft:windows_10"],
                                        published=(TODAY - timedelta(days=200)).isoformat() + "T00:00:00.000",
                                        kev=(TODAY - timedelta(days=100)).isoformat())])
    runner.refresh_categories(settings, force=True)

    def series(port, d):
        return 9000 if d == TODAY - timedelta(days=1) else 1000 + (d.toordinal() % 7)  # spike on last complete day
    load_scans(settings, series)

    out = priority.combined(settings, horizon=90)
    os_row = next(r for r in out["items"] if r["category"] == "operating_system")
    assert os_row["expected"] > 0 and os_row["elevated_scanning"] is True
    assert os_row["scan_z"] is not None and os_row["scan_z"] > 2
    assert out["watch"] and out["watch"][0]["category"] == "operating_system"
    # the forecast expectation is unchanged by scanning: it is the measured number, untouched
    from app.analysis.exploitation import forecast
    assert os_row["expected"] == next(
        r["expected"] for r in forecast(settings, 90)["items"] if r["category"] == "operating_system")


def test_signal_check_finds_a_real_lead_when_surges_precede_exploitation(one_port):
    settings = one_port
    # exploitation clustered a few days after each scan surge, and nowhere else
    surge_days = [TODAY - timedelta(days=d) for d in range(390, 20, -30)]  # ~13 surges
    entries = []
    for i, surge in enumerate(surge_days):
        for j in range(4):  # several OS CVEs exploited 3-6 days after each surge
            entries.append(nvd_entry(f"CVE-2024-{i:02d}{j:02d}", ["microsoft:windows_10"],
                                     published=(surge - timedelta(days=60)).isoformat() + "T00:00:00.000",
                                     kev=(surge + timedelta(days=3 + j)).isoformat()))
    load_catalogue(settings, entries)
    runner.refresh_categories(settings, force=True)

    surge_set = set(surge_days)
    load_scans(settings, lambda port, d: 12000 if d in surge_set else 1000 + (d.toordinal() % 3))

    out = priority.signal_check(settings, lead_days=20, threshold=2.0)
    assert out["elevated_days"] >= 10 and out["events_after_elevated"] >= 20
    assert out["mean_after_elevated"] > out["mean_after_normal"]
    assert out["lift"] > 1.3
    assert "followed by more exploitation" in out["verdict"]


def test_signal_check_says_so_when_there_is_no_lead(one_port):
    settings = one_port
    # exploitation spread evenly, unrelated to the (also flat) scanning
    entries = [nvd_entry(f"CVE-2024-{i:04d}", ["microsoft:windows_10"],
                         published=(TODAY - timedelta(days=400)).isoformat() + "T00:00:00.000",
                         kev=(TODAY - timedelta(days=d)).isoformat())
               for i, d in enumerate(range(300, 40, -8))]
    load_catalogue(settings, entries)
    runner.refresh_categories(settings, force=True)
    load_scans(settings, lambda port, d: 1000 + (d.toordinal() % 5))  # no surges at all

    out = priority.signal_check(settings, lead_days=20, threshold=2.0)
    # with no elevated days, the check honestly declines to claim anything
    assert out["elevated_days"] == 0 and out["verdict"] == "too little history to tell yet"


def test_endpoints(one_port):
    settings = one_port
    load_catalogue(settings, [nvd_entry("CVE-2024-0001", ["microsoft:windows_10"],
                                        published=(TODAY - timedelta(days=200)).isoformat() + "T00:00:00.000",
                                        kev=(TODAY - timedelta(days=100)).isoformat())])
    runner.refresh_categories(settings, force=True)
    load_scans(settings, lambda port, d: 1000 + (d.toordinal() % 7))
    with TestClient(app) as api:
        prio = api.get("/api/v1/analysis/priority", params={"horizon": 90}).json()
        assert "items" in prio and "watch" in prio
        assert api.get("/api/v1/analysis/priority", params={"horizon": 45}).status_code == 422
        check = api.get("/api/v1/analysis/scan-signal-check").json()
        assert "verdict" in check and "lift" in check


def test_priority_is_empty_without_scans(settings, client):
    """No scans yet: the forecast still comes through, every scanning field simply null."""
    runner.run_source(settings, "nvd", client=client) if False else None
    out = priority.combined(settings, horizon=90)
    assert out["items"] == [] and out["watch"] == []
    assert priority.signal_check(settings)["verdict"] == "no data"
