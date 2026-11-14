"""Scanning activity ingestion, the surge detector and the trend query."""

import json
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app import queries, runner, state
from app.main import app
from app.sources import SOURCES
from app.sources.scans import parse_history

TODAY = state.utcnow().date()


def history_doc(port: int, series: list[tuple[str, int]]) -> bytes:
    """A porthistory response: date -> sources, with the metadata keys ISC adds."""
    doc = {str(i): {"date": d, "records": src * 10, "targets": 200, "sources": src, "tcp": 95, "udp": 0}
           for i, (d, src) in enumerate(series)}
    doc.update(startdate=series[0][0], enddate=series[-1][0], port=port)
    return json.dumps(doc).encode()


@pytest.fixture
def isc(settings, tmp_path, monkeypatch):
    """A fake DShield that returns, for each port, a flat baseline with a spike on 445."""
    ports = {"ports": [
        {"port": 445, "category": "operating_system", "service": "SMB"},
        {"port": 22, "category": "remote_management", "service": "SSH"},
        {"port": 500, "category": "vpn_remote_access", "service": "IKE"},
    ]}
    path = tmp_path / "ports.json"
    path.write_text(json.dumps(ports))
    settings.scans_ports_file = path

    def series_for(port: int, start: date, end: date) -> list[tuple[str, int]]:
        days = (end - start).days + 1
        out = []
        for i in range(days):
            d = start + timedelta(days=i)
            base = {445: 1000, 22: 5000, 500: 300}[port]
            # 445 spikes on the last *complete* day (yesterday); today stays flat, as the
            # real feed's current day is still being aggregated and reads low.
            value = base * 6 if (port == 445 and d == end - timedelta(days=1)) else base + (i % 3)
            out.append((d.isoformat(), value))
        return out

    box = {"fail": set(), "requests": []}

    def handler(request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")
        port = int(parts[2]); start = date.fromisoformat(parts[3]); end = date.fromisoformat(parts[4])
        box["requests"].append(port)
        if port in box["fail"]:
            return httpx.Response(503)
        return httpx.Response(200, content=history_doc(port, series_for(port, start, end)))

    return settings, box, httpx.Client(transport=httpx.MockTransport(handler))


def test_parse_history_ignores_metadata_keys():
    doc = history_doc(445, [("2026-11-12", 10), ("2026-11-13", 20)])
    rows = parse_history(doc, 445)
    assert [r["observed_date"] for r in rows] == [date(2026, 11, 12), date(2026, 11, 13)]
    assert rows[0]["sources"] == 10 and rows[0]["records"] == 100 and rows[0]["port"] == 445


def test_ingest_writes_one_file_per_day_with_every_port(isc):
    settings, box, client = isc
    run = runner.run_source(settings, "scans", client=client)
    assert run["status"] == "success" and run["changed"] is True
    assert "3/3 ports ok" in run["message"]

    dates = SOURCES["scans"].snapshot_dates(settings)
    assert dates[-1] == TODAY and len(dates) == settings.scans_lookback_days + 1
    latest = queries._rows("SELECT port FROM read_parquet(?) ORDER BY port",
                           [SOURCES["scans"].curated_path(settings, TODAY).as_posix()])
    assert [r["port"] for r in latest] == [22, 445, 500]


def test_a_steady_day_is_not_rewritten(isc):
    settings, box, client = isc
    runner.run_source(settings, "scans", client=client)
    box["requests"].clear()
    again = runner.run_source(settings, "scans", client=client)
    assert again["status"] == "success" and again["changed"] is False
    assert again["message"].startswith("0 days written")  # nothing changed, nothing rewritten


def test_one_port_failing_does_not_stop_the_others_but_all_failing_does(isc):
    settings, box, client = isc
    box["fail"] = {22}
    run = runner.run_source(settings, "scans", client=client)
    assert run["status"] == "success" and "2/3 ports ok" in run["message"] and "22" in run["message"]

    box["fail"] = {22, 445, 500}
    dead = runner.run_source(settings, "scans", client=client)
    assert dead["status"] == "failed" and "every port failed" in dead["message"]


def test_the_surge_detector_finds_the_spike_and_names_its_category(isc):
    settings, box, client = isc
    runner.run_source(settings, "scans", client=client)
    out = queries.scans_surges(settings, baseline_days=9, min_z=2.0)
    assert out["surges"], out
    top = out["surges"][0]
    assert top["port"] == 445 and top["category"] == "operating_system"
    assert top["z"] > 2 and top["ratio"] > 3
    # the flat ports are in 'all' but not flagged as surges
    assert {r["port"] for r in out["all"]} == {22, 445, 500}
    assert all(r["port"] != 445 for r in out["surges"][1:])


def test_trend_groups_by_category_and_endpoints_answer(isc):
    settings, box, client = isc
    with TestClient(app) as api:
        assert api.get("/api/v1/scans/trend").json()["items"] == []
        runner.run_source(settings, "scans", client=client)

        trend = api.get("/api/v1/scans/trend", params={"by": "category", "days": 30}).json()
        cats = {i["key"] for i in trend["items"]}
        assert cats == {"operating_system", "remote_management", "vpn_remote_access"}
        assert trend["metric"] == "sources"

        surges = api.get("/api/v1/scans/surges").json()["surges"]
        assert surges and surges[0]["port"] == 445
        assert len(api.get("/api/v1/scans/ports").json()["items"]) == 3
        assert api.get("/api/v1/scans/trend", params={"metric": "nope"}).status_code == 422
        names = [s["name"] for s in api.get("/api/v1/sources").json()["sources"]]
        assert names == ["kev", "epss", "nvd", "exploits", "news", "scans"]


def test_a_late_correction_rewrites_only_that_day(isc):
    settings, box, client = isc
    runner.run_source(settings, "scans", client=client)
    stored = SOURCES["scans"].curated_path(settings, TODAY)
    before = stored.stat().st_mtime

    # DShield revises today's 445 number upward; the handler already returns the spike,
    # so bump it again to force a change on exactly one day.
    def revised(request):
        parts = request.url.path.strip("/").split("/")
        port = int(parts[2]); start = date.fromisoformat(parts[3]); end = date.fromisoformat(parts[4])
        days = (end - start).days + 1
        def val(port, i):
            if port == 445 and i == days - 1:
                return 99999  # today revised upward
            if port == 445 and i == days - 2:
                return 1000 * 6  # the same yesterday spike the first run wrote
            return {445: 1000, 22: 5000, 500: 300}[port] + (i % 3)
        series = [((start + timedelta(days=i)).isoformat(), val(port, i)) for i in range(days)]
        return httpx.Response(200, content=history_doc(port, series))

    run = runner.run_source(settings, "scans",
                            client=httpx.Client(transport=httpx.MockTransport(revised)))
    assert run["message"].startswith("1 days written")  # only today changed
    value = queries._rows("SELECT sources FROM read_parquet(?) WHERE port = 445",
                          [stored.as_posix()])[0]["sources"]
    assert value == 99999
