import json
from datetime import date

import duckdb

from app import queries, runner, state
from app.sources import SOURCES

from .conftest import KEV_DOC, epss_file


def test_kev_ingest_stores_raw_and_curated(settings, client):
    run = runner.run_source(settings, "kev", client=client)
    assert run["status"] == "success" and run["rows"] == 3 and run["changed"] is True

    snap = date.fromisoformat(run["snapshot_date"])
    source = SOURCES["kev"]
    assert json.loads(source.raw_path(settings, snap).read_bytes()) == KEV_DOC
    meta = json.loads(source.raw_path(settings, snap).with_name("meta.json").read_text())
    assert meta["sha256"] == run["sha256"] and meta["retrieved_at"].endswith("Z")

    rows = duckdb.connect().execute(
        "SELECT cve_id, date_added, cwes FROM read_parquet(?) ORDER BY cve_id",
        [str(source.curated_path(settings, snap))],
    ).fetchall()
    assert rows[0] == ("CVE-2022-0003", date(2022, 1, 15), [])  # missing 'cwes' key tolerated
    assert rows[2] == ("CVE-2024-0001", date(2026, 11, 10), ["CWE-78"])


def test_same_content_twice_is_unchanged_and_new_content_replaces(settings, client, feeds):
    runner.run_source(settings, "kev", client=client)
    again = runner.run_source(settings, "kev", client=client)
    assert again["status"] == "success" and again["changed"] is False

    doc = json.loads(feeds["kev"])
    doc["vulnerabilities"] = doc["vulnerabilities"][:2]
    feeds["kev"] = json.dumps(doc).encode()
    third = runner.run_source(settings, "kev", client=client)
    assert third["changed"] is True and third["rows"] == 2
    assert len(SOURCES["kev"].snapshot_dates(settings)) == 1  # same day: one snapshot


def test_epss_snapshot_date_comes_from_the_file(settings, client):
    run = runner.run_source(settings, "epss", client=client)
    assert run["status"] == "success" and run["rows"] == 4
    assert run["snapshot_date"] == "2026-11-12"
    row = duckdb.connect().execute(
        "SELECT epss, percentile, model_version, score_date, backfilled FROM read_parquet(?) "
        "WHERE cve_id = 'CVE-2024-0001'",
        [str(SOURCES["epss"].curated_path(settings, date(2026, 11, 12)))],
    ).fetchone()
    assert row == (0.94321, 0.999, "v2025.03.14", date(2026, 11, 12), False)


def test_epss_backfill_keeps_one_snapshot_per_day(settings, client, feeds):
    runner.run_source(settings, "epss", client=client)
    feeds["epss"] = epss_file("2026-11-11")
    run = runner.run_source(settings, "epss", "backfill", backfill_day=date(2026, 11, 11), client=client)
    assert run["status"] == "success" and run["snapshot_date"] == "2026-11-11"
    assert SOURCES["epss"].snapshot_dates(settings) == [date(2026, 11, 11), date(2026, 11, 12)]
    history = queries.epss_history(settings, "cve-2024-0001")
    assert [i["score_date"] for i in history["items"]] == [date(2026, 11, 11), date(2026, 11, 12)]


def test_epss_v1_file_without_comment_line(settings, client, feeds):
    feeds["epss"] = epss_file(header=False)
    run = runner.run_source(settings, "epss", "backfill", backfill_day=date(2021, 5, 1), client=client)
    assert run["status"] == "success" and run["rows"] == 4 and run["snapshot_date"] == "2021-05-01"


def test_failures_are_recorded_and_store_nothing(settings, client, feeds):
    feeds["status"] = 503
    run = runner.run_source(settings, "kev", client=client)
    assert run["status"] == "failed" and "503" in run["message"]
    assert SOURCES["kev"].snapshot_dates(settings) == []

    feeds["status"] = 200
    feeds["kev"] = b'{"vulnerabilities": []}'
    assert runner.run_source(settings, "kev", client=client)["status"] == "failed"
    feeds["epss"] = b"not gzip"
    assert runner.run_source(settings, "epss", client=client)["status"] == "failed"
    assert SOURCES["epss"].snapshot_dates(settings) == []
    assert not list(settings.curated_dir.rglob("*.tmp"))
    assert len(state.list_runs(settings.state_db)) == 3


def test_overview_joins_kev_and_epss(settings, client):
    runner.run_source(settings, "kev", client=client)
    runner.run_source(settings, "epss", client=client)
    out = queries.overview(settings)
    assert out["kev_total"] == 3 and out["kev_ransomware"] == 1
    assert out["epss_total"] == 4 and out["epss_high"] == 2
    assert out["kev_epss"]["kev_cves"] == 3 and out["kev_epss"]["with_epss"] == 2
    top = queries.epss_top(settings, 2)["items"]
    assert [(i["cve_id"], i["in_kev"]) for i in top] == [("CVE-2024-0001", True), ("CVE-2021-9999", False)]


def test_backfill_asks_for_one_file_per_step(settings, monkeypatch):
    """A weekly step over years must not blow past the per-request limit."""
    from fastapi.testclient import TestClient

    from app import main

    asked: list[list] = []
    # The endpoint hands the work to a background task; let it record instead of download.
    monkeypatch.setattr(main, "_backfill", asked.append)

    with TestClient(main.app) as api:
        weekly = api.post(
            "/api/v1/sources/epss/backfill", params={"start": "2021-04-14", "end": "2026-11-01", "step": 7}
        )
        assert weekly.status_code == 202
        assert weekly.json() == {"accepted": True, "days_requested": 290, "days_to_download": 290, "step": 7}
        assert len(asked[0]) == 290
        assert (asked[0][1] - asked[0][0]).days == 7 and asked[0][0].isoformat() == "2021-04-14"

        daily = api.post("/api/v1/sources/epss/backfill", params={"start": "2021-04-14", "end": "2026-11-01"})
        assert daily.status_code == 422 and "500" in daily.json()["detail"]

        backwards = api.post("/api/v1/sources/epss/backfill", params={"start": "2026-02-01", "end": "2026-01-01"})
        assert backwards.status_code == 422
