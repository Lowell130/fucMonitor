import pytest
from fastapi.testclient import TestClient

from app import runner
from app.main import app


@pytest.fixture
def api(settings):
    with TestClient(app) as test_client:
        yield test_client


def test_empty_system_answers_without_errors(api):
    assert api.get("/health").json()["status"] == "ok"
    sources = api.get("/api/v1/sources").json()
    assert [s["name"] for s in sources["sources"]] == ["kev", "epss", "nvd", "exploits", "news"]
    assert all(s["snapshots"] == 0 and s["latest_snapshot_date"] is None for s in sources["sources"])
    assert api.get("/api/v1/overview").json()["kev_total"] is None
    assert api.get("/api/v1/kev").json() == {"snapshot_date": None, "total": 0, "items": []}
    assert api.get("/api/v1/kev/timeline").json()["items"] == []
    assert api.get("/api/v1/epss/top").json()["items"] == []
    assert api.get("/api/v1/epss/CVE-2024-0001").json()["items"] == []
    assert api.get("/api/v1/jobs").json() == {"items": []}


def test_data_endpoints_after_ingestion(api, settings, client):
    runner.run_source(settings, "kev", client=client)
    runner.run_source(settings, "epss", client=client)

    kev = api.get("/api/v1/kev", params={"search": "acme", "limit": 1}).json()
    assert kev["total"] == 2 and len(kev["items"]) == 1
    assert kev["items"][0]["cve_id"] == "CVE-2024-0001"
    assert api.get("/api/v1/kev", params={"since": "2026-01-01"}).json()["total"] == 1

    months = api.get("/api/v1/kev/timeline").json()["items"]
    assert months == [
        {"month": "2022-01", "added": 1},
        {"month": "2023-05", "added": 1},
        {"month": "2026-11", "added": 1},
    ]
    assert api.get("/api/v1/kev/vendors").json()["items"][0]["vendor_project"] == "Acme"

    status = {s["name"]: s for s in api.get("/api/v1/sources").json()["sources"]}
    assert status["epss"]["latest_rows"] == 4 and status["epss"]["latest_snapshot_date"] == "2026-11-12"
    assert status["kev"]["last_run"]["status"] == "success"
    assert len(api.get("/api/v1/jobs", params={"source": "kev"}).json()["items"]) == 1


def test_validation_and_unknown_source(api):
    assert api.post("/api/v1/sources/nope/run").status_code == 404
    assert api.get("/api/v1/jobs", params={"source": "nope"}).status_code == 404
    assert api.get("/api/v1/kev", params={"limit": 0}).status_code == 422
    bad = api.post("/api/v1/sources/epss/backfill", params={"start": "2026-02-01", "end": "2026-01-01"})
    assert bad.status_code == 422


def test_taxonomy_has_stable_ids_and_both_languages(api):
    tax = api.get("/api/v1/taxonomy").json()
    for group in ("technology_categories", "event_types"):
        ids = [c["id"] for c in tax[group]]
        assert len(ids) == len(set(ids))
        assert all(c["en"] and c["it"] for c in tax[group])
    assert 12 <= len(tax["technology_categories"]) <= 15
