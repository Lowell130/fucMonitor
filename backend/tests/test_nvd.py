import json
from datetime import date, datetime, timezone

import duckdb
import httpx
import pytest
from fastapi.testclient import TestClient

from app import queries, runner, state
from app.main import app
from app.sources import SOURCES
from app.sources.nvd import WATERMARK, parse_record


def record(cve_id: str, **over) -> dict:
    base = {
        "id": cve_id,
        "sourceIdentifier": "cve@mitre.org",
        "published": "2026-11-01T10:00:00.000",
        "lastModified": "2026-11-11T12:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "es", "value": "Una vulnerabilidad"}, {"lang": "en", "value": "A flaw."}],
        "metrics": {
            "cvssMetricV31": [
                {"source": "nvd@nist.gov", "type": "Primary",
                 "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L", "attackVector": "NETWORK",
                              "baseScore": 9.8, "baseSeverity": "CRITICAL"}}
            ],
            "cvssMetricV2": [
                {"type": "Primary", "baseSeverity": "HIGH",
                 "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L", "accessVector": "NETWORK", "baseScore": 7.5}}
            ],
        },
        "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": "CWE-78"},
                                                           {"lang": "en", "value": "NVD-CWE-noinfo"}]}],
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:edge_gateway:1.0:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:edge_gateway:1.1:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:other:os:*:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"},
        ]}]}],
        "references": [{"url": "https://e.org/a", "tags": ["Exploit", "Third Party Advisory"]},
                       {"url": "https://e.org/b", "tags": ["Patch"]}],
        "cisaExploitAdd": "2026-11-10",
    }
    base.update(over)
    return {"cve": base}


def payload(records: list[dict], total: int, start: int = 0) -> bytes:
    return json.dumps(
        {"resultsPerPage": len(records), "startIndex": start, "totalResults": total, "vulnerabilities": records}
    ).encode()


@pytest.fixture
def nvd(settings, monkeypatch):
    """Fake NVD: `pages` is the queue of replies, `calls` records the query parameters."""
    monkeypatch.setenv("FUC_NVD_DELAY_SECONDS", "0")
    monkeypatch.setenv("FUC_NVD_PAGE_SIZE", "2")
    from app.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    box = {"pages": [], "calls": [], "status": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        box["calls"].append(dict(request.url.params))
        if box["status"] != 200:
            status, box["status"] = box["status"], 200  # fail once, then recover
            return httpx.Response(status)
        return httpx.Response(200, content=box["pages"].pop(0))

    return settings, box, httpx.Client(transport=httpx.MockTransport(handler))


def test_parse_record_takes_the_newest_metric_and_affected_products():
    row = parse_record(record("CVE-2026-0001"), datetime(2026, 11, 12, tzinfo=timezone.utc))
    assert row["cve_id"] == "CVE-2026-0001"
    assert row["published"] == datetime(2026, 11, 1, 10, tzinfo=timezone.utc)
    assert (row["cvss_version"], row["cvss_score"], row["cvss_severity"]) == ("3.1", 9.8, "CRITICAL")
    assert row["attack_vector"] == "NETWORK" and row["description"] == "A flaw."
    assert row["cwes"] == ["CWE-78"]  # NVD-CWE-noinfo is not a weakness
    assert row["vendors"] == ["acme"] and row["products"] == ["acme:edge_gateway"]
    assert row["cpe_count"] == 3  # wildcard products are counted but not named
    assert row["reference_tags"] == ["Exploit", "Patch", "Third Party Advisory"]
    assert row["has_exploit_reference"] is True
    assert row["cisa_exploit_add"] == date(2026, 11, 10)


def test_parse_record_survives_missing_fields():
    row = parse_record({"cve": {"id": "cve-2026-0002"}}, datetime(2026, 11, 12, tzinfo=timezone.utc))
    assert row["cve_id"] == "CVE-2026-0002" and row["published"] is None
    assert row["cvss_score"] is None and row["vendors"] == [] and row["has_exploit_reference"] is False
    assert parse_record({"cve": {}}, datetime.now(timezone.utc)) is None


def test_v2_only_record_keeps_its_severity():
    only_v2 = record("CVE-2026-0003")
    only_v2["cve"]["metrics"].pop("cvssMetricV31")
    row = parse_record(only_v2, datetime(2026, 11, 12, tzinfo=timezone.utc))
    assert (row["cvss_version"], row["cvss_score"], row["cvss_severity"]) == ("2.0", 7.5, "HIGH")


def test_first_run_downloads_everything_then_only_changes(nvd):
    settings, box, client = nvd
    box["pages"] = [payload([record("CVE-2026-0001"), record("CVE-2026-0002")], 3),
                    payload([record("CVE-2026-0003")], 3, start=2)]
    first = runner.run_source(settings, "nvd", client=client)
    assert first["status"] == "success" and first["rows"] == 3 and "full" in first["message"]
    assert "lastModStartDate" not in box["calls"][0] and box["calls"][1]["startIndex"] == "2"
    assert state.get_value(settings.state_db, WATERMARK)

    box["calls"].clear()
    box["pages"] = [payload([record("CVE-2026-0002", vulnStatus="Modified")], 1)]
    second = runner.run_source(settings, "nvd", client=client)
    assert second["status"] == "success" and second["rows"] == 1 and "update" in second["message"]
    assert "lastModStartDate" in box["calls"][0] and "lastModEndDate" in box["calls"][0]

    # Both runs land in today's partition as separate part files; the newest row wins.
    files = SOURCES["nvd"].curated_files(settings)
    assert len(files) == 2
    rows = duckdb.connect().execute(
        f"SELECT cve_id, vuln_status FROM ({queries.nvd_latest()}) ORDER BY cve_id", [files]
    ).fetchall()
    assert rows == [("CVE-2026-0001", "Analyzed"), ("CVE-2026-0002", "Modified"), ("CVE-2026-0003", "Analyzed")]


def test_rate_limit_is_retried_and_a_dead_api_fails_the_run(nvd):
    settings, box, client = nvd
    box["status"] = 403  # NVD answers 403 when the rate limit is hit
    box["pages"] = [payload([record("CVE-2026-0001")], 1)]
    assert runner.run_source(settings, "nvd", client=client)["status"] == "success"

    from app.config import get_settings

    get_settings.cache_clear()
    settings.nvd_max_retries = 0
    box["status"] = 503
    box["pages"] = [payload([], 0)]
    failed = runner.run_source(settings, "nvd", client=client)
    assert failed["status"] == "failed" and "503" in failed["message"]


def test_api_serves_the_catalogue_and_a_merged_cve_profile(nvd, client):
    settings, box, nvd_client = nvd
    box["pages"] = [payload([record("CVE-2026-0001"),
                             record("CVE-2026-0002", published="2024-02-01T00:00:00.000",
                                    metrics={}, configurations=[], references=[], cisaExploitAdd=None)], 2)]
    with TestClient(app) as api:
        assert api.get("/api/v1/nvd/overview").json()["total"] is None
        runner.run_source(settings, "nvd", client=nvd_client)

        overview = api.get("/api/v1/nvd/overview").json()
        assert overview["total"] == 2 and overview["with_cvss"] == 1 and overview["with_products"] == 1
        assert overview["by_year"] == [{"year": 2024, "cves": 1}, {"year": 2026, "cves": 1}]
        assert overview["by_severity"] == [{"severity": "CRITICAL", "cves": 1}]
        assert api.get("/api/v1/nvd/vendors").json()["items"] == [
            {"vendor": "acme", "cves": 1, "products": 1}]

        profile = api.get("/api/v1/cve/cve-2026-0001").json()
        assert profile["cve_id"] == "CVE-2026-0001"
        assert profile["nvd"]["cvss_score"] == 9.8 and profile["nvd"]["products"] == ["acme:edge_gateway"]
        assert profile["kev"] is None and profile["epss"] is None and profile["exploits"] == []
        assert api.get("/api/v1/cve/CVE-1999-9999").json()["nvd"] is None
        assert api.get("/api/v1/cve/not-a-cve").status_code == 422


def test_a_slow_api_makes_it_ask_for_smaller_pages(nvd, monkeypatch):
    """NVD times out on big pages when busy: halve the page instead of losing the download."""
    settings, box, client = nvd
    settings.nvd_page_size = 1000
    settings.nvd_max_retries = 0
    box["pages"] = [payload([record("CVE-2026-0001")], 1)]

    def handler(request: httpx.Request) -> httpx.Response:
        box["calls"].append(dict(request.url.params))
        if request.url.params["resultsPerPage"] == "1000":
            return httpx.Response(524)  # gateway timeout, as seen in the real run
        return httpx.Response(200, content=box["pages"].pop(0))

    run = runner.run_source(settings, "nvd", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert run["status"] == "success" and run["rows"] == 1
    assert [c["resultsPerPage"] for c in box["calls"]] == ["1000", "500"]


def test_an_interrupted_full_download_carries_on_from_where_it_stopped(nvd, monkeypatch):
    """The resume point must never run ahead of what is readable on disk."""
    from app.sources import nvd as nvd_source

    monkeypatch.setattr(nvd_source, "ROLL_EVERY", 2)
    settings, box, client = nvd  # two records per page
    settings.nvd_max_retries = 0
    box["pages"] = [payload([record("CVE-2026-0001"), record("CVE-2026-0002")], 6)]

    def failing(request: httpx.Request) -> httpx.Response:
        box["calls"].append(dict(request.url.params))
        if box["pages"]:
            return httpx.Response(200, content=box["pages"].pop(0))
        return httpx.Response(503)

    first = runner.run_source(settings, "nvd", client=httpx.Client(transport=httpx.MockTransport(failing)))
    assert first["status"] == "failed"
    assert state.get_value(settings.state_db, WATERMARK) is None

    resume = int(state.get_value(settings.state_db, "nvd.resume_index"))
    stored = duckdb.connect().execute(
        "SELECT count(*) FROM read_parquet(?)", [SOURCES["nvd"].curated_files(settings)]
    ).fetchone()[0]
    assert resume == 2 and stored >= resume  # what it promises is really there
    assert not list((settings.curated_dir / "nvd").glob("**/*.tmp"))

    box["calls"].clear()
    box["pages"] = [payload([record("CVE-2026-0003"), record("CVE-2026-0004")], 6, start=2),
                    payload([record("CVE-2026-0005"), record("CVE-2026-0006")], 6, start=4)]
    second = runner.run_source(settings, "nvd", client=client)
    assert second["status"] == "success" and "full" in second["message"]
    assert box["calls"][0]["startIndex"] == "2"  # the first two records are not asked for again
    assert state.get_value(settings.state_db, "nvd.resume_index") == "0"

    rows = duckdb.connect().execute(
        f"SELECT count(*) FROM ({queries.nvd_latest()})", [SOURCES["nvd"].curated_files(settings)]
    ).fetchone()[0]
    assert rows == 6


def test_a_part_file_left_by_a_killed_process_is_cleared(nvd):
    settings, box, client = nvd
    folder = settings.curated_dir / "nvd" / "snapshot_date=2026-11-13"
    folder.mkdir(parents=True)
    (folder / "part-dead.parquet.tmp").write_bytes(b"not a parquet file")
    box["pages"] = [payload([record("CVE-2026-0001")], 1)]
    run = runner.run_source(settings, "nvd", client=client)
    assert run["status"] == "success"
    assert not list((settings.curated_dir / "nvd").glob("**/*.tmp"))


def test_a_resume_point_beyond_the_stored_records_is_not_trusted(nvd, monkeypatch):
    """Records 0..N must never be skipped because a counter says they were fetched."""
    from app.sources import nvd as nvd_source

    monkeypatch.setattr(nvd_source, "ROLL_EVERY", 2)
    settings, box, client = nvd
    box["pages"] = [payload([record("CVE-2026-0001"), record("CVE-2026-0002")], 2)]
    runner.run_source(settings, "nvd", client=client)  # stores 2 records

    # Something moved the counter ahead of the data (a lost part file, a manual edit).
    state.set_value(settings.state_db, "nvd.resume_index", "20000")
    state.set_value(settings.state_db, WATERMARK, "")
    box["pages"] = [payload([record("CVE-2026-0001"), record("CVE-2026-0002")], 2)]
    box["calls"].clear()
    run = runner.run_source(settings, "nvd", client=client)
    assert run["status"] == "success"
    assert box["calls"][0]["startIndex"] == "0"  # back to the beginning, no silent gap


def test_an_unfinished_download_is_picked_up_again_at_startup(nvd, monkeypatch):
    from app.sources import nvd as nvd_source

    monkeypatch.setattr(nvd_source, "ROLL_EVERY", 2)
    settings, box, client = nvd
    source = SOURCES["nvd"]
    assert source.needs_run(settings) is True

    box["pages"] = [payload([record("CVE-2026-0001"), record("CVE-2026-0002")], 6)]

    def failing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=box["pages"].pop(0)) if box["pages"] else httpx.Response(503)

    settings.nvd_max_retries = 0
    runner.run_source(settings, "nvd", client=httpx.Client(transport=httpx.MockTransport(failing)))
    # Today has a partition, but the catalogue is only part way down: still due.
    assert source.snapshot_dates(settings) == [state.utcnow().date()]
    assert source.needs_run(settings) is True

    # Even with the resume marker cleared, an unfinished catalogue is still due:
    # only a download that ran to the end sets the watermark.
    marker = state.get_value(settings.state_db, "nvd.resume_index")
    state.set_value(settings.state_db, "nvd.resume_index", "0")
    assert source.needs_run(settings) is True
    state.set_value(settings.state_db, "nvd.resume_index", marker)

    box["pages"] = [payload([record("CVE-2026-0003"), record("CVE-2026-0004")], 6, start=2),
                    payload([record("CVE-2026-0005"), record("CVE-2026-0006")], 6, start=4)]
    assert runner.run_source(settings, "nvd", client=client)["status"] == "success"
    assert source.needs_run(settings) is False
