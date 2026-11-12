import gzip
import json

import httpx
import pytest

from app.config import Settings, get_settings

KEV_DOC = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.12",
    "dateReleased": "2026-11-12T10:00:00.000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Acme",
            "product": "Edge Gateway",
            "vulnerabilityName": "Acme Edge Gateway Command Injection",
            "dateAdded": "2026-11-10",
            "shortDescription": "Command injection.",
            "requiredAction": "Apply mitigations.",
            "dueDate": "2026-12-01",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-78"],
        },
        {
            "cveID": "CVE-2023-0002",
            "vendorProject": "Acme",
            "product": "Mail Server",
            "vulnerabilityName": "Acme Mail Server RCE",
            "dateAdded": "2023-05-02",
            "shortDescription": "Remote code execution.",
            "requiredAction": "Apply updates.",
            "dueDate": "2023-05-23",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": [],
        },
        {
            "cveID": "CVE-2022-0003",
            "vendorProject": "Globex",
            "product": "CMS",
            "vulnerabilityName": "Globex CMS Auth Bypass",
            "dateAdded": "2022-01-15",
            "shortDescription": "Authentication bypass.",
            "requiredAction": "Apply updates.",
            "dueDate": "2022-02-05",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
    ],
}


def epss_file(score_date: str = "2026-11-12", header: bool = True) -> bytes:
    lines = []
    if header:
        lines.append(f"#model_version:v2025.03.14,score_date:{score_date}T00:00:00+0000")
    lines += [
        "cve,epss,percentile",
        "CVE-2024-0001,0.94321,0.99900",
        "CVE-2023-0002,0.00450,0.61000",
        "CVE-2021-9999,0.25000,0.96000",
        "CVE-2020-1111,0.00010,0.01000",
    ]
    return gzip.compress(("\n".join(lines) + "\n").encode())


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Settings:
    monkeypatch.setenv("FUC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FUC_SCHEDULER_ENABLED", "false")
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


@pytest.fixture
def feeds():
    """Mutable fake upstream: change the bytes or status between calls."""
    return {"kev": json.dumps(KEV_DOC).encode(), "epss": epss_file(), "status": 200}


@pytest.fixture
def client(feeds) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if feeds["status"] != 200:
            return httpx.Response(feeds["status"])
        if "known_exploited" in request.url.path:
            return httpx.Response(200, content=feeds["kev"])
        return httpx.Response(200, content=feeds["epss"])

    return httpx.Client(transport=httpx.MockTransport(handler))
