"""CISA Known Exploited Vulnerabilities catalog.

One exploitation label among several: KEV reflects what CISA can confirm and cares
about, not everything exploited in the world. Keep it separate from other labels.

The catalog is a full list that changes in place, so we keep one snapshot per day
(retrieval date, UTC). `date_added` is when CISA listed the CVE, which is often later
than the first real exploitation.
"""

import json
import os
from datetime import date

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

from ..config import Settings
from ..state import utcnow
from .base import IngestResult, Source, download, promote, sha256

SCHEMA = pa.schema(
    [
        ("cve_id", pa.string()),
        ("vendor_project", pa.string()),
        ("product", pa.string()),
        ("vulnerability_name", pa.string()),
        ("date_added", pa.date32()),
        ("due_date", pa.date32()),
        ("known_ransomware_campaign_use", pa.string()),
        ("cwes", pa.list_(pa.string())),
        ("short_description", pa.string()),
        ("required_action", pa.string()),
        ("notes", pa.string()),
        ("catalog_version", pa.string()),
        ("retrieved_at", pa.timestamp("s", tz="UTC")),
    ]
)


def _date(value) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def parse(content: bytes, retrieved_at) -> pa.Table:
    doc = json.loads(content)
    version = doc.get("catalogVersion")
    rows = []
    for v in doc.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        rows.append(
            {
                "cve_id": cve,
                "vendor_project": v.get("vendorProject"),
                "product": v.get("product"),
                "vulnerability_name": v.get("vulnerabilityName"),
                "date_added": _date(v.get("dateAdded")),
                "due_date": _date(v.get("dueDate")),
                "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse"),
                "cwes": [str(c) for c in (v.get("cwes") or [])],
                "short_description": v.get("shortDescription"),
                "required_action": v.get("requiredAction"),
                "notes": v.get("notes"),
                "catalog_version": version,
                "retrieved_at": retrieved_at.replace(microsecond=0),
            }
        )
    return pa.Table.from_pylist(rows, schema=SCHEMA)


class KevSource(Source):
    name = "kev"
    title = "CISA Known Exploited Vulnerabilities"
    homepage = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    raw_filename = "known_exploited_vulnerabilities.json"

    def ingest(self, settings: Settings, client: httpx.Client, progress=None) -> IngestResult:
        content = download(client, settings.kev_url)
        retrieved_at = utcnow()
        snapshot = retrieved_at.date()
        digest = sha256(content)

        table = parse(content, retrieved_at)
        if table.num_rows == 0:
            raise ValueError("KEV feed parsed to zero rows; refusing to store an empty snapshot")

        if self.stored_sha256(settings, snapshot) == digest:
            return IngestResult(snapshot, table.num_rows, len(content), digest, False, "unchanged")

        self.write_raw(settings, snapshot, content, settings.kev_url, retrieved_at)
        target = self.curated_path(settings, snapshot)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name("data.parquet.tmp")
        pq.write_table(table, tmp, compression="zstd")
        promote(tmp, target)
        return IngestResult(snapshot, table.num_rows, len(content), digest, True, "stored")
