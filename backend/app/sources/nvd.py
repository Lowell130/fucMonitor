"""NVD CVE records: publication date, severity, weakness and affected products (CPE).

This is the backbone for mapping vulnerabilities to technology categories. KEV and EPSS
say *which* CVEs matter; NVD says *what* they are and *what they affect*.

Storage is append-only, one partition per retrieval day:

    curated/nvd/snapshot_date=<day>/part-<time>.parquet

The first run downloads the whole catalogue; later runs ask NVD only for the records
changed since the last run (the watermark in the `kv` table). So a partition holds the
records as they were *that day*, and the current state of a CVE is its most recent row.
Reading "as of" a past date means ignoring later partitions, which keeps features
point-in-time correct for the days this system has been running.

NVD rewrites records over time (severity and CPE lists are often filled in weeks later),
so a record retrieved today describes the CVE as NVD sees it today, not at publication.
This matters when training: use the row that was current on the day being modelled.

Rate limits (https://nvd.nist.gov/developers/start-here): 5 requests per 30 seconds
without an API key, 50 with one. A free key makes the first full download much faster.
"""

import json
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

from .. import state
from ..config import Settings
from .base import IngestResult, Source

WATERMARK = "nvd.last_modified_watermark"
MAX_WINDOW = timedelta(days=110)  # NVD refuses a lastModified range wider than 120 days
OVERLAP = timedelta(minutes=10)  # re-ask a little before the watermark, in case of clock skew
RESUME = "nvd.resume_index"
MIN_PAGE_SIZE = 250
CVSS_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

SCHEMA = pa.schema(
    [
        ("cve_id", pa.string()),
        ("published", pa.timestamp("s", tz="UTC")),
        ("last_modified", pa.timestamp("s", tz="UTC")),
        ("vuln_status", pa.string()),
        ("description", pa.string()),
        ("cvss_version", pa.string()),
        ("cvss_score", pa.float64()),
        ("cvss_severity", pa.string()),
        ("attack_vector", pa.string()),
        ("cvss_vector", pa.string()),
        ("cwes", pa.list_(pa.string())),
        ("vendors", pa.list_(pa.string())),
        ("products", pa.list_(pa.string())),
        ("cpe_count", pa.int32()),
        ("reference_tags", pa.list_(pa.string())),
        ("has_exploit_reference", pa.bool_()),
        ("cisa_exploit_add", pa.date32()),
        ("source_identifier", pa.string()),
        # microseconds, not seconds: the most recent row of a CVE wins, and two runs can
        # fall in the same second.
        ("retrieved_at", pa.timestamp("us", tz="UTC")),
    ]
)

_CWE = re.compile(r"CWE-\d+")


def _timestamp(value: str | None) -> datetime | None:
    """NVD timestamps look like 2026-11-12T08:00:00.000 and are UTC without a zone."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _api_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _metric(metrics: dict) -> dict:
    """Best available CVSS score: newest version, preferring the primary source."""
    for key in CVSS_ORDER:
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData") or {}
        return {
            "cvss_version": data.get("version"),
            "cvss_score": data.get("baseScore"),
            # CVSS v2 carries the severity next to the data instead of inside it.
            "cvss_severity": (data.get("baseSeverity") or chosen.get("baseSeverity") or "").upper() or None,
            "attack_vector": (data.get("attackVector") or data.get("accessVector") or "").upper() or None,
            "cvss_vector": data.get("vectorString"),
        }
    return {k: None for k in ("cvss_version", "cvss_score", "cvss_severity", "attack_vector", "cvss_vector")}


def _products(configurations: list) -> tuple[list[str], list[str], int]:
    """Vendors and products of the affected CPEs, as vendor:product pairs."""
    vendors: dict[str, None] = {}
    products: dict[str, None] = {}
    count = 0
    for configuration in configurations or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = (match.get("criteria") or "").split(":")
                if len(parts) < 5 or parts[1] != "2.3":
                    continue
                count += 1
                vendor, product = parts[3], parts[4]
                if vendor in ("*", "-") or product in ("*", "-"):
                    continue  # counted, but there is no name to record
                vendors[vendor] = None
                products[f"{vendor}:{product}"] = None
    return sorted(vendors), sorted(products), count


def parse_record(entry: dict, retrieved_at: datetime) -> dict | None:
    cve = entry.get("cve") or {}
    cve_id = (cve.get("id") or "").strip().upper()
    if not cve_id:
        return None
    english = next(
        (d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), ""
    )
    cwes = sorted(
        {
            code
            for weakness in cve.get("weaknesses") or []
            for item in weakness.get("description") or []
            for code in _CWE.findall(item.get("value") or "")
        }
    )
    tags = sorted({tag for ref in cve.get("references") or [] for tag in ref.get("tags") or []})
    vendors, products, cpe_count = _products(cve.get("configurations"))
    added = cve.get("cisaExploitAdd")
    return {
        "cve_id": cve_id,
        "published": _timestamp(cve.get("published")),
        "last_modified": _timestamp(cve.get("lastModified")),
        "vuln_status": cve.get("vulnStatus"),
        "description": (english or "")[:1000],
        **_metric(cve.get("metrics") or {}),
        "cwes": cwes,
        "vendors": vendors,
        "products": products,
        "cpe_count": cpe_count,
        "reference_tags": tags,
        "has_exploit_reference": "Exploit" in tags,
        "cisa_exploit_add": date.fromisoformat(added[:10]) if added else None,
        "source_identifier": cve.get("sourceIdentifier"),
        "retrieved_at": retrieved_at,
    }


class NvdSource(Source):
    name = "nvd"
    title = "NVD CVE records (NIST)"
    homepage = "https://nvd.nist.gov/developers/vulnerabilities"

    def ingest(self, settings: Settings, client: httpx.Client, progress=None) -> IngestResult:
        report = progress or (lambda _message: None)
        watermark = state.get_value(settings.state_db, WATERMARK)
        started = state.utcnow()
        if watermark and self.snapshot_dates(settings):
            windows = self._windows(_timestamp(watermark) - OVERLAP, started)
            mode, resume_from = "update", 0
        else:
            windows = [None]  # the whole catalogue
            # A full download takes many minutes and NVD does go down mid-way, so it
            # records how far it got and carries on from there next time.
            mode = "full"
            resume_from = int(state.get_value(settings.state_db, RESUME) or 0)

        retrieved_at = started
        writer = _PartWriter(self, settings, retrieved_at)
        total = 0
        try:
            for index, window in enumerate(windows, start=1):
                label = "" if window is None else f" ({index}/{len(windows)})"
                total += self._download(
                    settings, client, window, writer, retrieved_at, report, label, resume_from
                )
                resume_from = 0
        finally:
            written = writer.close()

        state.set_value(settings.state_db, WATERMARK, state.iso(started))
        state.set_value(settings.state_db, RESUME, "0")
        message = f"{total} records ({mode})"
        if mode == "full":
            message += "; first full download"
        return IngestResult(retrieved_at.date(), written, 0, "", written > 0, message)

    # --- downloading -------------------------------------------------------
    def _windows(self, start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
        windows = []
        while start < end:
            stop = min(start + MAX_WINDOW, end)
            windows.append((start, stop))
            start = stop
        return windows or [(end - timedelta(minutes=1), end)]

    def _download(
        self,
        settings: Settings,
        client: httpx.Client,
        window: tuple[datetime, datetime] | None,
        writer: "_PartWriter",
        retrieved_at: datetime,
        report,
        label: str,
        resume_from: int = 0,
    ) -> int:
        page_size = settings.nvd_page_size
        start_index, total_results, seen = resume_from, None, 0
        while True:
            params = {"resultsPerPage": page_size, "startIndex": start_index}
            if window is not None:
                params["lastModStartDate"] = _api_time(window[0])
                params["lastModEndDate"] = _api_time(window[1])
            try:
                payload = self._get(settings, client, params)
            except RuntimeError:
                # NVD times out on large pages when it is busy. Ask for less and carry on
                # from the same place rather than losing the whole download.
                if page_size <= MIN_PAGE_SIZE:
                    raise
                page_size = max(MIN_PAGE_SIZE, page_size // 2)
                report(f"NVD is slow; asking for {page_size} records at a time{label}")
                continue
            total_results = payload.get("totalResults", 0)
            entries = payload.get("vulnerabilities") or []
            rows = [r for e in entries if (r := parse_record(e, retrieved_at))]
            writer.write(rows)
            seen += len(entries)
            start_index += len(entries) or page_size
            if window is None:
                state.set_value(settings.state_db, RESUME, str(start_index))
            report(f"{min(start_index, total_results)}/{total_results} records{label}")
            if not entries or start_index >= total_results:
                return seen

    def _get(self, settings: Settings, client: httpx.Client, params: dict) -> dict:
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        delay = settings.nvd_delay()
        last_error: Exception | None = None
        for attempt in range(settings.nvd_max_retries + 1):
            if attempt:
                time.sleep(min(delay * 2 ** attempt, 30))
            try:
                response = client.get(settings.nvd_url, params=params, headers=headers)
                if response.status_code in (403, 429) or response.status_code >= 500:
                    # 403 is how NVD answers a rate limit, not only a denial; 5xx covers its
                    # gateway timeouts (502, 503, 504, 524), which are common under load.
                    last_error = httpx.HTTPStatusError(
                        f"HTTP {response.status_code} from NVD", request=response.request, response=response
                    )
                    continue
                response.raise_for_status()
                time.sleep(delay)
                return response.json()
            except (httpx.TransportError, json.JSONDecodeError) as exc:
                last_error = exc
        raise RuntimeError(f"NVD request failed after {settings.nvd_max_retries + 1} attempts: {last_error}")


class _PartWriter:
    """Writes one Parquet part file for this run, in row groups, so memory stays flat."""

    def __init__(self, source: Source, settings: Settings, retrieved_at: datetime):
        name = f"part-{retrieved_at.strftime('%Y%m%dT%H%M%S')}-{os.urandom(2).hex()}.parquet"
        self.target = source.curated_path(settings, retrieved_at.date()).with_name(name)
        self.tmp = self.target.with_name(name + ".tmp")
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.writer: pq.ParquetWriter | None = None
        self.rows = 0

    def write(self, rows: list[dict]) -> None:
        if not rows:
            return
        if self.writer is None:
            self.writer = pq.ParquetWriter(self.tmp, SCHEMA, compression="zstd")
        self.writer.write_table(pa.Table.from_pylist(rows, schema=SCHEMA))
        self.rows += len(rows)

    def close(self) -> int:
        if self.writer is None:
            return 0
        self.writer.close()
        os.replace(self.tmp, self.target)
        return self.rows
