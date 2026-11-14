"""Internet scanning activity, aggregated, from the SANS Internet Storm Center (DShield).

This is the early-warning layer. The other sources say a vulnerability exists or has been
confirmed exploited; this says that, right now, more machines than usual are probing a given
service across the Internet. A surge in scanning of a service often precedes the public
confirmation that a vulnerability in it is being exploited, so it fills the gap between
"published" and "known exploited" that the forecasts are about.

It observes nobody in particular. DShield aggregates the logs of many sensors into daily
totals per port: how many records, how many distinct source IPs, how many targets. We watch
a fixed list of ports (ports.json), each tied loosely to a technology category, and store the
daily numbers. No individual address is ever fetched, stored or shown.

The port-to-category link is deliberately coarse. Many services share a port, and 443 carries
almost everything, so this measures scanning of services *associated with* a category, not a
specific product and never a specific target. The trustworthy signal is the change over time,
not the absolute count.

Storage mirrors EPSS: one file per observed day, holding every watched port for that day. A
run re-fetches a trailing window so late corrections land, and the history goes back years, so
a usable baseline exists from the first backfill rather than only after weeks of collecting.
"""

import json
import os
from datetime import date, datetime, timedelta
from pathlib import Path

import httpx
import pyarrow as pa
import pyarrow.parquet as pq

from .. import state
from ..config import Settings
from .base import IngestResult, Source, promote

PORTS_FILE = Path(__file__).with_name("ports.json")

SCHEMA = pa.schema(
    [
        ("observed_date", pa.date32()),
        ("port", pa.int32()),
        ("records", pa.int64()),
        ("targets", pa.int32()),
        ("sources", pa.int32()),  # distinct scanning IPs: the metric we trust most
        ("tcp_pct", pa.int32()),
        ("udp_pct", pa.int32()),
        ("retrieved_at", pa.timestamp("us", tz="UTC")),
    ]
)


def load_ports(settings: Settings) -> list[dict]:
    path = settings.scans_ports_file or PORTS_FILE
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    seen = set()
    for entry in config["ports"]:
        if entry["port"] in seen:
            raise ValueError(f"Duplicate port {entry['port']} in {path}")
        seen.add(entry["port"])
    return config["ports"]


def port_category(settings: Settings) -> dict[int, str]:
    return {entry["port"]: entry["category"] for entry in load_ports(settings)}


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_history(content: bytes, port: int) -> list[dict]:
    """Rows of a porthistory response. Keys are numeric strings plus some metadata keys."""
    doc = json.loads(content)
    rows = []
    for key, value in doc.items():
        if not key.isdigit() or not isinstance(value, dict) or "date" not in value:
            continue
        try:
            observed = date.fromisoformat(str(value["date"])[:10])
        except ValueError:
            continue
        rows.append(
            {
                "observed_date": observed,
                "port": port,
                "records": _int(value.get("records")),
                "targets": _int(value.get("targets")),
                "sources": _int(value.get("sources")),
                "tcp_pct": _int(value.get("tcp")),
                "udp_pct": _int(value.get("udp")),
            }
        )
    return rows


class ScansSource(Source):
    name = "scans"
    title = "Internet scanning activity (SANS ISC / DShield)"
    homepage = "https://isc.sans.edu/api/"
    cadence = "daily"

    def ingest(self, settings: Settings, client: httpx.Client, progress=None) -> IngestResult:
        today = state.utcnow().date()
        start = today - timedelta(days=settings.scans_lookback_days)
        return self._collect(settings, client, start, today, progress, trigger="window")

    def backfill(self, settings: Settings, client: httpx.Client, day: date, progress=None) -> IngestResult:
        """One historical year ending at `day`, in a single pass. DShield keeps years."""
        start = day - timedelta(days=365)
        return self._collect(settings, client, start, day, progress, trigger="backfill")

    def _collect(self, settings, client, start, end, progress, trigger) -> IngestResult:
        report = progress or (lambda _m: None)
        ports = load_ports(settings)
        retrieved_at = state.utcnow().replace(microsecond=0)
        headers = {"User-Agent": settings.user_agent}

        by_day: dict[date, list[dict]] = {}
        failed = []
        for index, entry in enumerate(ports, start=1):
            port = entry["port"]
            url = settings.scans_url.format(
                port=port, start=start.isoformat(), end=end.isoformat()
            )
            try:
                response = client.get(url, headers=headers, timeout=settings.http_timeout)
                response.raise_for_status()
                for row in parse_history(response.content, port):
                    by_day.setdefault(row["observed_date"], []).append({**row, "retrieved_at": retrieved_at})
            except Exception as exc:  # noqa: BLE001 - one port must not stop the others
                failed.append(f"{port} ({type(exc).__name__})")
            report(f"{index}/{len(ports)} ports")

        if ports and len(failed) == len(ports):
            raise RuntimeError(f"every port failed; first: {failed[0]}")

        written_days = 0
        new_rows = 0
        for observed, rows in sorted(by_day.items()):
            target = self.curated_path(settings, observed)
            existing = self._existing(target)
            fresh = {r["port"]: r for r in rows}
            if existing == {p: _comparable(r) for p, r in fresh.items()}:
                continue  # the stored day already matches; leave it
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name("data.parquet.tmp")
            pq.write_table(pa.Table.from_pylist(list(fresh.values()), schema=SCHEMA), tmp, compression="zstd")
            promote(tmp, target)
            written_days += 1
            new_rows += len(fresh)

        message = f"{written_days} days written ({new_rows} rows), {len(ports) - len(failed)}/{len(ports)} ports ok"
        if failed:
            message += f"; failed ports: {', '.join(failed)}"
        return IngestResult(end, new_rows, 0, "", written_days > 0, message)

    def _existing(self, target: Path) -> dict[int, tuple]:
        if not target.exists():
            return {}
        table = pq.read_table(target)
        rows = table.to_pylist()
        return {r["port"]: _comparable(r) for r in rows}


def _comparable(row: dict) -> tuple:
    """The fields that decide whether a stored day already matches, ignoring retrieved_at."""
    return (row["records"], row["targets"], row["sources"], row["tcp_pct"], row["udp_pct"])
