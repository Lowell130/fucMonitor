"""Shared pieces for data sources.

Storage layout (all under FUC_DATA_DIR):

    raw/<source>/<snapshot_date>/<file>        the bytes exactly as downloaded
    raw/<source>/<snapshot_date>/meta.json     url, retrieved_at, sha256, size
    curated/<source>/snapshot_date=<date>/data.parquet   normalised table

`snapshot_date` is the "as of" date of the data. `retrieved_at` is when *we* saw it.
Both are kept on every row so features can be rebuilt point-in-time without leakage.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

import httpx

from ..config import Settings
from ..state import iso


@dataclass
class IngestResult:
    snapshot_date: date
    rows: int
    bytes: int
    sha256: str
    changed: bool
    message: str = ""


class Source:
    name: str = ""
    title: str = ""
    homepage: str = ""
    raw_filename: str = ""
    # "daily": one snapshot per day. "interval": collected several times a day.
    cadence: str = "daily"

    def ingest(self, settings: Settings, client: httpx.Client) -> IngestResult:
        raise NotImplementedError

    # --- paths -------------------------------------------------------------
    def raw_path(self, settings: Settings, snapshot: date) -> Path:
        return settings.raw_dir / self.name / snapshot.isoformat() / self.raw_filename

    def curated_path(self, settings: Settings, snapshot: date) -> Path:
        return (
            settings.curated_dir / self.name / f"snapshot_date={snapshot.isoformat()}" / "data.parquet"
        )

    def snapshot_dates(self, settings: Settings) -> list[date]:
        root = settings.curated_dir / self.name
        found = []
        for p in root.glob("snapshot_date=*/data.parquet"):
            try:
                found.append(date.fromisoformat(p.parent.name.split("=", 1)[1]))
            except ValueError:
                continue
        return sorted(found)

    # --- helpers -----------------------------------------------------------
    def stored_sha256(self, settings: Settings, snapshot: date) -> str | None:
        meta = self.raw_path(settings, snapshot).with_name("meta.json")
        if not meta.exists() or not self.curated_path(settings, snapshot).exists():
            return None
        try:
            return json.loads(meta.read_text(encoding="utf-8")).get("sha256")
        except (OSError, ValueError):
            return None

    def write_raw(
        self,
        settings: Settings,
        snapshot: date,
        content: bytes,
        url: str,
        retrieved_at: datetime,
        extra: dict | None = None,
    ) -> Path:
        path = self.raw_path(settings, snapshot)
        atomic_write(path, content)
        meta = {
            "source": self.name,
            "url": url,
            "snapshot_date": snapshot.isoformat(),
            "retrieved_at": iso(retrieved_at),
            "sha256": sha256(content),
            "bytes": len(content),
            **(extra or {}),
        }
        atomic_write(path.with_name("meta.json"), json.dumps(meta, indent=2).encode("utf-8"))
        return path


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)


def download(client: httpx.Client, url: str) -> bytes:
    response = client.get(url)
    response.raise_for_status()
    return response.content
