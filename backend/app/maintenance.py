"""Checks the stored files are readable, and clears out the ones that are not.

A single truncated Parquet file breaks every query that reads a whole source, and the error
names no file unless somebody is watching the logs. This turns that into something a person
can run and act on.

Removing a file is safe for sources that can fetch the day again (EPSS by backfill, KEV,
news and exploits on their next run). For the CVE catalogue a removed part leaves a gap
until a full download runs, so that is reported rather than done quietly.
"""

import logging

import pyarrow.parquet as pq

from .config import Settings
from .sources import SOURCES

log = logging.getLogger("fucmonitor.maintenance")
REFETCHABLE = {"epss", "kev", "news", "exploits"}


def verify(settings: Settings, repair: bool = False) -> dict:
    """Read the footer of every stored file. With `repair`, delete the unreadable ones."""
    sources = []
    for name, source in SOURCES.items():
        unreadable = []
        files = source.curated_files(settings)
        for path in files:
            try:
                pq.read_metadata(path)
            except Exception as exc:  # noqa: BLE001 - whatever is wrong with it, it is wrong
                entry = {"file": path, "error": f"{type(exc).__name__}: {exc}"[:300], "removed": False}
                if repair:
                    from pathlib import Path

                    Path(path).unlink(missing_ok=True)
                    entry["removed"] = True
                    log.warning("maintenance: removed unreadable %s", path)
                unreadable.append(entry)
        advice = ""
        if unreadable:
            advice = (
                "run the source again, or backfill the missing days"
                if name in REFETCHABLE
                else "the catalogue now has a gap: clear the watermark to force a full download"
            )
        sources.append(
            {"source": name, "files": len(files), "unreadable": unreadable, "advice": advice}
        )
    return {"repaired": repair, "sources": sources}
