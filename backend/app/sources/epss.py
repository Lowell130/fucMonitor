"""EPSS daily scores (FIRST.org). The baseline to beat, and a model feature.

File format (gzip CSV): from EPSS v2 a first comment line such as
`#model_version:v2025.03.14,score_date:2026-11-12T00:00:00+0000`, then `cve,epss,percentile`.
The snapshot date is the score_date published in the file, so a late or repeated
download never creates a wrong day.
"""

import gzip
import io
import os
import re
from datetime import date

import duckdb
import httpx

from ..config import Settings
from ..state import iso, utcnow
from .base import IngestResult, Source, download, sha256

_SCORE_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")
_MODEL = re.compile(r"model_version:([^,\s]+)")


def read_header(content: bytes) -> tuple[date | None, str | None, int]:
    """Return (score_date, model_version, lines to skip before the CSV header)."""
    with gzip.open(io.BytesIO(content), "rt", encoding="utf-8") as fh:
        first = fh.readline()
    if not first.startswith("#"):
        return None, None, 0
    d = _SCORE_DATE.search(first)
    m = _MODEL.search(first)
    return (date.fromisoformat(d.group(1)) if d else None), (m.group(1) if m else None), 1


class EpssSource(Source):
    name = "epss"
    title = "EPSS scores (FIRST.org)"
    homepage = "https://www.first.org/epss/data"
    raw_filename = "epss_scores.csv.gz"

    def ingest(self, settings: Settings, client: httpx.Client) -> IngestResult:
        return self._store(settings, download(client, settings.epss_url), settings.epss_url)

    def backfill(self, settings: Settings, client: httpx.Client, day: date) -> IngestResult:
        """Fetch one historical day. Valid point-in-time: the file is the score as of `day`."""
        url = settings.epss_dated_url.format(date=day.isoformat())
        return self._store(settings, download(client, url), url, fallback_date=day, backfilled=True)

    def _store(
        self,
        settings: Settings,
        content: bytes,
        url: str,
        fallback_date: date | None = None,
        backfilled: bool = False,
    ) -> IngestResult:
        retrieved_at = utcnow()
        score_date, model, skip = read_header(content)
        snapshot = score_date or fallback_date or retrieved_at.date()
        digest = sha256(content)

        if self.stored_sha256(settings, snapshot) == digest:
            rows = duckdb.connect().execute(
                "SELECT count(*) FROM read_parquet(?)", [str(self.curated_path(settings, snapshot))]
            ).fetchone()[0]
            return IngestResult(snapshot, rows, len(content), digest, False, "unchanged")

        raw = self.write_raw(
            settings,
            snapshot,
            content,
            url,
            retrieved_at,
            extra={"model_version": model, "backfilled": backfilled},
        )
        target = self.curated_path(settings, snapshot)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name("data.parquet.tmp")

        con = duckdb.connect()
        try:
            con.execute(
                f"""
                COPY (
                    SELECT upper(trim(cve))        AS cve_id,
                           epss::DOUBLE            AS epss,
                           percentile::DOUBLE      AS percentile,
                           ?::VARCHAR              AS model_version,
                           ?::DATE                 AS score_date,
                           ?::TIMESTAMPTZ          AS retrieved_at,
                           ?::BOOLEAN              AS backfilled
                    FROM read_csv(?, skip = {int(skip)}, header = true, compression = 'gzip',
                                  columns = {{'cve': 'VARCHAR', 'epss': 'VARCHAR', 'percentile': 'VARCHAR'}})
                    WHERE cve IS NOT NULL
                ) TO '{tmp.as_posix()}' (FORMAT parquet, COMPRESSION zstd)
                """,
                [model, snapshot.isoformat(), iso(retrieved_at), backfilled, str(raw)],
            )
            rows = con.execute("SELECT count(*) FROM read_parquet(?)", [str(tmp)]).fetchone()[0]
        finally:
            con.close()

        if rows == 0:
            tmp.unlink(missing_ok=True)
            raise ValueError("EPSS file parsed to zero rows; refusing to store an empty snapshot")
        os.replace(tmp, target)
        return IngestResult(snapshot, rows, len(content), digest, True, "stored")
