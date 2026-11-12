"""Job history in SQLite: what ran, when, and how it ended.

Analytical data lives in Parquet files; this database only holds operational state.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS job_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT NOT NULL,
    trigger       TEXT NOT NULL,
    status        TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    snapshot_date TEXT,
    rows          INTEGER,
    bytes         INTEGER,
    sha256        TEXT,
    changed       INTEGER,
    message       TEXT
);
CREATE INDEX IF NOT EXISTS idx_job_runs_source ON job_runs (source, id DESC);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def connect(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def start_run(db_path: Path, source: str, trigger: str) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO job_runs (source, trigger, status, started_at) VALUES (?, ?, 'running', ?)",
            (source, trigger, iso(utcnow())),
        )
        return int(cur.lastrowid)


def finish_run(db_path: Path, run_id: int, status: str, **fields) -> None:
    allowed = {"snapshot_date", "rows", "bytes", "sha256", "changed", "message"}
    cols = {k: v for k, v in fields.items() if k in allowed}
    if "changed" in cols and cols["changed"] is not None:
        cols["changed"] = int(cols["changed"])
    assignments = "".join(f", {k} = ?" for k in cols)
    with connect(db_path) as conn:
        conn.execute(
            f"UPDATE job_runs SET status = ?, finished_at = ?{assignments} WHERE id = ?",
            (status, iso(utcnow()), *cols.values(), run_id),
        )


def mark_interrupted(db_path: Path) -> None:
    """Runs left in 'running' by a previous process can never finish: close them."""
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE job_runs SET status = 'failed', finished_at = ?, "
            "message = 'interrupted by a restart' WHERE status = 'running'",
            (iso(utcnow()),),
        )


def _row(row: sqlite3.Row) -> dict:
    d = dict(row)
    if d.get("changed") is not None:
        d["changed"] = bool(d["changed"])
    return d


def list_runs(db_path: Path, source: str | None = None, limit: int = 50) -> list[dict]:
    with connect(db_path) as conn:
        if source:
            rows = conn.execute(
                "SELECT * FROM job_runs WHERE source = ? ORDER BY id DESC LIMIT ?", (source, limit)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM job_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_row(r) for r in rows]


def get_run(db_path: Path, run_id: int) -> dict:
    with connect(db_path) as conn:
        return _row(conn.execute("SELECT * FROM job_runs WHERE id = ?", (run_id,)).fetchone())


def last_run(db_path: Path, source: str, status: str | None = None) -> dict | None:
    with connect(db_path) as conn:
        if status:
            row = conn.execute(
                "SELECT * FROM job_runs WHERE source = ? AND status = ? ORDER BY id DESC LIMIT 1",
                (source, status),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM job_runs WHERE source = ? ORDER BY id DESC LIMIT 1", (source,)
            ).fetchone()
    return _row(row) if row else None
