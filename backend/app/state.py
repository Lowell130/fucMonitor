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

CREATE TABLE IF NOT EXISTS feed_state (
    feed_id              TEXT PRIMARY KEY,
    url                  TEXT,
    last_fetch_at        TEXT,
    last_status          TEXT,
    last_message         TEXT,
    last_success_at      TEXT,
    etag                 TEXT,
    last_modified        TEXT,
    items_seen           INTEGER NOT NULL DEFAULT 0,
    items_new            INTEGER NOT NULL DEFAULT 0,
    total_items          INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS product_category (
    product    TEXT PRIMARY KEY,
    category   TEXT NOT NULL,
    note       TEXT,
    decided_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kv (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT
);
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


# --- news feeds ----------------------------------------------------------------
def feed_states(db_path: Path) -> dict[str, dict]:
    with connect(db_path) as conn:
        return {r["feed_id"]: dict(r) for r in conn.execute("SELECT * FROM feed_state").fetchall()}


def record_feed(db_path: Path, fetched_at: datetime, outcome: dict, new_items: int) -> None:
    """Save the result of one feed fetch. A failure keeps the previous ETag and counters."""
    ok = outcome["status"] != "failed"
    now = iso(fetched_at)
    with connect(db_path) as conn:
        conn.execute("INSERT OR IGNORE INTO feed_state (feed_id) VALUES (?)", (outcome["feed_id"],))
        if ok:
            conn.execute(
                """UPDATE feed_state SET url = ?, last_fetch_at = ?, last_status = ?, last_message = '',
                          last_success_at = ?, etag = ?, last_modified = ?, items_seen = ?, items_new = ?,
                          total_items = total_items + ?, consecutive_failures = 0
                   WHERE feed_id = ?""",
                (outcome["url"], now, outcome["status"], now, outcome.get("etag"),
                 outcome.get("last_modified"), outcome["items_seen"], new_items, new_items,
                 outcome["feed_id"]),
            )
        else:
            conn.execute(
                """UPDATE feed_state SET last_fetch_at = ?, last_status = 'failed', last_message = ?,
                          items_seen = 0, items_new = 0, consecutive_failures = consecutive_failures + 1
                   WHERE feed_id = ?""",
                (now, outcome["message"], outcome["feed_id"]),
            )


# --- small key/value store (watermarks and similar) ----------------------------
def get_value(db_path: Path, key: str) -> str | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_value(db_path: Path, key: str, value: str) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, iso(utcnow())),
        )


def set_run_message(db_path: Path, run_id: int, message: str) -> None:
    """Progress of a running job, so a long download is visible while it happens."""
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE job_runs SET message = ? WHERE id = ? AND status = 'running'", (message[:1000], run_id)
        )


# --- hand-made product assignments ---------------------------------------------
def product_categories(db_path: Path) -> dict[str, str]:
    with connect(db_path) as conn:
        return {r["product"]: r["category"] for r in conn.execute("SELECT * FROM product_category")}


def product_decisions(db_path: Path) -> list[dict]:
    with connect(db_path) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM product_category ORDER BY decided_at DESC, product")]


def count_product_categories(db_path: Path) -> int:
    with connect(db_path) as conn:
        return conn.execute("SELECT count(*) AS n FROM product_category").fetchone()["n"]


def set_product_category(db_path: Path, product: str, category: str, note: str | None = None) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO product_category (product, category, note, decided_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(product) DO UPDATE SET category = excluded.category, note = excluded.note, "
            "decided_at = excluded.decided_at",
            (product, category, note, iso(utcnow())),
        )


def clear_product_category(db_path: Path, product: str) -> bool:
    """Drop a hand-made assignment so the product falls back to the rules."""
    with connect(db_path) as conn:
        return conn.execute("DELETE FROM product_category WHERE product = ?", (product,)).rowcount > 0
