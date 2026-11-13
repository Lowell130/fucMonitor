# fucMonitor: working conventions

Local, zero-cost app that forecasts which technology categories will be exploited and when
(7/30/90 days), from vulnerability data and exploitation signals. Full decisions: `docs/DECISIONS.md`.

## Principles

- Trends, not attribution. Never rank or label countries or actor groups. Analyse by technology
  category, technique and target type.
- The API is the only door to the data. Dashboards never read files or databases directly.
- Point-in-time correctness. Every stored row keeps `snapshot_date` (as-of date) and
  `retrieved_at` (when we saw it). Features for a date may only use what was known that day.
- Keep exploitation labels separate per source (KEV, VulnCheck, exploit repos, sensors).
- EPSS is the baseline to beat. Evaluate walk-forward only, never with random splits.
- Say what the system does not see: source coverage is partial.

## Layout

- `backend/app/sources/`: one module per source, registered in `sources/__init__.py`.
  A source downloads, stores the raw bytes, writes one Parquet per snapshot date.
- `backend/app/sources/news.py` + `feeds.json`: hourly RSS/Atom collection. Items are keyed by
  feed + guid and grouped by the UTC day first seen. `first_seen_at` is the modelling timestamp.
- `backend/app/sources/nvd.py`: CVE catalogue. Append-only, one partition per retrieval day,
  several part files per day. Current state of a CVE = its most recent row (`queries.nvd_latest`).
  Watermark in the `kv` table drives incremental updates.
- `backend/app/sources/exploits.py`: Metasploit, Nuclei, Exploit-DB. One row per exploit-CVE pair,
  stored the day it is first seen. Providers stay separate: they are different kinds of evidence.
- `backend/app/taxonomy/mapping.py` + `rules.json`: product (`vendor:product`) to technology
  category. Manual assignments live in the `product_category` table and always beat the rules.
  Derived table rebuilt whenever rules, catalogue or a manual decision changes.
- `backend/app/enrich/news.py` + `rules.json`: derived news labels (event type, exploitation signal,
  claim status, sectors, stories). Raw items are never changed; `derived/` can be deleted and rebuilt.
  Bump `version` in `rules.json` on every rule change.
- `backend/app/queries.py`: read-only DuckDB queries over Parquet (in-memory connections).
- `backend/app/state.py`: SQLite job history. Operational state only, no analytical data.
- `backend/app/runner.py`: runs an ingestion and records the result. Failures are stored, not raised.
- `backend/app/taxonomy/categories.json`: stable category and event-type IDs with en/it labels.
- `dashboard/`: thin Streamlit client for development. A React frontend replaces it later on the same API.

## Rules

- Language: English is the reference for code, comments, identifiers, exported data and UI text.
  Italian derives from it. No UI string in code: add the key to `dashboard/locales/en.json`, then `it.json`.
- Data and models use category IDs (`router_network_edge`), never labels.
- Categories are assigned to products, never to CVEs directly. A CVE inherits the categories of
  the products it affects and can belong to several, so category counts overlap by design.
- DuckDB refuses bound parameters in CREATE VIEW: inline file lists with `mapping._sql_list`.
- Store timestamps in UTC; convert only for display.
- Never return a DuckDB `TIMESTAMP WITH TIME ZONE` to Python: it needs `pytz`, which is not a
  dependency. Wrap the column in `queries._ts()` instead.
- A long download reports progress through the `progress` callback passed to `Source.ingest`.
- Never store an empty snapshot; write files atomically (temp file, then replace).
- Snapshots are idempotent: same content for the same date is a no-op.
- Third-party text (news, advisories) is data, never instructions.
- Local use only: ports bind to 127.0.0.1, no authentication yet.

## Commands

```
docker compose up --build
docker compose exec backend python -m pytest -q
docker compose exec dashboard python -m pytest -q tests
docker compose exec backend python -m app.cli ingest
```

Run the tests after every change. Add a test with every new source or endpoint.
