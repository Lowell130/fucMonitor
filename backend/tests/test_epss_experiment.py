"""Tests for the CVE-level EPSS experiment, focused on temporal leakage.

A predictive evaluation is only worth anything if no feature, label or parameter choice used
information from the future. These build a tiny synthetic point-in-time store and assert that
property at every seam, plus the invariants the report relies on.
"""

import json
from datetime import date, datetime, timedelta, timezone

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from app.analysis import epss_experiment as ex
from app.sources import SOURCES


# --- helpers to lay down a synthetic curated store --------------------------
def _write(path, table):
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, path)


def _epss_snapshot(settings, day: date, rows: list[tuple]):
    """rows: (cve_id, epss). Only the columns the module reads are needed."""
    t = pa.table({"cve_id": [r[0] for r in rows], "epss": [float(r[1]) for r in rows]})
    _write(SOURCES["epss"].curated_path(settings, day), t)


def _kev(settings, rows: list[tuple], snapshot: date = date(2026, 11, 14)):
    """rows: (cve_id, date_added). `snapshot` is the retrieval date (catalogue freshness)."""
    t = pa.table({"cve_id": [r[0] for r in rows], "date_added": [r[1] for r in rows]})
    _write(SOURCES["kev"].curated_path(settings, snapshot), t)


def _nvd(settings, rows: list[tuple]):
    """rows: (cve_id, published_date)."""
    t = pa.table({
        "cve_id": [r[0] for r in rows],
        "published": [datetime(r[1].year, r[1].month, r[1].day, tzinfo=timezone.utc) for r in rows],
    })
    _write(SOURCES["nvd"].curated_path(settings, date(2026, 11, 14)), t)


def _exploits(settings, rows: list[tuple]):
    """rows: (cve_id, provider, provider_date)."""
    t = pa.table({
        "cve_id": [r[0] for r in rows],
        "provider": [r[1] for r in rows],
        "provider_date": [r[2] for r in rows],
    })
    _write(SOURCES["exploits"].curated_path(settings, date(2026, 11, 14)), t)


def _con(settings):
    import duckdb

    con = duckdb.connect()
    ex._lookup_tables(con, settings)
    return con


# --- pure-logic leakage rules ------------------------------------------------
def test_train_dates_never_use_unclosed_windows():
    evals = [date(2024, 1, 1), date(2024, 2, 1), date(2024, 3, 1), date(2024, 4, 1)]
    # At 2024-03-01 with a 30-day horizon, 2024-02-01's window closes 2024-03-02 (> 03-01),
    # so it must be excluded; only January qualifies.
    assert ex._train_dates(evals, date(2024, 3, 1), 30) == [date(2024, 1, 1)]
    # The test date itself is never in its own training set.
    assert date(2024, 3, 1) not in ex._train_dates(evals, date(2024, 3, 1), 30)


def test_eval_dates_exclude_unelapsed_window():
    dates = [date(2026, 10, 1), date(2026, 11, 1)]
    today = date(2026, 11, 14)
    got = ex._eval_dates(dates, horizon=30, start=date(2022, 1, 1), today=today)
    assert date(2026, 10, 1) in got          # window closed 2026-10-31 <= today
    assert date(2026, 11, 1) not in got      # window closes 2026-12-01 > today


def test_eval_dates_are_spaced_at_least_a_horizon_apart():
    # Weekly snapshots: picking must skip to >= horizon days after the last pick, so the
    # outcome windows (D, D+H] never overlap and no KEV entry is counted at two dates.
    dates = [date(2024, 1, 1) + timedelta(days=7 * i) for i in range(40)]
    today = date(2026, 1, 1)
    got = ex._eval_dates(dates, horizon=30, start=date(2024, 1, 1), today=today)
    gaps = [(got[i + 1] - got[i]).days for i in range(len(got) - 1)]
    assert gaps and min(gaps) >= 30          # disjoint windows by construction


def test_prior_snapshot_is_strictly_earlier():
    dates = [date(2024, 1, 1), date(2024, 1, 29), date(2024, 2, 26)]
    p = ex._prior_snapshot(dates, date(2024, 2, 26))
    assert p is not None and p < date(2024, 2, 26) and (date(2024, 2, 26) - p).days >= 14


# --- feature/label point-in-time correctness ---------------------------------
@pytest.fixture
def store(settings):
    """A store where the leakage traps are explicit.

    At D = 2024-02-26 and a 30-day window:
      PAST    already in KEV on 2024-01-10  -> excluded from the population
      SOON    enters KEV 2024-03-10 (in window)      -> positive
      LATER   enters KEV 2024-06-01 (after window)   -> negative, NOT excluded
      NEVER   never in KEV                            -> negative
      FUTUREPUB published 2024-05-01 (after D)        -> excluded (not yet published)
    """
    D = date(2024, 2, 26)
    prior = date(2024, 1, 29)
    for day, ep in [(prior, 0.10), (D, 0.20)]:
        _epss_snapshot(settings, day, [
            ("CVE-PAST", ep), ("CVE-SOON", ep + 0.05), ("CVE-LATER", ep),
            ("CVE-NEVER", 0.001), ("CVE-FUTUREPUB", 0.30),
        ])
    _kev(settings, [
        ("CVE-PAST", date(2024, 1, 10)),
        ("CVE-SOON", date(2024, 3, 10)),
        ("CVE-LATER", date(2024, 6, 1)),
    ])
    _nvd(settings, [
        ("CVE-PAST", date(2020, 1, 1)), ("CVE-SOON", date(2023, 1, 1)),
        ("CVE-LATER", date(2023, 1, 1)), ("CVE-NEVER", date(2023, 1, 1)),
        ("CVE-FUTUREPUB", date(2024, 5, 1)),
    ])
    return settings, D, prior


def test_already_listed_cve_excluded_and_future_entry_is_positive(store):
    settings, D, prior = store
    con = _con(settings)
    # Query the population the same way _assemble does, but keep ids to assert membership.
    import duckdb

    rows = duckdb.connect().execute(f"""
        WITH e AS (SELECT cve_id, epss FROM read_parquet('{ex._epss_file(settings, D)}'))
        SELECT e.cve_id,
               CASE WHEN k.kev_date > DATE '{D}' AND k.kev_date <= DATE '{D}' + 30 THEN 1 ELSE 0 END AS y
        FROM e
        LEFT JOIN (SELECT cve_id, min(date_added) kev_date FROM read_parquet('{SOURCES["kev"].curated_path(settings, date(2026,11,14)).as_posix()}') GROUP BY 1) k USING(cve_id)
        LEFT JOIN (SELECT cve_id, min(published) published FROM read_parquet('{SOURCES["nvd"].curated_path(settings, date(2026,11,14)).as_posix()}') GROUP BY 1) p USING(cve_id)
        WHERE (k.kev_date IS NULL OR k.kev_date > DATE '{D}')
          AND p.published IS NOT NULL AND p.published <= TIMESTAMP '{D} 23:59:59+00'
    """).df()
    con.close()
    pop = dict(zip(rows["cve_id"], rows["y"]))
    assert "CVE-PAST" not in pop            # already listed before D -> excluded
    assert "CVE-FUTUREPUB" not in pop       # not yet published at D -> excluded
    assert pop["CVE-SOON"] == 1             # enters KEV within the window -> positive
    assert pop["CVE-LATER"] == 0            # enters KEV after the window -> negative, kept
    assert pop["CVE-NEVER"] == 0


def test_assemble_counts_match_expected(store):
    settings, D, prior = store
    con = _con(settings)
    arr = ex._assemble(con, settings, D, ex._epss_file(settings, prior), horizon=30)
    con.close()
    # population = SOON, LATER, NEVER (PAST and FUTUREPUB excluded)
    assert len(arr["y"]) == 3
    assert int(arr["y"].sum()) == 1         # exactly SOON
    # lead time of the positive is recorded and lies inside the window
    d2k = arr["d2k"][arr["y"] == 1][0]
    assert 0 < d2k <= 30


def test_trend_uses_only_prior_snapshot(store):
    settings, D, prior = store
    con = _con(settings)
    arr = ex._assemble(con, settings, D, ex._epss_file(settings, prior), horizon=30)
    con.close()
    # EPSS rose 0.10 -> 0.20 between prior and D for SOON and LATER (trend > 0); CVE-NEVER sat
    # at 0.001 on both snapshots (trend 0). None are is_new (all present in the prior snapshot).
    assert (arr["x2"] >= 0).all()
    assert (arr["x2"] > 0).sum() >= 2
    assert (arr["isnew"] == 0).all()


def test_no_prior_snapshot_marks_is_new(settings):
    D = date(2024, 2, 26)
    _epss_snapshot(settings, D, [("CVE-A", 0.2)])
    _kev(settings, [])
    _nvd(settings, [("CVE-A", date(2023, 1, 1))])
    con = _con(settings)
    arr = ex._assemble(con, settings, D, None, horizon=30)  # no prior file available
    con.close()
    assert arr["isnew"][0] == 1
    assert arr["x2"][0] == 0.0               # trend defaults to 0 when no history


# --- invariants the report relies on ----------------------------------------
def test_recalibration_is_monotone_so_within_date_rank_is_identical():
    import numpy as np

    rng = np.random.default_rng(0)
    epss = rng.random(500)
    y = (rng.random(500) < epss * 0.1).astype(float)
    # Platt recalibration is sigmoid(a + b*logit(epss)); strictly monotone in epss for b>0,
    # so the rank-based ROC-AUC must match raw EPSS exactly.
    z = np.log(np.clip(epss, 1e-6, 1 - 1e-6) / (1 - np.clip(epss, 1e-6, 1 - 1e-6)))
    recal = 1 / (1 + np.exp(-(-2.0 + 1.3 * z)))
    assert ex._roc_auc(epss, y) == pytest.approx(ex._roc_auc(recal, y), abs=1e-9)


def test_pr_auc_and_budget_are_tie_order_invariant():
    import numpy as np

    # Many exact ties (as EPSS has): the metric must not depend on how tied rows are ordered.
    rng = np.random.default_rng(1)
    score = np.repeat(np.array([0.9, 0.5, 0.5, 0.5, 0.1]), 20).astype(float)
    y = (rng.random(len(score)) < 0.3).astype(float)
    ap1 = ex._ap(score, y)
    roc1 = ex._roc_auc(score, y)
    perm = rng.permutation(len(score))
    ap2 = ex._ap(score[perm], y[perm])
    roc2 = ex._roc_auc(score[perm], y[perm])
    assert ap1 == pytest.approx(ap2, abs=1e-9)
    assert roc1 == pytest.approx(roc2, abs=1e-9)
    # budget expected-TP is also permutation-invariant when the boundary lands inside a tie group
    allrows = [np.arange(len(score))]
    b1 = ex._budget(score, y, np.full(len(score), -1), allrows, fixed=25)
    b2 = ex._budget(score[perm], y[perm], np.full(len(score), -1), allrows, fixed=25)
    assert b1["tp_expected"] == pytest.approx(b2["tp_expected"], abs=1e-9)


def test_run_smoke_and_no_leakage_invariants(settings):
    """A small end-to-end run: enough monthly snapshots and positives to train and score."""
    import numpy as np

    # ~20 months of snapshots so that, after >=30-day spacing, plenty of eval dates remain.
    months = [date(2024, 1, 2) + timedelta(days=31 * i) for i in range(20)]
    priors = [m - timedelta(days=28) for m in months]
    cves = [f"CVE-X{i:03d}" for i in range(300)]
    for day in sorted(set(months + priors)):
        rows = [(c, 0.01 + (i % 50) / 100.0) for i, c in enumerate(cves)]
        _epss_snapshot(settings, day, rows)
    # 5 CVEs enter KEV ~10 days into the window after each eval date (distinct CVEs each time)
    kev_rows = []
    for j, day in enumerate(months):
        for k in range(5):
            kev_rows.append((cves[j * 5 + k], day + timedelta(days=10)))
    _kev(settings, kev_rows)
    _nvd(settings, [(c, date(2023, 1, 1)) for c in cves])

    out = ex.run(settings, horizon=30, neg_ratio=20, min_train_pos=1, start=date(2024, 1, 1))
    # structure
    assert out["horizon_days"] == 30
    assert set(out["models"]) == set(ex.MODELS)
    assert out["walk_forward"]["positives"] >= 1
    # Recalibration is monotone in EPSS, so it cannot change discrimination: the distance of the
    # within-date ROC-AUC from 0.5 is identical to raw EPSS (direction may flip if the fit learns
    # b<0 on this degenerate synthetic data; on real data b>0 and the values match directly).
    raw_w = out["models"]["raw_epss"]["roc_auc_within_date_mean"]
    pla_w = out["models"]["epss_platt"]["roc_auc_within_date_mean"]
    assert abs(raw_w - 0.5) == pytest.approx(abs(pla_w - 0.5), abs=1e-6)
    # base_rate has a Brier but no ranking metrics
    assert "roc_auc_pooled" not in out["models"]["base_rate"]
    assert out["models"]["base_rate"]["brier_skill_vs_base_rate"] == pytest.approx(0.0, abs=1e-9)
    # windows are disjoint by construction (spacing >= horizon), so no double counting
    assert out["windows_disjoint"] is True
    assert "exactly one date" in out["repeated_cves_and_overlap"]

    # the live scorer runs on numpy alone (no pandas) and reports a sane population count
    scored = ex.score_current(settings, horizon=30, top=10, neg_ratio=20)
    assert "age" in scored["model"].lower()
    assert scored["population"] >= len(scored["items"]) >= 1
    assert all(it["age_days"] >= 0 for it in scored["items"])


def _news(settings, rows):
    """rows: (item_id, first_seen_date, [cve_ids])."""
    t = pa.table({
        "item_id": [r[0] for r in rows],
        "first_seen_at": [datetime(r[1].year, r[1].month, r[1].day, tzinfo=timezone.utc) for r in rows],
        "cve_ids": [r[2] for r in rows],
    })
    _write(SOURCES["news"].curated_path(settings, date(2026, 11, 15)), t)


def test_news_readiness_reports_insufficient_short_history(settings):
    # No news at all -> not ready, clear note.
    r0 = ex.news_history_readiness(settings, horizon=30)
    assert r0["ready"] is False and r0["observed_days"] == 0
    # A few days of news -> still not ready (needs ~a year), but counts are reported.
    _news(settings, [(f"n{i}", date(2026, 11, 12) + timedelta(days=i % 4), ["CVE-2026-0001"])
                     for i in range(20)])
    r1 = ex.news_history_readiness(settings, horizon=30)
    assert r1["ready"] is False
    assert r1["observed_days"] == 4 and r1["span_days"] <= 4
    assert r1["items_with_cve"] == 20
    assert "hold-out" in r1["note"]


def test_exploit_ablation_point_in_time_and_structure(settings):
    """The ablation adds a point-in-time 'public exploit by D' feature and keeps the machinery."""
    months = [date(2024, 1, 2) + timedelta(days=31 * i) for i in range(20)]
    priors = [m - timedelta(days=28) for m in months]
    cves = [f"CVE-X{i:03d}" for i in range(300)]
    for day in sorted(set(months + priors)):
        _epss_snapshot(settings, day, [(c, 0.01 + (i % 50) / 100.0) for i, c in enumerate(cves)])
    kev_rows = [(cves[j * 5 + k], day + timedelta(days=10)) for j, day in enumerate(months) for k in range(5)]
    _kev(settings, kev_rows)
    _nvd(settings, [(c, date(2023, 1, 1)) for c in cves])
    # exploits: Exploit-DB with a date in 2024-06 for a block of CVEs; Nuclei has no date (ignored)
    _exploits(settings, [(cves[i], "exploitdb", date(2024, 6, 1)) for i in range(50)]
                        + [(cves[i], "nuclei", None) for i in range(50, 60)])

    out = ex.run_exploit_ablation(settings, horizon=30, neg_ratio=20, min_train_pos=1,
                                  start=date(2024, 1, 1))
    assert set(out["models"]) == set(ex._ABLATION_MODELS)
    # exploit_only is a ranker with metrics; verdict mentions exploit availability
    assert "roc_auc_within_date_mean" in out["models"]["exploit_only"]
    assert "exploit" in out["verdict"].lower()
    assert any("provider's own date" in lim for lim in out["limits"])

    # point-in-time: before the exploit date no CVE is flagged; after it, the block is
    import duckdb
    con = duckdb.connect()
    ex._lookup_tables(con, settings, with_exploit=True)
    before = ex._assemble(con, settings, months[3], None, 30, with_exploit=True)   # 2024-04-04
    after = ex._assemble(con, settings, months[8], None, 30, with_exploit=True)    # 2024-09-06
    con.close()
    assert before["x5"].sum() == 0            # exploit date 2024-06-01 is in the future here
    assert after["x5"].sum() > 0              # and in the past here


def test_scan_experiment_handles_missing_data(settings):
    """With no catalogue/scan history the scan experiment returns a note, not a crash."""
    from app.analysis import scan_experiment
    out = scan_experiment.run(settings, horizon=90)
    assert out["methods"] == [] and "note" in out


def test_prospective_log_snapshot_and_closed_window_scoring(settings):
    """Freeze a prediction, then score only once its window has closed; append-only, no overwrite."""
    from app.analysis import prediction_log as pl
    from app.state import utcnow

    # minimal live population so score_current works: a few CVEs, one snapshot, trend prior, NVD
    latest = date(2026, 1, 5)
    prior = date(2025, 12, 8)
    cves = [f"CVE-P{i:03d}" for i in range(120)]
    for day in (prior, latest):
        _epss_snapshot(settings, day, [(c, 0.02 + (i % 40) / 100.0) for i, c in enumerate(cves)])
    # training history so the model can fit (reuse monthly snapshots in 2025)
    months = [date(2025, 1, 2) + timedelta(days=31 * i) for i in range(12)]
    for day in months:
        _epss_snapshot(settings, day, [(c, 0.02 + (i % 40) / 100.0) for i, c in enumerate(cves)])
    kev_rows = [(cves[j * 3 + k], day + timedelta(days=8)) for j, day in enumerate(months) for k in range(3)]
    _kev(settings, kev_rows)
    _nvd(settings, [(c, date(2024, 1, 1)) for c in cves])

    r = pl.snapshot_predictions(settings, horizon=30, top=20)
    assert r["status"] == "logged" and r["n_predicted"] >= 1
    # the snapshot stores both rankings (model_score and epss) per CVE
    rec = json.loads((pl._log_dir(settings) / f"cve_kev_ranking_h30_{utcnow().date()}.json").read_text())
    assert all({"cve_id", "model_score", "epss"} <= set(it) for it in rec["items"])
    assert "stale_inputs" in rec and "inputs_signature" in rec
    # atomic write left a backup copy and recorded the run
    assert (pl._log_dir(settings) / "_backup").exists()
    assert (pl._log_dir(settings) / "_runs.jsonl").exists()
    # idempotent: a second call the same day does not overwrite
    again = pl.snapshot_predictions(settings, horizon=30, top=20)
    assert again["status"] == "already_logged"

    # window not closed yet -> pending, nothing scored
    sc = pl.score_prospective(settings, horizon=30)
    assert sc["pending_window_open"] >= 1 and sc["closed_scored"] == 0
    assert sc["pooled_precision_at_k_all_windows"] is None


def test_prospective_scoring_requires_closed_and_covered_window(settings):
    """A window that elapsed but is not covered by KEV data is not scored; a covered one is."""
    import json as _json
    from app.analysis import prediction_log as pl

    # Catalogue retrieved only through 2026-02-10 (snapshot date = freshness), a true entrant 01-15
    _kev(settings, [("CVE-HIT-0001", date(2026, 1, 15)), ("CVE-OLD-0001", date(2025, 1, 1))],
         snapshot=date(2026, 2, 10))

    def write_snap(issued, items):
        rec = {"kind": "cve_kev_ranking", "issued_at": issued,
               "window_closes": str(date.fromisoformat(issued) + timedelta(days=30)),
               "model_version": "4", "items": items}
        pl._snapshot_path(settings, 30, date.fromisoformat(issued)).parent.mkdir(parents=True, exist_ok=True)
        pl._snapshot_path(settings, 30, date.fromisoformat(issued)).write_text(_json.dumps(rec))

    # covered: issued 2026-01-05, closes 2026-02-04 ... but kev_max is 2026-01-15 < 2026-02-04
    # so make a covered one that closes before kev_max, and an uncovered one after it.
    write_snap("2025-12-20", [{"cve_id": "CVE-HIT-0001", "model_score": 0.9, "epss": 0.1},
                              {"cve_id": "CVE-MISS-0002", "model_score": 0.8, "epss": 0.9}])  # closes 2026-01-19 <= kev_max
    write_snap("2026-01-20", [{"cve_id": "CVE-X", "model_score": 0.5, "epss": 0.5}])          # closes 2026-02-19 > kev_max
    out = pl.score_prospective(settings, horizon=30, ks=(1, 2))
    assert out["closed_scored"] == 1                      # only the covered window
    assert out["pending_data_not_covering_window"] == 1  # the uncovered one
    # model ranked the true KEV entrant first, EPSS ranked it second -> model precision@1 higher
    pm = out["pooled_precision_at_k_all_windows"]["model"][1]
    pe = out["pooled_precision_at_k_all_windows"]["epss"][1]
    assert pm == 1.0 and pe == 0.0


def test_collection_health_reports_staleness_and_problems(settings):
    """With no data, every source is stale and problems are visible, not silent."""
    from app import health
    rep = health.collection_report(settings)
    assert rep["ok"] is False
    assert rep["problems"]                       # stale sources surfaced
    assert {s["source"] for s in rep["sources"]} >= {"kev", "epss", "nvd", "scans"}
    assert all("stale" in s for s in rep["sources"])


def test_watchlist_loads_validates_and_weights(settings):
    from app import watchlist
    # absent -> inactive, with a helpful note
    wl0 = watchlist.load(settings)
    assert wl0["active"] is False and "watchlist.json" in wl0["note"]
    # write one valid category and one unknown id
    (pathlib_Path := __import__("pathlib").Path)(settings.data_dir).mkdir(parents=True, exist_ok=True)
    (pathlib_Path(settings.data_dir) / "watchlist.json").write_text(__import__("json").dumps({
        "impact_weights": {"low": 1, "medium": 2, "high": 4},
        "categories": [{"category_id": "vpn_remote_access", "impact": "high"},
                       {"category_id": "not_a_real_category", "impact": "low"}],
        "products": [{"product": "acme:gw", "impact": "medium"}],
    }))
    wl = watchlist.load(settings)
    assert wl["active"] is True
    assert wl["categories"]["vpn_remote_access"]["weight"] == 4.0
    assert "not_a_real_category" in wl["unknown_category_ids"]   # unknown surfaced, not silently kept
    assert wl["products"]["acme:gw"]["weight"] == 2.0
    assert watchlist.category_weight(wl, "vpn_remote_access") == 4.0
    assert watchlist.category_weight(wl, "web_cms") == 0.0
