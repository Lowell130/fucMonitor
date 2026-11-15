"""CVE-level exploitation-prediction experiment: can we anticipate a single CVE's
entry into CISA KEV better than the raw EPSS score, with a temporally honest evaluation?

This is an *experiment*, deliberately kept apart from the category forecast. It does not
touch `exploitation.forecast`, the overview or the aggregate numbers. It answers one
question and reports the answer with its limits, so that only what the data supports is ever
promoted into the product.

The target
----------
For a prediction made on date D, the positive outcome is: the CVE *enters the CISA KEV
catalogue* within the next `horizon` days, i.e. its first `date_added` falls in (D, D+H].
This is entry into one known-exploitation catalogue, **not** the real start of exploitation,
which is earlier and unobserved. Absence from KEV means "not seen in this source", never
"never exploited". Every result below measures the ability to anticipate *this source*.

The population at D
-------------------
Every CVE that, as of D, (a) has an EPSS score in the snapshot nearest to D, (b) was already
published in NVD (`published <= D`; publication date is stable, so it is point-in-time safe),
and (c) is **not yet in KEV** (first `date_added` is null or after D). CVEs already in KEV are
excluded: we predict a *first* listing, not re-list known ones.

Features (all point-in-time safe)
---------------------------------
- `logit(EPSS as of D)` — the baseline, used as-is and also recalibrated.
- `EPSS trend` — EPSS(D) minus EPSS at the snapshot ~28 days earlier (0 when the CVE was not
  yet scored then, flagged by `is_new`). A rising score is a leading hint.
- `log1p(age in days)` — D minus publication date. Fresh CVEs enter KEV far more often.

CVSS, CWE and affected products are **excluded on purpose**: NVD is stored as current state
only (one row per CVE, rewritten over time), so their value at a past D is not reconstructible
without leakage. They belong to a separate, clearly-flagged experiment, not this one.

Models compared (walk-forward, train-only fitting)
--------------------------------------------------
1. ``raw_epss``   — the EPSS score used directly as the probability. No fitting.
2. ``epss_platt`` — EPSS recalibrated to the KEV target by a logistic fit on the training
   data only. It is monotone in EPSS, so it **cannot change EPSS's ranking** — it only fixes
   the number's calibration. This isolates the benefit of recalibration.
3. ``feat_model`` — a logistic regression on EPSS + trend + age + is_new. The gain of this
   over ``epss_platt`` is the benefit of *new information*, cleanly separated from recalibration.

Evaluation
----------
Walk-forward, no random splits. Test dates are one EPSS snapshot per month whose whole H-day
outcome window has already elapsed. At each test date D the models are trained only on earlier
test dates whose outcome window closed on or before D (so every training label was fully
observable then). Negatives are sub-sampled for the fit and re-weighted so calibration is
preserved; metrics are always computed on the **full** population at D.

Metrics: ROC-AUC (rank-based, tie-safe — the honest discrimination metric at this sparsity),
PR-AUC (reported but near-zero and tie-dominated at ~6e-5 prevalence, so not the headline),
Brier and a quantile-binned calibration error, precision/recall at fixed alert budgets and at
an equal budget, lead time before the KEV listing, and ROC-AUC per calendar year for stability.
"""

from __future__ import annotations

from datetime import date, timedelta

import duckdb
import numpy as np

from ..config import Settings
from ..sources import SOURCES


# --- data assembly -----------------------------------------------------------
def _epss_dates(settings: Settings) -> list[date]:
    return SOURCES["epss"].snapshot_dates(settings)


def _epss_file(settings: Settings, day: date) -> str:
    return SOURCES["epss"].curated_path(settings, day).as_posix()


def _eval_dates(dates: list[date], horizon: int, start: date, today: date) -> list[date]:
    """Test dates spaced at least `horizon` days apart, each with a fully elapsed H-day window.

    Spacing >= horizon makes the outcome windows (D, D+H] disjoint: consecutive dates satisfy
    D_next >= D + H, so window i ends (D+H) exactly where window i+1 starts (D_next) or earlier.
    A KEV entry therefore falls in at most one window and is never counted twice, and a CVE that
    enters KEV in a window is already listed (and so excluded) by the next test date. Picking
    greedily can leave a few-day gap between a window's end and the next snapshot; entries in
    such a gap are simply not counted anywhere (conservative), never double-counted.
    """
    picked: list[date] = []
    last: date | None = None
    for d in dates:
        if d < start or d + timedelta(days=horizon) > today:
            continue
        if last is None or (d - last).days >= horizon:
            picked.append(d)
            last = d
    return picked


def _prior_snapshot(dates: list[date], D: date, target: int = 28, lo: int = 14, hi: int = 45) -> date | None:
    cand = [d for d in dates if lo <= (D - d).days <= hi]
    return min(cand, key=lambda d: abs((D - d).days - target)) if cand else None


def _train_dates(evals: list[date], Dk: date, horizon: int) -> list[date]:
    """Earlier test dates whose whole H-day outcome window had already closed by Dk.

    This is the no-leakage rule for training: at Dk we may learn only from examples whose
    entire future outcome was observable on or before Dk.
    """
    return [Dj for Dj in evals if Dj < Dk and Dj + timedelta(days=horizon) <= Dk]


def _fetch(con: duckdb.DuckDBPyConnection, sql: str) -> dict:
    """Run a query and return columns as plain numpy arrays, without needing pandas.

    DuckDB's fetchnumpy returns a masked array for a column that holds NULLs; we fill those
    with NaN so callers can test them with np.isnan uniformly.
    """
    res = con.execute(sql).fetchnumpy()
    out = {}
    for name, arr in res.items():
        if np.ma.isMaskedArray(arr):
            try:
                out[name] = arr.astype(float).filled(np.nan)
            except (ValueError, TypeError):
                out[name] = arr.filled(None)
        else:
            out[name] = np.asarray(arr)
    return out


def _assemble(con: duckdb.DuckDBPyConnection, settings: Settings, D: date,
              prior_file: str | None, horizon: int) -> dict:
    """Point-in-time feature arrays for every CVE in the population at D (float32, no strings)."""
    if prior_file:
        prior_cte = f"p AS (SELECT cve_id, epss AS epss_prior FROM read_parquet('{prior_file}'))"
    else:
        prior_cte = "p AS (SELECT NULL::VARCHAR cve_id, NULL::DOUBLE epss_prior WHERE 1=0)"
    sql = f"""
        WITH e AS (SELECT cve_id, epss FROM read_parquet('{_epss_file(settings, D)}')),
        {prior_cte}
        SELECT e.epss, p.epss_prior,
               CAST(date_diff('day', CAST(pub.published AS DATE), DATE '{D}') AS DOUBLE) AS age,
               CASE WHEN k.kev_date > DATE '{D}' AND k.kev_date <= DATE '{D}' + {horizon}
                    THEN 1 ELSE 0 END AS y,
               CASE WHEN k.kev_date > DATE '{D}' AND k.kev_date <= DATE '{D}' + {horizon}
                    THEN date_diff('day', DATE '{D}', k.kev_date) ELSE -1 END AS d2k
        FROM e
        LEFT JOIN p USING (cve_id)
        LEFT JOIN kev k USING (cve_id)
        LEFT JOIN pub USING (cve_id)
        WHERE (k.kev_date IS NULL OR k.kev_date > DATE '{D}')
          AND pub.published IS NOT NULL
          AND pub.published <= TIMESTAMP '{D} 23:59:59+00'
    """
    d = _fetch(con, sql)
    ep = np.clip(d["epss"].astype(float), 1e-6, 1 - 1e-6)
    pr = d["epss_prior"].astype(float)
    is_new = np.isnan(pr).astype(np.float32)
    trend = np.where(np.isnan(pr), 0.0, ep - np.clip(pr, 1e-6, 1 - 1e-6)).astype(np.float32)
    age = np.clip(d["age"].astype(float), 0, None)
    return {
        "epss": ep.astype(np.float32),
        "x1": np.log(ep / (1 - ep)).astype(np.float32),
        "x2": trend,
        "x3": np.log1p(age).astype(np.float32),
        "isnew": is_new,
        "y": d["y"].astype(np.float32),
        "d2k": d["d2k"].astype(np.int32),
    }


def _lookup_tables(con: duckdb.DuckDBPyConnection, settings: Settings) -> None:
    """Point-in-time KEV first-entry date and NVD publication date, as temp tables."""
    kev_files = SOURCES["kev"].curated_files(settings)
    nvd_files = SOURCES["nvd"].curated_files(settings)
    con.execute(
        "CREATE TEMP TABLE kev AS SELECT cve_id, min(date_added) AS kev_date "
        "FROM read_parquet(?) GROUP BY 1",
        [kev_files],
    )
    con.execute(
        "CREATE TEMP TABLE pub AS SELECT cve_id, min(published) AS published "
        "FROM read_parquet(?) GROUP BY 1",
        [nvd_files],
    )


# --- model (pure numpy logistic regression, L2, intercept unpenalised) -------
def _fit_logit(Z: np.ndarray, y: np.ndarray, w: np.ndarray, l2: float = 1.0, iters: int = 30) -> np.ndarray:
    d = Z.shape[1]
    beta = np.zeros(d)
    R = np.eye(d)
    R[0, 0] = 0.0
    for _ in range(iters):
        p = np.clip(1 / (1 + np.exp(-np.clip(Z @ beta, -30, 30))), 1e-9, 1 - 1e-9)
        W = w * p * (1 - p)
        grad = Z.T @ (w * (y - p)) - l2 * (R @ beta)
        H = (Z * W[:, None]).T @ Z + l2 * R
        try:
            step = np.linalg.solve(H, grad)
        except np.linalg.LinAlgError:
            step = np.linalg.lstsq(H, grad, rcond=None)[0]
        beta = beta + step
        if np.max(np.abs(step)) < 1e-8:
            break
    return beta


def _standardize(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    mu = X.mean(0)
    sd = X.std(0)
    sd[sd < 1e-9] = 1.0
    return mu, sd


def _train_matrix(data: dict, train_dates: list[date], neg_ratio: int, rng: np.random.Generator):
    Xs, ys, ws = [], [], []
    for Dj in train_dates:
        d = data[Dj]
        y = d["y"]
        pos = y == 1
        neg = y == 0
        Xall = np.column_stack([d["x1"], d["x2"], d["x3"], d["isnew"]])
        npos = int(pos.sum())
        Xs.append(Xall[pos]); ys.append(y[pos]); ws.append(np.ones(npos))
        nneg = int(neg.sum())
        ntake = min(nneg, max(1, neg_ratio * max(1, npos)))
        sel = rng.choice(np.where(neg)[0], size=ntake, replace=False)
        Xs.append(Xall[sel]); ys.append(np.zeros(ntake)); ws.append(np.full(ntake, nneg / ntake))
    return np.vstack(Xs).astype(float), np.concatenate(ys), np.concatenate(ws)


# --- metrics -----------------------------------------------------------------
def _roc_auc(score: np.ndarray, y: np.ndarray) -> float:
    """Rank-based AUC with average ranks for ties (tie-safe), fully vectorised."""
    n = len(score)
    npos = y.sum()
    nneg = n - npos
    if npos == 0 or nneg == 0:
        return float("nan")
    order = np.argsort(score)                 # ties grouped by equal value, order within irrelevant
    s = score[order]
    change = np.empty(n, dtype=bool)
    change[0] = True
    change[1:] = s[1:] != s[:-1]
    starts = np.flatnonzero(change)           # first index of each equal-value group
    ends = np.append(starts[1:], n)           # exclusive end of each group
    avg_rank = (starts + ends - 1) / 2.0 + 1  # average 1-based rank within the group
    group = np.cumsum(change) - 1
    rr = np.empty(n)
    rr[order] = avg_rank[group]
    return float((rr[y == 1].sum() - npos * (npos + 1) / 2) / (npos * nneg))


def _ap(score: np.ndarray, y: np.ndarray) -> float:
    """Average precision, tie-safe: operating points are defined only at the boundaries between
    groups of equal score, so tied examples are never split by their arbitrary input order."""
    order = np.argsort(-score)
    s = score[order]
    ys = y[order]
    P = ys.sum()
    if P == 0:
        return 0.0
    tp = np.cumsum(ys)
    fp = np.cumsum(1 - ys)
    boundary = np.ones(len(s), dtype=bool)
    boundary[:-1] = s[:-1] != s[1:]           # last index of each equal-score group
    tp_b = tp[boundary]
    fp_b = fp[boundary]
    recall = tp_b / P
    precision = tp_b / np.maximum(tp_b + fp_b, 1)
    rprev = np.concatenate([[0.0], recall[:-1]])
    return float(np.sum((recall - rprev) * precision))


def _brier(p: np.ndarray, y: np.ndarray) -> float:
    return float(np.mean((p - y) ** 2))


def _ece(p: np.ndarray, y: np.ndarray, bins: int = 10) -> float:
    edges = np.quantile(p, np.linspace(0, 1, bins + 1))
    edges[0] = -1
    edges[-1] = 2
    tot = 0.0
    for i in range(bins):
        m = (p > edges[i]) & (p <= edges[i + 1])
        if m.sum():
            tot += abs(p[m].mean() - y[m].mean()) * m.sum()
    return float(tot / len(y))


def _budget(score, y, d2k, groups, fixed=None):
    """Precision/recall when, at each test date, the top-`b` scored CVEs are alerted.

    Tie-safe: EPSS has large groups of identical scores, so the budget boundary often lands
    inside a tie group where the choice of which tied CVEs to alert is arbitrary. Rather than let
    input order decide, count the *expected* number of true positives in the straddled group
    (its positives times the fraction of it that fits in the budget). true-positive counts are
    therefore fractional. Lead time is taken only over positives whose whole tie group fits, where
    selection is unambiguous.
    """
    tp = fp = fn = 0.0
    leads = []
    for ids in groups:
        sc = score[ids]
        yy = y[ids]
        P = int(yy.sum())
        b = P if fixed is None else fixed
        if b <= 0:
            fn += P
            continue
        order = np.argsort(-sc)
        sc_s = sc[order]
        ids_s = ids[order]
        yy_s = yy[order]
        n = len(sc_s)
        taken = 0
        sel_tp = 0.0
        i = 0
        while i < n and taken < b:
            j = i
            while j + 1 < n and sc_s[j + 1] == sc_s[i]:
                j += 1
            gsize = j - i + 1
            gpos = int(yy_s[i:j + 1].sum())
            slots = b - taken
            if gsize <= slots:                 # whole group fits: deterministic selection
                sel_tp += gpos
                for k in range(i, j + 1):
                    if yy_s[k] == 1 and d2k[ids_s[k]] >= 0:
                        leads.append(int(d2k[ids_s[k]]))
                taken += gsize
            else:                              # group straddles the budget: expected positives
                sel_tp += gpos * slots / gsize
                taken = b
            i = j + 1
        selected = min(b, n)
        tp += sel_tp
        fp += selected - sel_tp
        fn += P - sel_tp
    la = np.array(leads)
    return {
        "tp_expected": round(tp, 1), "fp_expected": round(fp, 1),
        "precision": round(tp / max(1e-9, tp + fp), 4),
        "recall": round(tp / max(1e-9, tp + fn), 4),
        "lead_median": float(np.median(la)) if len(la) else None,
        "lead_mean": round(float(la.mean()), 1) if len(la) else None,
    }


# --- public entry points -----------------------------------------------------
# Bumped whenever the experiment logic changes, so a cached result is not reused across versions.
_EXPERIMENT_VERSION = "3"
# Ranking models (produce a per-CVE score). base_rate is a non-ranking reference for Brier.
RANKERS = ("raw_epss", "epss_platt", "epss_age", "epss_trend", "feat_model")
MODELS = ("base_rate",) + RANKERS
# Which standardized feature columns (of [x1=logit epss, x2=trend, x3=age, isnew]) each fit uses.
_FEATURE_COLS = {"epss_platt": [0], "epss_age": [0, 2], "epss_trend": [0, 1], "feat_model": [0, 1, 2, 3]}


def assemble_all(settings: Settings, horizon: int = 30, start: date | None = None) -> tuple[list[date], dict]:
    """Build the point-in-time feature arrays for every monthly eval date. The slow half of a
    run; split out so callers can cache it and so tests can exercise it directly."""
    from ..state import utcnow

    start = start or date(2022, 1, 1)
    today = utcnow().date()
    con = duckdb.connect()
    try:
        con.execute("PRAGMA threads=4")
        _lookup_tables(con, settings)
        all_dates = _epss_dates(settings)
        evals = _eval_dates(all_dates, horizon, start, today)
        if len(evals) < 6:
            raise ValueError("not enough EPSS history for a walk-forward run")
        data = {D: _assemble(con, settings, D, _epss_file(settings, p) if (p := _prior_snapshot(all_dates, D)) else None, horizon)
                for D in evals}
    finally:
        con.close()
    return evals, data


def run(settings: Settings, horizon: int = 30, neg_ratio: int = 40, min_train_pos: int = 30,
        start: date | None = None, budgets=(5, 10, 20, 50, 100), seed: int = 42) -> dict:
    """Walk-forward comparison of raw EPSS, a constant base-rate, recalibrated EPSS,
    EPSS+age, EPSS+trend and the full feature model.

    Everything here is reconstructed from the stored point-in-time Parquet, so the result is
    reproducible from the repository. Touches nothing else in the app.
    """
    evals, data = assemble_all(settings, horizon, start)
    return evaluate(evals, data, horizon, neg_ratio, min_train_pos, budgets, seed)


def _cache_path(settings: Settings, horizon: int) -> "Path":
    from pathlib import Path

    return Path(settings.data_dir) / "derived" / f"epss_experiment_h{horizon}.json"


def _inputs_signature(settings: Settings, horizon: int) -> str:
    """A tag that changes whenever anything the result depends on changes: the experiment code
    (`_EXPERIMENT_VERSION`), the horizon, and the newest EPSS, KEV and NVD snapshots. Keying the
    cache on this, not on the EPSS date alone, stops it serving a result that newer KEV entries,
    a newer NVD catalogue or a code change have made stale."""
    def last(source: str) -> str:
        ds = SOURCES[source].snapshot_dates(settings)
        return str(ds[-1]) if ds else "none"
    return (f"v{_EXPERIMENT_VERSION}|h{horizon}|epss={last('epss')}|"
            f"kev={last('kev')}|nvd={last('nvd')}")


def run_cached(settings: Settings, horizon: int = 30) -> dict:
    """Run `run`, but serve a cached result while its inputs have not changed.

    The walk-forward run is heavy (minutes). The cached JSON carries an `inputs_signature`
    (code version + horizon + latest EPSS/KEV/NVD snapshots); the cache is reused only when that
    signature still matches, so a new KEV entry, a refreshed NVD catalogue or a code change all
    force a recompute. The cache lives under data/derived, which is recalculable and gitignored.
    """
    import json

    sig = _inputs_signature(settings, horizon)
    dates = _epss_dates(settings)
    latest = str(dates[-1]) if dates else None
    path = _cache_path(settings, horizon)
    if path.exists():
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
            if cached.get("inputs_signature") == sig:
                cached["served_from_cache"] = True
                return cached
        except (ValueError, OSError):
            pass
    out = run(settings, horizon=horizon)
    out["data_as_of"] = latest
    out["inputs_signature"] = sig
    out["served_from_cache"] = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    except OSError:
        pass
    return out


def evaluate(evals: list[date], data: dict, horizon: int = 30, neg_ratio: int = 40,
             min_train_pos: int = 30, budgets=(5, 10, 20, 50, 100), seed: int = 42) -> dict:
    """Walk-forward training, scoring and metrics over pre-assembled feature arrays."""
    wf = score_walk_forward(evals, data, horizon, neg_ratio, min_train_pos, seed)
    return compute_metrics(wf, horizon, budgets)


def score_walk_forward(evals: list[date], data: dict, horizon: int = 30, neg_ratio: int = 40,
                       min_train_pos: int = 30, seed: int = 42) -> dict:
    """The walk-forward training and scoring half: returns the pooled per-row scores and labels.

    Split from the metrics so a caller can cache it (it is the expensive half) and so the two
    halves can be tested independently. No metric is computed here.
    """
    rng = np.random.default_rng(seed)
    rec = {m: [] for m in MODELS}
    ry, ryr, rd2k, rdid, scored = [], [], [], [], []
    within = {m: [] for m in RANKERS}  # per-date ROC-AUC, to separate within-date from pooled
    for Dk in evals:
        # TRAIN ONLY on earlier test dates whose whole H-day window had already closed by Dk,
        # so every training label was fully observable then. No future information.
        train = _train_dates(evals, Dk, horizon)
        if sum(int(data[Dj]["y"].sum()) for Dj in train) < min_train_pos:
            continue
        X, Y, W = _train_matrix(data, train, neg_ratio, rng)
        mu, sd = _standardize(X)
        Z = (X - mu) / sd
        coef = {m: _fit_logit(np.column_stack([np.ones(len(Z))] + [Z[:, c] for c in cols]), Y, W)
                for m, cols in _FEATURE_COLS.items()}
        base = float((W * Y).sum() / W.sum())  # constant prediction = training prevalence only

        t = data[Dk]
        Xt = np.column_stack([t["x1"], t["x2"], t["x3"], t["isnew"]]).astype(float)
        Zt = (Xt - mu) / sd
        yk = t["y"].astype(float)
        sc = {"raw_epss": t["epss"].astype(float), "base_rate": np.full(len(yk), base)}
        for m, cols in _FEATURE_COLS.items():
            Zd = np.column_stack([np.ones(len(Zt))] + [Zt[:, c] for c in cols])
            sc[m] = 1 / (1 + np.exp(-np.clip(Zd @ coef[m], -30, 30)))
        for m in MODELS:
            rec[m].append(sc[m].astype(np.float32))  # float32 keeps the pooled arrays small
        for m in RANKERS:
            within[m].append(_roc_auc(sc[m], yk))
        ry.append(yk.astype(np.float32))
        ryr.append(np.full(len(yk), Dk.year, dtype=np.int16))
        rd2k.append(t["d2k"])
        rdid.append(np.full(len(yk), len(scored), dtype=np.int32))
        scored.append(Dk)

    if not scored:
        raise ValueError("no test date had enough training history")

    eval_gaps = [(scored[i + 1] - scored[i]).days for i in range(len(scored) - 1)]
    del data  # free the per-date feature dict before pooling
    return {
        "S": {m: np.concatenate(rec[m]) for m in MODELS},
        "y": np.concatenate(ry),
        "yr": np.concatenate(ryr),
        "d2k": np.concatenate(rd2k),
        "dateid": np.concatenate(rdid),
        "within": within,
        "scored": [str(s) for s in scored],
        "eval_gaps": eval_gaps,
    }


def compute_metrics(wf: dict, horizon: int = 30, budgets=(5, 10, 20, 50, 100)) -> dict:
    """The metrics half: pooled and within-date ROC-AUC, PR-AUC, Brier + skill, calibration,
    precision/recall at alert budgets, lead time and per-year stability, over pooled scores."""
    S = wf["S"]
    y = wf["y"]
    yr = wf["yr"]
    d2k = wf["d2k"]
    dateid = wf["dateid"]
    within = wf["within"]
    scored = wf["scored"]
    eval_gaps = wf["eval_gaps"]
    brier_base = _brier(S["base_rate"], y)

    def model_block(m):
        b = _brier(S[m], y)
        out = {"brier": round(b, 6),
               "brier_skill_vs_base_rate": round(1 - b / brier_base, 4) if brier_base else None}
        if m != "base_rate":
            out.update({
                "roc_auc_pooled": round(_roc_auc(S[m], y), 4),
                "roc_auc_within_date_mean": round(float(np.nanmean(within[m])), 4),
                "pr_auc": round(_ap(S[m], y), 5),
                "ece": round(_ece(S[m], y), 5),
            })
        return out

    models = {m: model_block(m) for m in MODELS}
    # Per-date row-index groups, computed once and reused across every budget and model.
    order = np.argsort(dateid, kind="stable")
    bounds = np.searchsorted(dateid[order], np.arange(len(scored) + 1))
    groups = [order[bounds[i]:bounds[i + 1]] for i in range(len(scored))]
    by_budget = {int(b): {m: _budget(S[m], y, d2k, groups, fixed=b) for m in RANKERS} for b in budgets}
    equal_budget = {m: _budget(S[m], y, d2k, groups, fixed=None) for m in RANKERS}
    years = sorted(set(int(v) for v in yr))
    # Each year is a disjoint block of test dates => a separate temporal evaluation.
    by_year = {yy: {"test_dates": int(len(set(dateid[yr == yy]))), "positives": int(y[yr == yy].sum()),
                    **{m: round(_roc_auc(S[m][yr == yy], y[yr == yy]), 4) for m in RANKERS}}
               for yy in years}

    raw_pool = models["raw_epss"]["roc_auc_pooled"]
    feat_pool = models["feat_model"]["roc_auc_pooled"]
    verdict = _verdict(models, by_year)
    return {
        "target": f"first entry into CISA KEV within {horizon} days of the prediction date",
        "target_note": "entry into one known-exploitation catalogue (KEV = CISA Known Exploited "
                       "Vulnerabilities), not the real exploitation start date; absence from KEV "
                       "means 'not seen in this source', not 'never exploited'.",
        "horizon_days": horizon,
        "reproducible_from": "backend/app/analysis/epss_experiment.run(); data = stored "
                             "point-in-time Parquet (EPSS dated snapshots, KEV date_added, NVD published).",
        "walk_forward": {"test_dates": len(scored), "first": str(scored[0]), "last": str(scored[-1]),
                         "rows": int(len(y)), "positives": int(y.sum()),
                         "prevalence": round(float(y.mean()), 8),
                         "eval_gap_days": {"min": min(eval_gaps), "median": int(np.median(eval_gaps)),
                                           "max": max(eval_gaps)} if eval_gaps else None},
        "windows_disjoint": bool(not eval_gaps or min(eval_gaps) >= horizon),
        "repeated_cves_and_overlap": (
            f"Test dates are {min(eval_gaps) if eval_gaps else horizon}-{max(eval_gaps) if eval_gaps else horizon} days "
            f"apart, each at least the {horizon}-day window, so the outcome windows (D, D+{horizon}] are "
            "disjoint: a future KEV entry falls in at most one window and is never counted twice. A CVE "
            "recurs as a (CVE, date) example across dates only while it stays un-listed, and once it enters "
            "KEV it is excluded from every later date's population; so a positive (first KEV entry) is "
            "counted at exactly one date. An entry landing in the few-day gap between a window's end and "
            "the next snapshot is not counted anywhere (conservative), never double-counted."),
        "features_used": ["logit(EPSS as of D)", "EPSS ~28-day trend", "log1p(CVE age in days)", "is_new"],
        "features_excluded": ["CVSS", "CWE", "affected products/category (NVD is stored as current "
                              "state only; their value at a past date is not reconstructible without leakage)"],
        "models": models,
        "metric_notes": {
            "roc_auc_within_date_mean": "ranking quality inside each date; raw_epss and epss_platt "
                "are equal here because Platt recalibration is monotone in EPSS and cannot change "
                "within-date order.",
            "roc_auc_pooled": "ranking across all dates pooled; raw vs recalibrated can differ only "
                "because recalibration uses different coefficients per date, changing cross-date "
                "comparability, not discrimination.",
            "brier_skill_vs_base_rate": "1 - Brier/Brier(constant training prevalence); >0 beats a "
                "constant base-rate forecast, <0 is worse. Every probability model here sits at or "
                "slightly below 0, so none adds probabilistic skill over predicting the base rate; "
                "the value is in ranking (ROC-AUC), not in the probability values.",
            "pr_auc": "tie-safe (operating points at equal-score boundaries), but near-zero at this "
                "prevalence; not the headline metric.",
            "budget_metrics": "alerts are chosen at each sampled test date, NOT every calendar day; "
                "'per_eval_date' means per sampled snapshot. Tie-safe: fractional expected true "
                "positives when the budget lands inside a group of equal scores.",
        },
        "precision_recall_by_budget_per_eval_date": by_budget,
        "precision_recall_equal_budget": equal_budget,
        "roc_auc_by_year": by_year,
        "feat_vs_raw_roc_gain_pooled": round(feat_pool - raw_pool, 4),
        "verdict": verdict,
        "limits": [
            "Measures anticipation of the KEV catalogue, not of all real exploitation.",
            "KEV date_added clusters on CISA cataloguing events (e.g. a large March-2022 "
            "back-fill), so the target timing is partly administrative, not purely real-world.",
            "PR-AUC is near-zero and tie-dominated at this prevalence; ROC-AUC and fixed-budget "
            "precision/recall are the informative metrics.",
            "Absolute performance is low: most KEV entrants had very low EPSS at prediction time, "
            "so a large share of listings is not anticipatable from these features.",
            "EPSS is reconstructed from FIRST's published dated files (faithful as-of-date), not "
            "captured live at each historical date; EPSS model version changed 5 times over the span.",
        ],
    }


def _verdict(models: dict, by_year: dict) -> str:
    raw_w = models["raw_epss"]["roc_auc_within_date_mean"]
    age_w = models["epss_age"]["roc_auc_within_date_mean"]
    trend_w = models["epss_trend"]["roc_auc_within_date_mean"]
    best = "epss_age" if age_w >= models["feat_model"]["roc_auc_within_date_mean"] else "feat_model"
    best_w = models[best]["roc_auc_within_date_mean"]
    recent_age = [v["epss_age"] - v["raw_epss"] for yy, v in by_year.items() if yy >= 2023]
    consistent = len(recent_age) >= 2 and all(g > 0 for g in recent_age)
    # which added feature actually carries the gain
    age_gain = age_w - raw_w
    trend_gain = trend_w - raw_w
    driver = ("CVE age carries essentially all of it; the EPSS trend adds almost nothing "
              f"(within-date ROC-AUC raw {raw_w:.2f}, +age {age_w:.2f}, +trend {trend_w:.2f})")
    plat_bss = models["epss_platt"]["brier_skill_vs_base_rate"]
    age_bss = models["epss_age"]["brier_skill_vs_base_rate"]
    calib = ("Recalibration to the KEV target leaves EPSS's ranking unchanged (within-date "
             "ROC-AUC identical to raw EPSS) and only rebases the probability to the KEV base rate. "
             f"On Brier every probability model sits at or just below a constant base-rate forecast "
             f"(skill vs base-rate: recalibrated {plat_bss:+.3f}, EPSS+age {age_bss:+.3f}), so none "
             "adds probabilistic skill; the gain is in ranking, not in the probability values.")
    target = ("The target is entry into the KEV catalogue, not the real exploitation start date, "
              "and absolute precision stays low (most entrants had very low EPSS), so this is "
              "justified only as a separate experimental ranking: EPSS stays the reference and the "
              "aggregate category forecast is untouched.")
    if age_gain >= 0.05 and consistent and age_gain > 2 * max(trend_gain, 1e-9):
        return (f"Against the KEV-entry target, adding CVE age improves ranking over raw EPSS "
                f"(within-date ROC-AUC {raw_w:.2f} -> {best_w:.2f}), repeated in every year "
                f"2023-2026 (separate temporal evaluations). {driver}. {calib} {target}")
    if abs(best_w - raw_w) < 0.03:
        return (f"No added feature credibly beats raw EPSS on ranking (within-date ROC-AUC "
                f"{raw_w:.2f} vs best {best_w:.2f}). {calib} Keep EPSS as the reference; do not "
                f"introduce a new model.")
    return (f"Partial result: {driver}. {calib} Keep EPSS as the reference; treat EPSS+age only as "
            f"an experimental ranking pending more positives. {target}")


def score_current(settings: Settings, horizon: int = 30, top: int = 100, neg_ratio: int = 40,
                  seed: int = 42) -> dict:
    """Rank today's not-yet-KEV population by the experimental EPSS+age model.

    The walk-forward experiment showed the whole ranking gain over EPSS comes from CVE age, not
    the EPSS trend, so the live ranker uses EPSS + age only. EXPERIMENTAL and clearly separate:
    a ranking of likely *KEV listing* within the horizon, not a probability of real exploitation,
    never fed into the category forecast. Trained on all test dates whose window has fully closed.
    """
    from ..state import utcnow

    today = utcnow().date()
    con = duckdb.connect()
    try:
        con.execute("PRAGMA threads=4")
        _lookup_tables(con, settings)
        all_dates = _epss_dates(settings)
        evals = _eval_dates(all_dates, horizon, date(2022, 1, 1), today)
        if not evals:
            raise ValueError("no usable EPSS history")
        train = [D for D in evals if D + timedelta(days=horizon) <= today]
        data = {D: _assemble(con, settings, D, _epss_file(settings, p) if (p := _prior_snapshot(all_dates, D)) else None, horizon)
                for D in train}
        # current population: latest snapshot, with cve_id kept for display
        latest = all_dates[-1]
        prior = _prior_snapshot(all_dates, latest)
        prior_cte = (f"p AS (SELECT cve_id, epss AS epss_prior FROM read_parquet('{_epss_file(settings, prior)}'))"
                     if prior else "p AS (SELECT NULL::VARCHAR cve_id, NULL::DOUBLE epss_prior WHERE 1=0)")
        cur = _fetch(con, f"""
            WITH e AS (SELECT cve_id, epss FROM read_parquet('{_epss_file(settings, latest)}')),
            {prior_cte}
            SELECT e.cve_id, e.epss, p.epss_prior,
                   CAST(date_diff('day', CAST(pub.published AS DATE), DATE '{latest}') AS DOUBLE) AS age
            FROM e LEFT JOIN p USING (cve_id) LEFT JOIN kev k USING (cve_id) LEFT JOIN pub USING (cve_id)
            WHERE (k.kev_date IS NULL OR k.kev_date > DATE '{latest}')
              AND pub.published IS NOT NULL AND pub.published <= TIMESTAMP '{latest} 23:59:59+00'
        """)
    finally:
        con.close()

    rng = np.random.default_rng(seed)
    X, Y, W = _train_matrix(data, train, neg_ratio, rng)
    mu, sd = _standardize(X)
    Z = (X - mu) / sd
    cols = _FEATURE_COLS["epss_age"]  # EPSS + age only: age is the feature that carries the gain
    b = _fit_logit(np.column_stack([np.ones(len(Z))] + [Z[:, c] for c in cols]), Y, W)

    cve_ids = cur["cve_id"]
    ep = np.clip(cur["epss"].astype(float), 1e-6, 1 - 1e-6)
    pr = cur["epss_prior"].astype(float)
    isnew = np.isnan(pr).astype(float)
    trend = np.where(np.isnan(pr), 0.0, ep - np.clip(pr, 1e-6, 1 - 1e-6))
    age = np.clip(cur["age"].astype(float), 0, None)
    Xc = np.column_stack([np.log(ep / (1 - ep)), trend, np.log1p(age), isnew])
    Zc = (Xc - mu) / sd
    Zd = np.column_stack([np.ones(len(Zc))] + [Zc[:, c] for c in cols])
    score = 1 / (1 + np.exp(-np.clip(Zd @ b, -30, 30)))
    order = np.argsort(-score)[:top]
    items = [{"cve_id": str(cve_ids[i]), "score": round(float(score[i]), 5),
              "epss": round(float(ep[i]), 5), "age_days": int(age[i])} for i in order]
    return {
        "as_of": str(latest),
        "horizon_days": horizon,
        "model": "EPSS + CVE age (logistic, recalibrated to KEV target on closed-window history)",
        "what": "experimental ranking of likely KEV listing within the horizon",
        "not": "a probability of real-world exploitation, and not used in the category forecast",
        "population": int(len(cve_ids)),
        "trained_on_test_dates": len(train),
        "items": items,
    }
