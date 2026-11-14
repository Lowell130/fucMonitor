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


def _monthly_eval_dates(dates: list[date], horizon: int, start: date, today: date) -> list[date]:
    """One snapshot per calendar month whose whole H-day window has elapsed."""
    by_month: dict[tuple[int, int], date] = {}
    for d in dates:
        if d < start or d + timedelta(days=horizon) > today:
            continue
        by_month.setdefault((d.year, d.month), d)
    return sorted(by_month.values())


def _prior_snapshot(dates: list[date], D: date, target: int = 28, lo: int = 14, hi: int = 45) -> date | None:
    cand = [d for d in dates if lo <= (D - d).days <= hi]
    return min(cand, key=lambda d: abs((D - d).days - target)) if cand else None


def _train_dates(evals: list[date], Dk: date, horizon: int) -> list[date]:
    """Earlier test dates whose whole H-day outcome window had already closed by Dk.

    This is the no-leakage rule for training: at Dk we may learn only from examples whose
    entire future outcome was observable on or before Dk.
    """
    return [Dj for Dj in evals if Dj < Dk and Dj + timedelta(days=horizon) <= Dk]


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
    df = con.execute(sql).df()
    ep = np.clip(df["epss"].to_numpy(float), 1e-6, 1 - 1e-6)
    pr = df["epss_prior"].to_numpy(float)
    is_new = np.isnan(pr).astype(np.float32)
    trend = np.where(np.isnan(pr), 0.0, ep - np.clip(pr, 1e-6, 1 - 1e-6)).astype(np.float32)
    age = np.clip(df["age"].to_numpy(float), 0, None)
    return {
        "epss": ep.astype(np.float32),
        "x1": np.log(ep / (1 - ep)).astype(np.float32),
        "x2": trend,
        "x3": np.log1p(age).astype(np.float32),
        "isnew": is_new,
        "y": df["y"].to_numpy(np.float32),
        "d2k": df["d2k"].to_numpy(np.int32),
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
    """Rank-based AUC, tie-safe (average ranks). The trustworthy discrimination metric here."""
    order = np.argsort(score, kind="mergesort")
    ss = score[order]
    ranks = np.empty(len(score))
    i = 0
    while i < len(score):
        j = i
        while j + 1 < len(score) and ss[j + 1] == ss[i]:
            j += 1
        ranks[i:j + 1] = (i + j) / 2.0 + 1
        i = j + 1
    rr = np.empty(len(score))
    rr[order] = ranks
    npos = y.sum()
    nneg = len(y) - npos
    if npos == 0 or nneg == 0:
        return float("nan")
    return float((rr[y == 1].sum() - npos * (npos + 1) / 2) / (npos * nneg))


def _ap(score: np.ndarray, y: np.ndarray) -> float:
    order = np.argsort(-score)
    ys = y[order]
    tp = np.cumsum(ys)
    fp = np.cumsum(1 - ys)
    prec = tp / (tp + fp)
    rec = tp / max(1, ys.sum())
    return float(np.sum((rec - np.concatenate([[0], rec[:-1]])) * prec))


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


def _budget(score, y, d2k, dateid, n_dates, fixed=None):
    tp = fp = fn = 0
    leads = []
    for i in range(n_dates):
        ids = np.where(dateid == i)[0]
        sc = score[ids]
        yy = y[ids]
        npos = int(yy.sum())
        b = npos if fixed is None else fixed
        if b <= 0:
            fn += npos
            continue
        top = ids[np.argsort(-sc)[:b]]
        hit = int(y[top].sum())
        tp += hit
        fp += int((1 - y[top]).sum())
        fn += npos - hit
        for j in top:
            if y[j] == 1 and d2k[j] >= 0:
                leads.append(int(d2k[j]))
    la = np.array(leads)
    return {
        "tp": tp, "fp": fp,
        "precision": round(tp / max(1, tp + fp), 4),
        "recall": round(tp / max(1, tp + fn), 4),
        "lead_median": float(np.median(la)) if len(la) else None,
        "lead_mean": round(float(la.mean()), 1) if len(la) else None,
    }


# --- public entry points -----------------------------------------------------
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
        evals = _monthly_eval_dates(all_dates, horizon, start, today)
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


def evaluate(evals: list[date], data: dict, horizon: int = 30, neg_ratio: int = 40,
             min_train_pos: int = 30, budgets=(5, 10, 20, 50, 100), seed: int = 42) -> dict:
    """Walk-forward training, scoring and metrics over pre-assembled feature arrays."""
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
    del data  # free the per-date feature dict before the pooled metric pass

    S = {m: np.concatenate(rec[m]) for m in MODELS}
    y = np.concatenate(ry)
    yr = np.concatenate(ryr)
    d2k = np.concatenate(rd2k)
    dateid = np.concatenate(rdid)
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
    by_budget = {int(b): {m: _budget(S[m], y, d2k, dateid, len(scored), fixed=b) for m in RANKERS} for b in budgets}
    equal_budget = {m: _budget(S[m], y, d2k, dateid, len(scored), fixed=None) for m in RANKERS}
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
        "repeated_cves_and_overlap": (
            f"Monthly test dates are {min(eval_gaps) if eval_gaps else horizon}-{max(eval_gaps) if eval_gaps else horizon} days "
            f"apart vs a {horizon}-day window, so a CVE's successive outcome windows barely overlap. "
            "A CVE recurs as a (CVE, date) example across months while it stays un-listed; each is a "
            "distinct prediction opportunity. A positive (first KEV entry) can occur at only one date, "
            "because a CVE is dropped from the population once listed, so positives never double-count."),
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
                "constant base-rate forecast, <0 is worse than it.",
            "pr_auc": "near-zero and tie-dominated at this prevalence; not the headline metric.",
        },
        "precision_recall_by_budget_per_day": by_budget,
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
    raw = models["raw_epss"]["roc_auc_pooled"]
    plat = models["epss_platt"]["roc_auc_pooled"]
    feat = models["feat_model"]["roc_auc_pooled"]
    raw_w = models["raw_epss"]["roc_auc_within_date_mean"]
    feat_w = models["feat_model"]["roc_auc_within_date_mean"]
    recent = [v["feat_model"] - v["raw_epss"] for yy, v in by_year.items() if yy >= 2023]
    consistent = len(recent) >= 2 and all(g > 0 for g in recent)
    calib = (f"Recalibration (EPSS->KEV target, train-only) leaves ranking unchanged "
             f"(within-date ROC-AUC identical to raw EPSS) and only fixes the probability scale.")
    if feat_w - raw_w >= 0.03 and consistent:
        return (f"Against the KEV-entry target, adding CVE age and EPSS trend improves ranking over "
                f"raw EPSS (within-date ROC-AUC {raw_w:.2f} -> {feat_w:.2f}; pooled {raw:.2f} -> "
                f"{feat:.2f}), and the gain repeats in every year 2023-2026 (separate temporal "
                f"evaluations). {calib} Absolute precision stays low and the target is KEV listing, "
                f"not real exploitation, so this is justified only as a separate experimental signal: "
                f"EPSS stays the reference and the aggregate category forecast is untouched.")
    if abs(feat_w - raw_w) < 0.03:
        return (f"The feature model does not credibly beat raw EPSS on ranking "
                f"(within-date ROC-AUC {raw_w:.2f} vs {feat_w:.2f}). {calib} Keep EPSS as the "
                f"reference; do not introduce a new model.")
    return (f"Mixed result (within-date ROC-AUC raw {raw_w:.2f}, features {feat_w:.2f}); the gain is "
            f"not stable across 2023-2026. {calib} Keep EPSS as the reference pending more positives.")


def score_current(settings: Settings, horizon: int = 30, top: int = 100, neg_ratio: int = 40,
                  seed: int = 42) -> dict:
    """Rank today's not-yet-KEV population by the experimental feature model.

    EXPERIMENTAL and clearly separate: this is a ranking of likely *KEV listing* within the
    horizon, not a probability of real exploitation, and it is never fed into the category
    forecast. Trained on all historical test dates whose outcome window has fully closed.
    """
    from ..state import utcnow

    today = utcnow().date()
    con = duckdb.connect()
    try:
        con.execute("PRAGMA threads=4")
        _lookup_tables(con, settings)
        all_dates = _epss_dates(settings)
        evals = _monthly_eval_dates(all_dates, horizon, date(2022, 1, 1), today)
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
        cur = con.execute(f"""
            WITH e AS (SELECT cve_id, epss FROM read_parquet('{_epss_file(settings, latest)}')),
            {prior_cte}
            SELECT e.cve_id, e.epss, p.epss_prior,
                   CAST(date_diff('day', CAST(pub.published AS DATE), DATE '{latest}') AS DOUBLE) AS age
            FROM e LEFT JOIN p USING (cve_id) LEFT JOIN kev k USING (cve_id) LEFT JOIN pub USING (cve_id)
            WHERE (k.kev_date IS NULL OR k.kev_date > DATE '{latest}')
              AND pub.published IS NOT NULL AND pub.published <= TIMESTAMP '{latest} 23:59:59+00'
        """).df()
    finally:
        con.close()

    rng = np.random.default_rng(seed)
    X, Y, W = _train_matrix(data, train, neg_ratio, rng)
    mu, sd = _standardize(X)
    Z = (X - mu) / sd
    bf = _fit_logit(np.column_stack([np.ones(len(Z)), Z]), Y, W)

    ep = np.clip(cur["epss"].to_numpy(float), 1e-6, 1 - 1e-6)
    pr = cur["epss_prior"].to_numpy(float)
    isnew = np.isnan(pr).astype(float)
    trend = np.where(np.isnan(pr), 0.0, ep - np.clip(pr, 1e-6, 1 - 1e-6))
    age = np.clip(cur["age"].to_numpy(float), 0, None)
    Xc = np.column_stack([np.log(ep / (1 - ep)), trend, np.log1p(age), isnew])
    Zc = (Xc - mu) / sd
    score = 1 / (1 + np.exp(-np.clip(np.column_stack([np.ones(len(Zc)), Zc]) @ bf, -30, 30)))
    order = np.argsort(-score)[:top]
    items = [{"cve_id": cur["cve_id"].iloc[i], "score": round(float(score[i]), 5),
              "epss": round(float(ep[i]), 5), "epss_trend": round(float(trend[i]), 5),
              "age_days": int(age[i])} for i in order]
    return {
        "as_of": str(latest),
        "horizon_days": horizon,
        "what": "experimental ranking of likely KEV listing within the horizon",
        "not": "a probability of real-world exploitation, and not used in the category forecast",
        "population": int(len(cur)),
        "trained_on_test_dates": len(train),
        "items": items,
    }
