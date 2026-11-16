"""A global observatory overview: one read-only view that keeps three kinds of information apart
and never mixes them.

  - OBSERVED FACTS      — what the record confirms (entry into CISA KEV), and, separately, any
                          documented consequences of incidents;
  - PREDICTIONS         — the model's estimate of KEV listing within a horizon (not of a
                          compromise, not of consequences);
  - EMERGING SIGNALS    — unvalidated early hints (scanning, news activity), kept as flags.

Every block carries its provenance and freshness, and the overview ends with an explicit list of
what is NOT collected. It composes existing queries only: it introduces no model, changes nothing
about the candidate under evaluation, and never fuses signals. In particular it does not infer a
"catastrophic" impact from technical scores, scanning or the number of news articles — article
volume is attention, not impact, and is labelled as such.
"""

from __future__ import annotations

from .config import Settings
from .sources import SOURCES


def _latest(settings: Settings, source: str):
    snaps = SOURCES[source].snapshot_dates(settings) if source in SOURCES else []
    return snaps[-1] if snaps else None


def _safe(fn):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - one broken block must not sink the overview
        return {"unavailable": f"{type(exc).__name__}: {exc}"}


def overview(settings: Settings, horizon: int = 30) -> dict:
    from . import queries
    from .analysis import exploitation
    from .state import utcnow

    today = utcnow().date()
    kev_as_of = _latest(settings, "kev")
    epss_as_of = _latest(settings, "epss")
    scans_as_of = _latest(settings, "scans")
    news_as_of = _latest(settings, "news")

    # --- OBSERVED FACTS --------------------------------------------------------------------
    def confirmed_exploitation():
        summ = queries.categories_summary(settings)
        by_cat = sorted(summ.get("items", []), key=lambda r: -(r.get("kev_cves") or 0))
        return {
            "source": "CISA KEV (Known Exploited Vulnerabilities)",
            "provenance": "catalogue retrieved from CISA; a listing is a confirmed-exploitation fact",
            "as_of_catalogue_retrieved": str(kev_as_of),
            "timeline_monthly": queries.kev_timeline(settings).get("items", []),
            "by_category": [{"category": r["category"], "kev_cves": r.get("kev_cves"),
                             "cves": r.get("cves"), "kev_share": r.get("kev_share")} for r in by_cat],
        }

    def documented_consequences():
        # We do NOT collect structured consequences (who was hit, downtime, data lost). What exists
        # is keyword-labelled event types reported in news — reported, partly inaccurate, and NOT an
        # impact measure. Shown separately and never used to infer severity.
        trend = queries.news_trend(settings, by="event_type", days=30)
        agg: dict[str, int] = {}
        for it in trend.get("items", []):
            if it.get("key"):
                agg[it["key"]] = agg.get(it["key"], 0) + int(it.get("stories") or 0)
        return {
            "status": "not systematically collected",
            "source": "news/advisories (reported, keyword-labelled, NOT verified)",
            "as_of": str(news_as_of),
            "reported_event_types_30d": dict(sorted(agg.items(), key=lambda kv: -kv[1])),
            "excludes_per_cve_feeds": trend.get("excluded_per_cve_feeds", []),
            "caveat": "reported event-type labels from news keyword rules (partly wrong); these are "
                      "NOT verified consequences and NOT a measure of impact or severity. Per-CVE "
                      "advisory feeds are excluded so counts reflect distinct reports, not CVE volume.",
        }

    # --- PREDICTIONS -----------------------------------------------------------------------
    def cve_to_watch():
        # Reuse the latest FROZEN daily snapshot from the prospective log instead of recomputing:
        # it is fast and keeps the overview consistent with what is actually being evaluated.
        from .analysis import prediction_log as pl

        snaps = pl._load_snapshots(settings, horizon)
        if snaps:
            latest = snaps[-1]
            items = sorted(latest.get("items", []), key=lambda it: -it.get("model_score", 0.0))[:20]
            return {
                "source": "experimental model (EPSS + CVE age), separate from the global ranking",
                "means": "probability of ENTRY INTO KEV within the horizon — NOT exploitation in the "
                         "wild and NOT a consequence",
                "issued_at": latest.get("issued_at"), "model_version": latest.get("model_version"),
                "horizon_days": horizon, "from": "frozen daily snapshot (prospective log)",
                "items": [{"cve_id": it["cve_id"], "score": it.get("model_score"), "epss": it.get("epss")}
                          for it in items],
            }
        return {"status": "no frozen snapshot yet",
                "note": "the daily prediction snapshot accumulates the frozen ranking; see "
                        "predictions/snapshot. Not recomputed live here to keep the overview fast."}

    def category_forecast():
        fc = exploitation.forecast(settings, horizon=max(horizon, 30))
        return {
            "source": "recent-rate baseline forecast (counts per category), not a model",
            "means": "expected number of category CVEs entering KEV in the window, with an interval",
            "generated_for": fc.get("generated_for"),
            "items": fc.get("items", []),
        }

    # --- EMERGING SIGNALS ------------------------------------------------------------------
    def scanning_pressure():
        surges = queries.scans_surges(settings)
        return {
            "source": "SANS ISC / DShield (aggregate scanning per port->category)",
            "as_of_observed": str(scans_as_of),
            "caveat": "a FLAG, not a prediction: the dedicated check (scan-signal-check / "
                      "scan-forecast-experiment) did NOT find that scanning leads exploitation; never "
                      "fused into the forecast. Historical values are retrospectively corrected.",
            "current_surges": surges.get("surges", []),
        }

    def news_activity():
        trend = queries.news_trend(settings, by="category", days=30)
        agg: dict[str, int] = {}
        for it in trend.get("items", []):
            if it.get("key"):
                agg[it["key"]] = agg.get(it["key"], 0) + int(it.get("stories") or 0)
        return {
            "source": "RSS feeds (official advisories + security + general press)",
            "as_of": str(news_as_of),
            "caveat": "article volume is ATTENTION, not impact; news history is short, so trends "
                      "over time are not yet meaningful (see news-readiness). Per-CVE advisory feeds "
                      "are excluded by default so this reflects attention, not CVE-advisory volume.",
            "excludes_per_cve_feeds": trend.get("excluded_per_cve_feeds", []),
            "stories_by_category_30d": dict(sorted(agg.items(), key=lambda kv: -kv[1])),
        }

    # --- provenance & freshness ------------------------------------------------------------
    freshness = []
    for name in sorted(SOURCES):
        latest = _latest(settings, name)
        freshness.append({"source": name, "latest_snapshot": str(latest) if latest else None,
                          "age_days": (today - latest).days if latest else None})

    return {
        "generated_at": utcnow().replace(microsecond=0).isoformat(),
        "distinct_by_design": "observed facts, predictions and emerging signals are separate and "
                              "never merged; impact/severity is not inferred from scores, scanning "
                              "or article counts.",
        "observed_events": {
            "kind": "confirmed facts",
            "confirmed_exploitation": _safe(confirmed_exploitation),
            "documented_consequences": _safe(documented_consequences),
        },
        "predictions": {
            "kind": "model estimates of KEV listing within the horizon (NOT consequences)",
            "cve_to_watch": _safe(cve_to_watch),
            "category_forecast": _safe(category_forecast),
        },
        "emerging_signals": {
            "kind": "unvalidated early signals, kept as flags (never fused)",
            "scanning_pressure": _safe(scanning_pressure),
            "news_activity": _safe(news_activity),
        },
        "provenance_and_freshness": freshness,
        "missing": [
            "Structured incident consequences (who was affected, downtime, data lost) and real "
            "severity are NOT collected; only KEV listing (a fact) and reported news event types.",
            "Confirmed exploitation comes only from CISA KEV; other sources (vendor confirmations, "
            "honeypots, telemetry) are not integrated, so coverage is partial and a minimum.",
            "News history is only a few days and not back-fillable, so change-over-time for news "
            "is not yet credible (readiness probe tracks when it will be).",
            "Scanning first-availability/revisions are retained only going forward; historical "
            "scan values are retrospectively corrected, so scanning trends are approximate.",
            "The experimental model predicts entry into KEV, not real-world exploitation and not "
            "consequences; it is a candidate under prospective evaluation, not a validated signal.",
        ],
    }
