"""The watchlist: an OPTIONAL personalization, separate from the global observatory.

The observatory ranks vulnerabilities globally by the experimental score, which predicts a CVE's
ENTRY INTO THE KEV CATALOGUE within the horizon — not the compromise of your environment. The
watchlist does not change that score or the model. It is a separate lens that says which systems
matter to you, so alerts can be grouped into explainable priority bands.

Three dimensions are kept DISTINCT and never multiplied into one number:
  - experimental score  — measured (probability of KEV listing);
  - impact              — declared by you (high / medium / low / not_used), else UNKNOWN;
  - exposure            — declared by you (internet / internal), else UNKNOWN.

Crucially, "not_used" (you told us it is not in your environment) is different from "unknown"
(you have not said). Anything you have not declared is treated as UNKNOWN — never as low impact —
and surfaced in a separate "needs classification" track, because we must not guess that it does not
matter. When no watchlist is present the overlay is inactive and nothing changes.
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import Settings

_TAXONOMY = Path(__file__).with_name("taxonomy") / "categories.json"
_IMPACT_ORDER = {"high": 3, "medium": 2, "low": 1}  # for picking the strongest declared impact
_IMPACT_LEVELS = set(_IMPACT_ORDER) | {"not_used"}
_EXPOSURE_LEVELS = {"internet", "internal"}


def _valid_category_ids() -> set[str]:
    try:
        d = json.loads(_TAXONOMY.read_text(encoding="utf-8"))
        return {c["id"] for c in d.get("technology_categories", [])}
    except (OSError, ValueError, KeyError):
        return set()


def _path(settings: Settings) -> Path:
    return Path(settings.data_dir) / "watchlist.json"


def _entry(raw: dict) -> dict:
    impact = raw.get("impact")
    exposure = raw.get("exposure")
    return {
        "impact": impact if impact in _IMPACT_LEVELS else "unknown",
        "exposure": exposure if exposure in _EXPOSURE_LEVELS else "unknown",
        "why": raw.get("why"),
    }


def load(settings: Settings) -> dict:
    """Load and validate the watchlist. Unknown category ids are reported, not silently dropped;
    an impact/exposure you did not give is recorded as 'unknown', never as low. `active` is False
    when no watchlist file is present."""
    path = _path(settings)
    if not path.exists():
        return {"active": False, "note": "no data/watchlist.json; see docs/IMPACT_SIZING.md and "
                "backend/app/watchlist.example.json. Optional: without it the observatory still "
                "ranks globally, it just cannot say which vulnerabilities matter to you.",
                "categories": {}, "products": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"active": False, "error": f"could not read watchlist.json: {exc}",
                "categories": {}, "products": {}}

    valid = _valid_category_ids()
    categories: dict[str, dict] = {}
    unknown_ids = []
    for e in raw.get("categories", []):
        cid = e.get("category_id")
        if cid not in valid:
            unknown_ids.append(cid)
            continue
        categories[cid] = _entry(e)
    products = {e["product"]: _entry(e) for e in raw.get("products", []) if e.get("product")}
    return {"active": bool(categories or products), "categories": categories, "products": products,
            "unknown_category_ids": unknown_ids,
            "note": "Impact and exposure are declared here and kept separate from the "
                    "exploitation-probability score; they are never multiplied into one number. "
                    "Undeclared items are UNKNOWN, not low impact; 'not_used' means excluded."}


# --- explainable priority bands (no arithmetic fusion) ---------------------------------------
_BAND_ORDER = ["priority_1_high_impact", "priority_2_medium_impact", "priority_3_low_impact",
               "needs_classification", "set_aside"]
_EXPOSURE_RANK = {"internet": 0, "internal": 1, "unknown": 2}


def _combine_impact(statuses: list[str]) -> str:
    """Impact of a CVE from the impact of the categories it touches. The strongest declared impact
    wins; if none is declared but something is unknown, the CVE is UNKNOWN (not low); only if every
    touched category is explicitly not_used is it set aside. No category at all -> unknown."""
    declared = [s for s in statuses if s in _IMPACT_ORDER]
    if declared:
        return max(declared, key=lambda s: _IMPACT_ORDER[s])
    if any(s == "unknown" for s in statuses) or not statuses:
        return "unknown"
    return "not_used"  # all touched categories explicitly not used


def _combine_exposure(exps: list[str]) -> str:
    if "internet" in exps:
        return "internet"
    if "internal" in exps:
        return "internal"
    return "unknown"


def _band(impact: str) -> tuple[str, str]:
    return {
        "high": ("priority_1_high_impact", "touches a category you marked high impact"),
        "medium": ("priority_2_medium_impact", "touches a category you marked medium impact"),
        "low": ("priority_3_low_impact", "touches a category you marked low impact"),
        "unknown": ("needs_classification", "impact not declared — unknown, classify before judging"),
        "not_used": ("set_aside", "all affected categories marked not used in your environment"),
    }[impact]


def prioritized_alerts(settings: Settings, horizon: int = 30, top: int = 100,
                       bands: str | None = None, exposure: str | None = None) -> dict:
    """Group the experimental CVE alerts into explainable priority bands using your watchlist,
    keeping the experimental score, impact and exposure as three separate columns. Optional
    `bands` (comma list) and `exposure` filters. A separate, optional view — the probability model
    and the prospective comparison are untouched."""
    from .analysis import epss_experiment as ex
    from .queries import _category_pairs, _rows

    wl = load(settings)
    if not wl["active"]:
        return {"active": False, "optional": True, "note": wl.get("note") or wl.get("error"),
                "horizon_days": horizon, "bands": {}, "items": []}

    pred = ex.score_current(settings, horizon=horizon, top=max(top, 300))
    scored = {it["cve_id"]: it for it in pred["items"]}
    cve_ids = list(scored)

    cats: dict[str, list[str]] = {}
    pairs = _category_pairs(settings)
    if pairs and cve_ids:
        sql, params = pairs
        rows = _rows(f"SELECT DISTINCT cve_id, category FROM {sql} WHERE category <> 'unmapped' "
                     f"AND cve_id IN ?", params + [cve_ids])
        for r in rows:
            cats.setdefault(r["cve_id"], []).append(r["category"])

    want_bands = set(b.strip() for b in bands.split(",")) if bands else None
    items = []
    band_counts = {b: 0 for b in _BAND_ORDER}
    for cve, it in scored.items():
        cve_cats = cats.get(cve, [])
        imp_statuses = [wl["categories"].get(c, {}).get("impact", "unknown") for c in cve_cats] or ["unknown"]
        exp_statuses = [wl["categories"].get(c, {}).get("exposure", "unknown") for c in cve_cats]
        impact = _combine_impact(imp_statuses)
        expo = _combine_exposure(exp_statuses)
        band, reason = _band(impact)
        band_counts[band] += 1
        items.append({
            "cve_id": cve,
            "experimental_score": it["score"],   # measured: probability of KEV listing (not of a
                                                 # compromise of your environment)
            "epss": it["epss"],
            "categories": cve_cats,
            "impact": impact,                    # declared by you, else unknown
            "exposure": expo,                    # declared by you, else unknown
            "band": band, "band_reason": reason,
        })

    if want_bands:
        items = [d for d in items if d["band"] in want_bands]
    if exposure:
        items = [d for d in items if d["exposure"] == exposure]
    # Sort by band, then internet-exposed first, then the experimental score. Each stays a separate,
    # visible column; the order is these three keys in sequence, not a product of them.
    items.sort(key=lambda d: (_BAND_ORDER.index(d["band"]), _EXPOSURE_RANK[d["exposure"]],
                              -d["experimental_score"]))
    return {
        "active": True, "optional": True,
        "horizon_days": horizon,
        "what": "experimental alerts grouped into explainable priority bands by your watchlist; "
                "experimental score, impact and exposure are separate dimensions, never multiplied",
        "score_means": "probability of entry into the KEV catalogue within the horizon — NOT the "
                       "probability that your environment is compromised",
        "band_order": _BAND_ORDER,
        "band_meaning": {
            "priority_1_high_impact": "affected category marked high impact by you",
            "priority_2_medium_impact": "marked medium impact",
            "priority_3_low_impact": "marked low impact",
            "needs_classification": "impact not declared — UNKNOWN, not low; classify to judge",
            "set_aside": "all affected categories marked not used in your environment",
        },
        "bands": band_counts,
        "filters_applied": {"bands": sorted(want_bands) if want_bands else None, "exposure": exposure},
        "items": items[:top],
    }
