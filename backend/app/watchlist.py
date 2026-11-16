"""The watchlist: which systems matter to THIS install, so global rankings can be turned into a
personal priority. It is the one thing the system cannot infer — it is about your environment, not
a property of any CVE — so it is supplied by you (data/watchlist.json), never invented.

Impact (what a compromise would cost you) and exploitation probability (what the model measures)
are kept as two separate dimensions. The overlay here ranks your alerts by probability x impact but
always shows both numbers; it never folds impact into the probability model, and when no watchlist
is present it changes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import Settings

_TAXONOMY = Path(__file__).with_name("taxonomy") / "categories.json"


def _valid_category_ids() -> set[str]:
    try:
        d = json.loads(_TAXONOMY.read_text(encoding="utf-8"))
        return {c["id"] for c in d.get("technology_categories", [])}
    except (OSError, ValueError, KeyError):
        return set()


def _path(settings: Settings) -> Path:
    return Path(settings.data_dir) / "watchlist.json"


def load(settings: Settings) -> dict:
    """Load and validate the watchlist. Reports unknown category ids rather than silently dropping
    them; returns `active: False` when no watchlist file is present."""
    path = _path(settings)
    if not path.exists():
        return {"active": False, "note": "no data/watchlist.json; see docs/IMPACT_SIZING.md and "
                "backend/app/watchlist.example.json. Without it the system ranks global "
                "vulnerabilities but cannot tell which ones matter to you.",
                "categories": {}, "products": {}, "weights": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"active": False, "error": f"could not read watchlist.json: {exc}",
                "categories": {}, "products": {}, "weights": {}}

    weights = raw.get("impact_weights") or {"low": 1, "medium": 2, "high": 4}
    valid = _valid_category_ids()
    categories: dict[str, dict] = {}
    unknown = []
    for entry in raw.get("categories", []):
        cid = entry.get("category_id")
        if cid not in valid:
            unknown.append(cid)
            continue
        categories[cid] = {"impact": entry.get("impact"),
                           "weight": float(weights.get(entry.get("impact"), 0)),
                           "why": entry.get("why")}
    products: dict[str, dict] = {}
    for entry in raw.get("products", []):
        p = entry.get("product")
        if not p:
            continue
        products[p] = {"impact": entry.get("impact"),
                       "weight": float(weights.get(entry.get("impact"), 0)),
                       "why": entry.get("why")}
    return {"active": bool(categories or products), "weights": weights,
            "categories": categories, "products": products,
            "unknown_category_ids": unknown,
            "note": "Impact is declared here and kept separate from the exploitation-probability "
                    "model; the overlay shows both and never fuses them."}


def category_weight(wl: dict, category_id: str) -> float:
    c = wl.get("categories", {}).get(category_id)
    return float(c["weight"]) if c else 0.0


def impact_alerts(settings: Settings, horizon: int = 30, top: int = 100) -> dict:
    """Re-rank the experimental CVE alerts by probability x impact, keeping probability and impact
    as separate columns. Only CVEs touching a watchlisted category get a non-zero impact; the rest
    stay visible with impact 0. A SEPARATE view — the probability model is untouched."""
    from .analysis import epss_experiment as ex
    from .queries import _category_pairs, _rows

    wl = load(settings)
    if not wl["active"]:
        return {"active": False, "note": wl.get("note") or wl.get("error"),
                "horizon_days": horizon, "items": []}

    pred = ex.score_current(settings, horizon=horizon, top=max(top, 200))
    scored = {it["cve_id"]: it for it in pred["items"]}
    cve_ids = list(scored)

    # categories for exactly these CVEs (one row per CVE-category)
    cats: dict[str, list[str]] = {}
    pairs = _category_pairs(settings)
    if pairs and cve_ids:
        sql, params = pairs
        rows = _rows(
            f"SELECT DISTINCT cve_id, category FROM {sql} WHERE category <> 'unmapped' "
            f"AND cve_id IN ?", params + [cve_ids])
        for r in rows:
            cats.setdefault(r["cve_id"], []).append(r["category"])

    items = []
    for cve, it in scored.items():
        cve_cats = cats.get(cve, [])
        weighted = [(c, category_weight(wl, c)) for c in cve_cats]
        best = max(weighted, key=lambda t: t[1], default=(None, 0.0))
        impact_w = best[1]
        items.append({
            "cve_id": cve,
            "probability_score": it["score"],   # measured by the model
            "epss": it["epss"],
            "categories": cve_cats,
            "impact_weight": impact_w,          # declared by you
            "impact_category": best[0] if impact_w > 0 else None,
            "priority": round(it["score"] * impact_w, 6),  # overlay = probability x impact
        })
    # rank by the overlay priority, then probability; both stay visible
    items.sort(key=lambda d: (-d["priority"], -d["probability_score"]))
    on_watch = [d for d in items if d["impact_weight"] > 0]
    return {
        "active": True,
        "horizon_days": horizon,
        "what": "experimental alerts re-ranked by probability x impact; probability and impact "
                "shown separately, never fused; the probability model is unchanged",
        "watchlisted_categories": sorted(wl["categories"]),
        "n_on_watchlist": len(on_watch),
        "items": items[:top],
    }
