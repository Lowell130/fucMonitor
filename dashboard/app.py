"""Thin development dashboard. It talks to the API only and never reads data files.

Every visible string comes from locales/*.json. Add keys to en.json first, then it.json.
"""

import os
import re
from datetime import date, timedelta

import altair as alt
import httpx
import pandas as pd
import streamlit as st

from i18n import LANGUAGES, translate

API_URL = os.environ.get("FUC_API_URL", "http://localhost:8000").rstrip("/")
PAGES = ["overview", "forecast", "scans", "pipeline", "news", "vulns", "categories", "kev", "epss"]

st.set_page_config(page_title="fucMonitor", page_icon="📈", layout="wide")


def api(method: str, path: str, json: dict | None = None, **params):
    response = httpx.request(method, f"{API_URL}{path}", params=params or None, json=json, timeout=60)
    response.raise_for_status()
    return response.json()


def get(path: str, **params):
    return api("GET", path, **{k: v for k, v in params.items() if v not in (None, "")})


@st.cache_data(ttl=120, show_spinner=False)
def get_cached(path: str, **params):
    """For reads that scan the whole catalogue. Two minutes is short enough to follow a
    download in progress and long enough that a rerun does not recompute everything."""
    return get(path, **params)


# --- language and navigation ---------------------------------------------------
with st.sidebar:
    lang = st.selectbox(
        "Language / Lingua", list(LANGUAGES), format_func=LANGUAGES.get, key="lang"
    )


def t(key: str, **values) -> str:
    return translate(lang, key, **values)


def table(rows: list[dict], columns: list[str], percent: tuple[str, ...] = (), links: tuple[str, ...] = ()) -> None:
    frame = pd.DataFrame(rows, columns=columns)
    for col in frame.columns:
        if frame[col].map(lambda v: isinstance(v, list)).any():
            frame[col] = frame[col].map(lambda v: ", ".join(v) if isinstance(v, list) else v)
    config = {c: st.column_config.Column(t(f"col.{c}")) for c in columns}
    for c in percent:
        frame[c] = frame[c] * 100
        config[c] = st.column_config.NumberColumn(t(f"col.{c}"), format="%.3f%%")
    for c in links:
        frame[c] = frame[c].replace("", None)
        config[c] = st.column_config.LinkColumn(t(f"col.{c}"), display_text=t("common.open"))
    st.dataframe(frame, column_config=config, hide_index=True, width="stretch")


with st.sidebar:
    st.title(t("app.title"))
    st.caption(t("app.tagline"))
    page = st.radio(t("nav.label"), PAGES, format_func=lambda p: t(f"nav.{p}"))
    st.button(t("common.refresh"))
    st.caption(t("app.dev_notice"))

try:
    get("/health")
except httpx.HTTPError:
    st.error(t("app.api_down", url=API_URL))
    st.stop()


# --- pages ---------------------------------------------------------------------
def page_overview() -> None:
    st.header(t("nav.overview"))
    data = get_cached("/api/v1/overview")
    if data["kev_total"] is None and data["epss_total"] is None:
        st.info(t("common.no_data"))
        return

    names = labels("technology_categories")
    prio = get_cached("/api/v1/analysis/priority", horizon=90)
    forecast = prio["items"]
    if forecast:
        top = [f for f in forecast if f["expected"] > 0][:3]
        if top:
            st.subheader(t("overview.at_risk"))
            st.caption(t("overview.at_risk_help"))
            for column, row in zip(st.columns(len(top)), top):
                label = names.get(row["category"], row["category"])
                if row.get("elevated_scanning"):
                    label = "🔺 " + label
                column.metric(
                    label, f"{row['expected']:.1f}",
                    help=t("overview.at_risk_metric", low=row["low"], high=row["high"],
                           share=f"{row['share']:.1%}" if row["share"] is not None else "–"),
                )
            watch = [w for w in prio["watch"] if w["category"] not in {r["category"] for r in top}]
            if any(r.get("elevated_scanning") for r in top) or watch:
                parts = [names.get(w["category"], w["category"]) for w in prio["watch"]]
                st.caption("🔺 " + t("overview.scanning_note", cats=", ".join(parts)))
            st.caption(t("overview.at_risk_link"))

    st.subheader(t("overview.catalogue"))
    cols = st.columns(5)
    cols[0].metric(t("overview.kev_total"), number(data["kev_total"]))
    cols[1].metric(t("overview.kev_recent"), number(data["kev_added_last_30_days"]))
    cols[2].metric(t("overview.kev_ransomware"), number(data["kev_ransomware"]))
    cols[3].metric(t("overview.epss_total"), number(data["epss_total"]))
    cols[4].metric(t("overview.epss_high"), number(data["epss_high"]))
    st.caption(
        f"KEV: {t('common.as_of', date=data['kev_snapshot_date'] or '–')} · "
        f"EPSS: {t('common.as_of', date=data['epss_snapshot_date'] or '–')}"
    )

    timeline = get_cached("/api/v1/kev/timeline")["items"]
    if timeline:
        st.subheader(t("overview.timeline"))
        frame = pd.DataFrame(timeline)
        frame["month"] = pd.to_datetime(frame["month"])
        st.altair_chart(
            alt.Chart(frame)
            .mark_bar()
            .encode(
                x=alt.X("month:T", title=None),
                y=alt.Y("added:Q", title=None),
                tooltip=[alt.Tooltip("month:T", format="%Y-%m"), "added:Q"],
            ),
            width="stretch",
        )
        st.caption(t("overview.timeline_help"))

    left, right = st.columns(2)
    with left:
        vendors = get_cached("/api/v1/kev/vendors", limit=15)["items"]
        if vendors:
            st.subheader(t("overview.vendors"))
            table(vendors, ["vendor_project", "cves", "last_added"])
            st.caption(t("overview.vendors_help"))
    with right:
        ke = data["kev_epss"]
        if ke and ke["kev_cves"]:
            st.subheader(t("overview.kev_epss"))
            n = ke["kev_cves"]
            a, b = st.columns(2)
            median = ke["median_epss"]
            a.metric(t("overview.kev_epss_median"), "–" if median is None else percent(median))
            b.metric(t("overview.kev_epss_high"), f"{ke['epss_ge_10pct'] / n:.0%}")
            a.metric(t("overview.kev_epss_low"), f"{ke['epss_lt_1pct'] / n:.0%}")
            b.metric(t("overview.kev_epss_missing"), number(n - ke["with_epss"]))
            st.caption(t("overview.kev_epss_help"))


def page_forecast() -> None:
    st.header(t("nav.forecast"))
    names = labels("technology_categories")
    horizon = st.radio(t("forecast.horizon"), [30, 90, 365],
                       format_func=lambda d: t("forecast.days", n=d), horizontal=True, index=1)
    data = get_cached("/api/v1/analysis/forecast", horizon=horizon)
    if not data["items"]:
        st.info(t("forecast.no_data"))
        return

    st.caption(t("forecast.method", horizon=horizon, lookback=data["lookback_days"] // 30))
    rows = [{**r, "label": names.get(r["category"], r["category"])} for r in data["items"]]
    frame = pd.DataFrame(rows)
    base = alt.Chart(frame).encode(
        y=alt.Y("label:N", title=None, sort="-x", axis=alt.Axis(labelLimit=260))
    )
    st.altair_chart(
        (base.mark_bar().encode(
            x=alt.X("expected:Q", title=t("forecast.axis", n=horizon)),
            tooltip=[alt.Tooltip("label:N", title=""), "expected:Q", "low:Q", "high:Q", "recent_cves:Q"])
         + base.mark_rule(strokeWidth=2, color="#888").encode(x="low:Q", x2="high:Q")),
        width="stretch",
    )
    table(rows, ["label", "expected", "low", "high", "recent_events", "recent_cves",
                 "share", "median_days", "last_exploited"], percent=("share",))
    st.caption(t("forecast.table_help"))

    st.subheader(t("forecast.accuracy"))
    scored = get_cached("/api/v1/analysis/backtest", horizon=horizon, step_days=30, points=24)
    if scored.get("methods"):
        best = scored["methods"][0]
        predicted = sum(e["predictions"].get("recent_rate_365", {}).get("expected", 0)
                        for e in scored["evaluations"])
        observed = scored["observed_total"]
        cols = st.columns(4)
        cols[0].metric(t("forecast.acc_error"), f"{best['mean_absolute_error']:.2f}")
        cols[1].metric(t("forecast.acc_coverage"), f"{best['interval_coverage']:.0%}")
        cols[2].metric(t("forecast.acc_bias"),
                       f"{(predicted - observed) / observed:+.0%}" if observed else "–")
        cols[3].metric(t("forecast.acc_points"), str(best["points"]))
        st.caption(t("forecast.acc_help", start=scored["from"], end=scored["to"]))
        table([{**m, "label": m["method"]} for m in scored["methods"]],
              ["label", "mean_absolute_error", "rmse", "interval_coverage", "points"])
        st.caption(t("forecast.acc_methods"))

    st.subheader(t("forecast.rates"))
    flat = []
    for item in get_cached("/api/v1/analysis/rates")["items"]:
        stats = item["horizons"].get(str(horizon))
        if stats and stats["eligible"]:
            flat.append({"label": names.get(item["category"], item["category"]),
                         "share": stats["share"], "share_low": stats["share_low"],
                         "share_high": stats["share_high"], "exploited": stats["exploited"],
                         "eligible": stats["eligible"], "median_days": stats["median_days"]})
    if flat:
        table(flat, ["label", "share", "share_low", "share_high", "exploited", "eligible", "median_days"],
              percent=("share", "share_low", "share_high"))
        st.caption(t("forecast.rates_help", n=horizon))

    st.subheader(t("forecast.speed"))
    speed = get_cached("/api/v1/analysis/time-to-exploit")["items"]
    if speed:
        table([{**r, "label": names.get(r["category"], r["category"])} for r in speed],
              ["label", "exploited", "median_days", "p25_days", "p75_days", "share_within_7", "share_within_30"],
              percent=("share_within_7", "share_within_30"))
        st.caption(t("forecast.speed_help"))

    with st.expander(t("forecast.limits")):
        st.markdown(t("forecast.limits_text"))


def page_scans() -> None:
    st.header(t("nav.scans"))
    st.caption(t("scans.intro"))
    names = labels("technology_categories")
    surges = get_cached("/api/v1/scans/surges", baseline_days=30, min_z=2.0)
    if not surges.get("all"):
        st.info(t("scans.no_data"))
        return

    flagged = surges["surges"]
    st.subheader(t("scans.surges"))
    if flagged:
        for row in flagged[:6]:
            cat = names.get(row["category"], row["category"])
            st.markdown(t("scans.surge_line", service=row["service"], port=row["port"],
                          category=cat, ratio=f"{row['ratio']:.1f}", z=f"{row['z']:.1f}"))
        st.caption(t("scans.surge_help"))
    else:
        st.success(t("scans.no_surge"))

    st.subheader(t("scans.trend"))
    watched = sorted({p["category"] for p in get_cached("/api/v1/scans/ports")["items"]})
    a, b = st.columns([1, 3])
    days = a.select_slider(t("scans.days"), [30, 90, 180, 365], value=90)
    shown = b.multiselect(t("scans.show"), watched, default=watched,
                          format_func=lambda k: names.get(k, k))
    data = [r for r in get_cached("/api/v1/scans/trend", by="category", days=days)["items"]
            if r["key"] in shown]
    if data:
        frame = pd.DataFrame(data)
        frame["day"] = pd.to_datetime(frame["day"])
        frame["label"] = frame["key"].map(lambda k: names.get(k, k))
        st.altair_chart(
            alt.Chart(frame).mark_line().encode(
                x=alt.X("day:T", title=None),
                y=alt.Y("value:Q", title=t("scans.axis")),
                color=alt.Color("label:N", title=None, legend=alt.Legend(orient="bottom", columns=2, labelLimit=260)),
                tooltip=[alt.Tooltip("day:T", format="%Y-%m-%d"), "label:N", "value:Q"],
            ),
            width="stretch",
        )
    st.caption(t("scans.trend_help"))

    st.subheader(t("scans.check"))
    check = get_cached("/api/v1/analysis/scan-signal-check", lead_days=30)
    verdict_key = {
        "scanning surges were followed by more exploitation": "scans.check_yes",
        "no lead found: surges were followed by less, not more": "scans.check_no",
        "no clear lead either way": "scans.check_flat",
        "too little history to tell yet": "scans.check_thin",
        "no data": "scans.check_thin",
    }.get(check.get("verdict"), "scans.check_thin")
    st.markdown("**" + t(verdict_key) + "**")
    if check.get("mean_after_elevated") is not None:
        cols = st.columns(3)
        cols[0].metric(t("scans.check_lift"), f"{check['lift']:.2f}×" if check.get("lift") else "–")
        cols[1].metric(t("scans.check_after_surge"), f"{check['mean_after_elevated']:.2f}")
        cols[2].metric(t("scans.check_normal"), f"{check['mean_after_normal']:.2f}")
    st.caption(t("scans.check_help", lead=check.get("lead_days", 30),
                 days=check.get("elevated_days", 0), events=check.get("events_after_elevated", 0)))

    with st.expander(t("scans.about")):
        st.markdown(t("scans.about_text"))


def page_pipeline() -> None:
    st.header(t("nav.pipeline"))
    info = get("/api/v1/sources")
    if info["scheduler_enabled"]:
        st.caption(
            t("pipeline.schedule", times=info["schedule_times_utc"], next=info["next_scheduled_run"] or "–")
            + " " + t("pipeline.schedule_news", minutes=info["news_interval_minutes"])
        )
    else:
        st.caption(t("pipeline.schedule_off"))

    for source in info["sources"]:
        with st.container(border=True):
            head, action = st.columns([5, 1])
            suffix = f" · {t('pipeline.running')}" if source["running"] else ""
            head.subheader(f"{source['title']}{suffix}")
            head.caption(f"{t('common.source')}: {source['homepage']}")
            if action.button(t("pipeline.run"), key=f"run-{source['name']}", disabled=source["running"]):
                try:
                    api("POST", f"/api/v1/sources/{source['name']}/run")
                    st.toast(t("pipeline.started", source=source["name"]))
                except httpx.HTTPStatusError:
                    st.toast(t("pipeline.busy", source=source["name"]))
            last = source["last_run"]
            cols = st.columns(5)
            cols[0].metric(t("pipeline.snapshots"), source["snapshots"])
            cols[1].metric(t("pipeline.latest"), source["latest_snapshot_date"] or "–")
            age = source["latest_snapshot_age_days"]
            cols[2].metric(t("pipeline.age"), "–" if age is None else age)
            rows = source["latest_rows"]
            cols[3].metric(t("pipeline.rows"), "–" if rows is None else f"{rows:,}".replace(",", " "))
            cols[4].metric(t("pipeline.last_run"), last["status"] if last else t("pipeline.never"))
            if last and last["status"] == "failed":
                st.error(last["message"])

    with st.expander(t("pipeline.backfill")):
        st.caption(t("pipeline.backfill_help"))
        today = date.today()
        a, b, c, d = st.columns([2, 2, 2, 1])
        start = a.date_input(t("pipeline.backfill_from"), today - timedelta(days=30),
                             min_value=date(2021, 4, 14), max_value=today)
        end = b.date_input(t("pipeline.backfill_to"), today - timedelta(days=1),
                           min_value=date(2021, 4, 14), max_value=today)
        step_names = {1: t("pipeline.backfill_daily"), 7: t("pipeline.backfill_weekly")}
        step = c.radio(t("pipeline.backfill_step"), list(step_names),
                       format_func=step_names.get, horizontal=True)
        d.write("")
        if d.button(t("pipeline.backfill_run")):
            try:
                out = api("POST", "/api/v1/sources/epss/backfill",
                          start=str(start), end=str(end), step=step)
                st.toast(t("pipeline.backfill_started", n=out["days_to_download"]))
            except httpx.HTTPStatusError as exc:
                st.error(exc.response.json().get("detail", str(exc)))

    st.subheader(t("pipeline.history"))
    table(
        get("/api/v1/jobs", limit=100)["items"],
        ["source", "trigger", "status", "started_at", "finished_at", "snapshot_date", "rows", "changed", "message"],
    )


def percent(value: float) -> str:
    """EPSS runs to five decimals: 0.99999 is not 100%, and saying so would be wrong."""
    return f"{value * 100:.3f}".rstrip("0").rstrip(".") + "%"


def number(value) -> str:
    """Thin spaces as thousands separator: readable in both languages."""
    return "–" if value is None else f"{value:,}".replace(",", " ")


def labels(group: str) -> dict[str, str]:
    """Display labels for taxonomy IDs, in the current language."""
    return {entry["id"]: entry.get(lang) or entry["en"] for entry in get("/api/v1/taxonomy").get(group, [])}


def page_news() -> None:
    st.header(t("nav.news"))
    events, sectors, claims = labels("event_types"), labels("target_sectors"), labels("claim_statuses")
    any_value = t("news.any")

    def choice(column, label: str, options: dict[str, str]) -> str | None:
        picked = column.selectbox(label, [any_value, *options], format_func=lambda k: options.get(k, k))
        return None if picked == any_value else picked

    a, b, c = st.columns([2, 1, 1])
    search = a.text_input(t("news.search"))
    event = choice(b, t("news.event"), events)
    sector = choice(c, t("news.sector"), sectors)
    a, b, c, d = st.columns(4)
    claim = choice(a, t("news.claim"), claims)
    kind = choice(b, t("news.kind"), {k: t(f"kind.{k}") for k in ("primary", "specialist", "general")})
    language = choice(c, t("news.language"), {"en": "English", "it": "Italiano"})
    only_cve = d.checkbox(t("news.only_cve"))
    only_exploited = d.checkbox(t("news.only_exploited"))
    collapse = d.checkbox(t("news.collapse"), value=True)

    data = get(
        "/api/v1/news", limit=500, search=search.strip(), event_type=event, sector=sector,
        claim_status=claim, kind=kind, language=language,
        has_cve="true" if only_cve else None, exploited="true" if only_exploited else None,
        collapse="true" if collapse else None,
    )
    feeds = get("/api/v1/news/feeds")["items"]
    if data["total"] == 0 and not any(f["last_fetch_at"] for f in feeds):
        st.info(t("common.no_data"))
        return
    st.caption(t("news.count_stories", n=data["total"]) if collapse else t("news.count", n=data["total"]))
    rows = [
        {**item,
         "event_type": events.get(item["event_type"], item["event_type"]),
         "claim_status": claims.get(item["claim_status"], item["claim_status"]),
         "target_sectors": [sectors.get(x, x) for x in item["target_sectors"] or []]}
        for item in data["items"]
    ]
    table(
        rows,
        ["published_at", "feed_title", "title", "event_type", "claim_status", "target_sectors",
         "exploitation_signal", "story_feeds", "cve_ids", "link", "summary", "language", "first_seen_at"],
        links=("link",),
    )
    st.caption(t("news.help"))

    st.subheader(t("news.trend"))
    a, b, c = st.columns([1, 1, 2])
    by = a.radio(t("news.trend_by"), ["event_type", "sector"], format_func=lambda k: t(f"news.by_{k}"), horizontal=True)
    days = b.select_slider(t("news.trend_days"), [7, 14, 30, 90], value=14)
    names = events if by == "event_type" else sectors
    quiet = [k for k in ("vulnerability_disclosure", "other") if k in names] if by == "event_type" else []
    shown = c.multiselect(
        t("news.trend_show"), list(names), default=[k for k in names if k not in quiet],
        format_func=lambda k: names.get(k, k),
    )
    trend = [r for r in get("/api/v1/news/trend", by=by, days=days)["items"] if r["key"] in shown]
    if trend:
        frame = pd.DataFrame(trend)
        frame["day"] = pd.to_datetime(frame["day"])
        frame["label"] = frame["key"].map(lambda k: names.get(k, k))
        st.altair_chart(
            alt.Chart(frame)
            .mark_bar()
            .encode(
                x=alt.X("yearmonthdate(day):O", title=None, axis=alt.Axis(format="%d %b", labelAngle=0)),
                y=alt.Y("stories:Q", title=t("news.trend_axis")),
                color=alt.Color("label:N", title=None, legend=alt.Legend(orient="bottom", columns=2, labelLimit=400)),
                tooltip=[alt.Tooltip("day:T", format="%Y-%m-%d"), "label:N", "stories:Q"],
            ),
            width="stretch",
        )
    else:
        st.info(t("news.trend_empty"))
    st.caption(t("news.trend_help"))

    st.subheader(t("news.feeds"))
    active = [f for f in feeds if f["enabled"]]
    failing = [f for f in active if f["last_status"] == "failed"]
    st.caption(t("news.feeds_summary", ok=len(active) - len(failing), n=len(active)))
    table(
        feeds,
        ["title", "kind", "language", "enabled", "last_status", "last_fetch_at", "items_new", "total_items",
         "consecutive_failures", "last_message"],
    )


def page_vulns() -> None:
    st.header(t("nav.vulns"))
    data = get_cached("/api/v1/nvd/overview")
    exploits = get("/api/v1/exploits/overview")
    if data["total"] is None and not exploits["cves"]:
        st.info(t("vulns.no_data"))
        return

    cols = st.columns(5)
    cols[0].metric(t("vulns.total"), number(data["total"]))
    cols[1].metric(t("vulns.with_cvss"), number(data["with_cvss"]))
    cols[2].metric(t("vulns.with_products"), number(data["with_products"]))
    cols[3].metric(t("vulns.with_exploit_ref"), number(data["with_exploit_reference"]))
    cols[4].metric(t("vulns.with_exploit_code"), number(exploits["cves"]))
    if data["retrieved_at"]:
        st.caption(t("vulns.as_of", date=data["retrieved_at"][:10]))

    if data["total"]:
        left, right = st.columns([3, 2])
        with left:
            st.subheader(t("vulns.by_year"))
            frame = pd.DataFrame([r for r in data["by_year"] if r["year"] >= 1999])
            st.altair_chart(
                alt.Chart(frame).mark_bar().encode(
                    x=alt.X("year:O", title=None, axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("cves:Q", title=None),
                    tooltip=["year:O", "cves:Q"],
                ),
                width="stretch",
            )
            st.caption(t("vulns.by_year_help"))
        with right:
            st.subheader(t("vulns.by_severity"))
            table(data["by_severity"], ["severity", "cves"])

        st.subheader(t("vulns.vendors"))
        a, b = st.columns([1, 3])
        since = a.select_slider(t("vulns.vendors_since"), [1999, 2018, 2024, 2026], value=2018)
        table(get_cached("/api/v1/nvd/vendors", limit=25, since_year=since)["items"], ["vendor", "cves", "products"])
        st.caption(t("vulns.vendors_help"))
    else:
        st.warning(t("vulns.nvd_missing"))

    if exploits["providers"]:
        st.subheader(t("vulns.providers"))
        table(exploits["providers"], ["provider", "entries", "cves", "last_seen"])

    st.subheader(t("vulns.lookup"))
    cve = st.text_input(t("vulns.lookup"), placeholder=t("epss.lookup_hint"), label_visibility="collapsed")
    cve = cve.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
        return
    profile = get(f"/api/v1/cve/{cve}")
    nvd, kev, epss = profile["nvd"], profile["kev"], profile["epss"]
    if not any((nvd, kev, epss, profile["exploits"], profile["news"])):
        st.warning(t("vulns.lookup_empty"))
        return
    cols = st.columns(5)
    cols[0].metric("CVSS", "–" if not nvd or nvd["cvss_score"] is None else f"{nvd['cvss_score']:.1f}")
    cols[1].metric("EPSS", "–" if not epss else percent(epss["epss"]))
    cols[2].metric(t("vulns.in_kev"), t("common.yes") if kev else t("common.no"))
    cols[3].metric(t("vulns.exploit_code"), str(len(profile["exploit_providers"])) if profile["exploit_providers"] else "–")
    cols[4].metric(t("vulns.mentions"), str(len(profile["news"])))
    if nvd:
        st.write(nvd["description"])
        facts = {
            t("col.published"): (nvd["published"] or "")[:10],
            t("col.cvss_severity"): nvd["cvss_severity"] or "–",
            t("col.attack_vector"): nvd["attack_vector"] or "–",
            t("col.cwes"): ", ".join(nvd["cwes"]) or "–",
            t("col.vuln_status"): nvd["vuln_status"] or "–",
            t("col.products"): ", ".join(nvd["products"][:12]) or "–",
        }
        st.dataframe(pd.DataFrame(facts.items(), columns=[t("vulns.field"), t("vulns.value")]),
                     hide_index=True, width="stretch")
    if kev:
        st.caption(t("vulns.kev_added", date=str(kev["date_added"]), ransomware=kev["known_ransomware_campaign_use"]))
    if profile["exploits"]:
        st.caption(t("vulns.exploits"))
        table(profile["exploits"], ["provider", "title", "reference_id", "provider_date", "reference_url", "first_seen_at"],
              links=("reference_url",))
    if profile["news"]:
        st.caption(t("vulns.news"))
        table(profile["news"], ["published_at", "feed_title", "title", "link"], links=("link",))


def page_categories() -> None:
    st.header(t("nav.categories"))
    names = labels("technology_categories")
    coverage = get_cached("/api/v1/categories/coverage")
    if not coverage["products"]:
        st.info(t("categories.no_data"))
        return

    def share(part: int, whole: int) -> str:
        return "–" if not whole else f"{part / whole:.0%}"

    cols = st.columns(4)
    cols[0].metric(t("categories.products"), f"{number(coverage['products_mapped'])} / {number(coverage['products'])}")
    cols[1].metric(t("categories.cves"), share(coverage["cves_mapped"], coverage["cves"]))
    cols[2].metric(t("categories.kev"), share(coverage["kev_cves_mapped"], coverage["kev_cves"]))
    cols[3].metric(t("categories.manual"), number(coverage["products_manual"]))
    st.caption(t("categories.coverage_help"))

    st.subheader(t("categories.summary"))
    a, _ = st.columns([1, 3])
    since = a.select_slider(t("vulns.vendors_since"), [1999, 2018, 2024, 2026], value=2018)
    rows = get_cached("/api/v1/categories/summary", since_year=since)["items"]
    if rows:
        frame = pd.DataFrame(rows)
        frame["label"] = frame["category"].map(lambda k: names.get(k, k))
        st.altair_chart(
            alt.Chart(frame).mark_bar().encode(
                x=alt.X("cves:Q", title=t("categories.axis")),
                y=alt.Y("label:N", title=None, sort="-x", axis=alt.Axis(labelLimit=260)),
                tooltip=[alt.Tooltip("label:N", title=""), "cves:Q", "kev_cves:Q"],
            ),
            width="stretch",
        )
        table([{**r, "category": names.get(r["category"], r["category"])} for r in rows],
              ["category", "cves", "kev_cves", "kev_share", "recent_cves", "last_published"],
              percent=("kev_share",))
        st.caption(t("categories.summary_help"))

    st.subheader(t("categories.queue"))
    st.caption(t("categories.queue_help"))
    queue = get("/api/v1/categories/products", assigned_by="unmapped", limit=50)
    if queue["total"]:
        st.caption(t("categories.queue_count", n=queue["total"]))
        table(queue["items"],
              ["product", "cve_count", "kev_count", "exploit_count", "recent_cve_count", "last_published"])
    else:
        st.success(t("categories.queue_empty"))

    st.subheader(t("categories.assign"))
    search = st.text_input(t("categories.search"), placeholder="fortinet")
    found = get("/api/v1/categories/products", search=search.strip(), limit=25) if search.strip() else queue
    options = [r["product"] for r in found["items"]]
    if not options:
        st.info(t("categories.none_found"))
        return
    a, b, c = st.columns([2, 2, 1])
    product = a.selectbox(t("categories.product"), options)
    current = next(r for r in found["items"] if r["product"] == product)
    category = b.selectbox(
        t("categories.category"), list(names),
        index=list(names).index(current["category"]) if current["category"] in names else 0,
        format_func=lambda k: names.get(k, k),
    )
    c.write("")
    if c.button(t("categories.save")):
        api("PUT", f"/api/v1/categories/products/{product}", json={"category": category})
        st.toast(t("categories.saved", product=product))
        st.rerun()
    st.caption(t("categories.assign_help", by=t(f"assigned.{current['assigned_by']}")))
    if current["assigned_by"] == "manual" and st.button(t("categories.clear")):
        api("DELETE", f"/api/v1/categories/products/{product}")
        st.toast(t("categories.cleared", product=product))
        st.rerun()


def page_kev() -> None:
    st.header(t("nav.kev"))
    search = st.text_input(t("kev.search"))
    data = get("/api/v1/kev", limit=500, search=search.strip())
    if data["snapshot_date"] is None:
        st.info(t("common.no_data"))
        return
    st.caption(f"{t('kev.count', n=data['total'])} · {t('common.as_of', date=data['snapshot_date'])}")
    table(
        data["items"],
        ["cve_id", "vendor_project", "product", "vulnerability_name", "date_added",
         "known_ransomware_campaign_use", "cwes", "short_description"],
    )


def page_epss() -> None:
    st.header(t("nav.epss"))
    limit = st.select_slider(t("epss.limit"), [50, 100, 250, 500, 1000], value=100)
    data = get("/api/v1/epss/top", limit=limit)
    if data["snapshot_date"] is None:
        st.info(t("common.no_data"))
        return
    st.subheader(t("epss.top"))
    st.caption(t("common.as_of", date=data["snapshot_date"]))
    table(data["items"], ["cve_id", "epss", "percentile", "in_kev"], percent=("epss", "percentile"))

    st.subheader(t("epss.lookup"))
    cve = st.text_input(t("epss.lookup"), placeholder=t("epss.lookup_hint"), label_visibility="collapsed")
    cve = cve.strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        items = get(f"/api/v1/epss/{cve}")["items"]
        if not items:
            st.warning(t("epss.lookup_empty"))
        elif len(items) == 1:
            table(items, ["score_date", "epss", "percentile", "model_version"], percent=("epss", "percentile"))
            st.caption(t("epss.lookup_one"))
        else:
            frame = pd.DataFrame(items)
            frame["score_date"] = pd.to_datetime(frame["score_date"])
            st.altair_chart(
                alt.Chart(frame)
                .mark_line(point=True)
                .encode(
                    x=alt.X("score_date:T", title=None),
                    y=alt.Y("epss:Q", title=t("col.epss"), axis=alt.Axis(format="%"), scale=alt.Scale(domain=[0, 1])),
                    tooltip=["score_date:T", alt.Tooltip("epss:Q", format=".2%"), "model_version:N"],
                ),
                width="stretch",
            )


{"overview": page_overview, "forecast": page_forecast, "scans": page_scans,
 "pipeline": page_pipeline, "news": page_news, "vulns": page_vulns,
 "categories": page_categories, "kev": page_kev, "epss": page_epss}[page]()
