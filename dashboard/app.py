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
PAGES = ["overview", "pipeline", "news", "kev", "epss"]

st.set_page_config(page_title="fucMonitor", page_icon="📈", layout="wide")


def api(method: str, path: str, **params):
    response = httpx.request(method, f"{API_URL}{path}", params=params or None, timeout=60)
    response.raise_for_status()
    return response.json()


def get(path: str, **params):
    return api("GET", path, **{k: v for k, v in params.items() if v not in (None, "")})


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
        config[c] = st.column_config.NumberColumn(t(f"col.{c}"), format="%.2f%%")
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
    data = get("/api/v1/overview")
    if data["kev_total"] is None and data["epss_total"] is None:
        st.info(t("common.no_data"))
        return

    def number(value) -> str:
        return "–" if value is None else f"{value:,}".replace(",", " ")

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

    timeline = get("/api/v1/kev/timeline")["items"]
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
        vendors = get("/api/v1/kev/vendors", limit=15)["items"]
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
            a.metric(t("overview.kev_epss_median"), "–" if median is None else f"{median:.1%}")
            b.metric(t("overview.kev_epss_high"), f"{ke['epss_ge_10pct'] / n:.0%}")
            a.metric(t("overview.kev_epss_low"), f"{ke['epss_lt_1pct'] / n:.0%}")
            b.metric(t("overview.kev_epss_missing"), number(n - ke["with_epss"]))
            st.caption(t("overview.kev_epss_help"))


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
        a, b, c = st.columns([2, 2, 1])
        start = a.date_input(t("pipeline.backfill_from"), today - timedelta(days=30), max_value=today)
        end = b.date_input(t("pipeline.backfill_to"), today - timedelta(days=1), max_value=today)
        c.write("")
        if c.button(t("pipeline.backfill_run")):
            try:
                out = api("POST", "/api/v1/sources/epss/backfill", start=str(start), end=str(end))
                st.toast(t("pipeline.backfill_started", n=out["days_to_download"]))
            except httpx.HTTPStatusError as exc:
                st.error(exc.response.json().get("detail", str(exc)))

    st.subheader(t("pipeline.history"))
    table(
        get("/api/v1/jobs", limit=100)["items"],
        ["source", "trigger", "status", "started_at", "finished_at", "snapshot_date", "rows", "changed", "message"],
    )


def page_news() -> None:
    st.header(t("nav.news"))
    any_value = t("news.any")
    a, b, c, d = st.columns([3, 1, 1, 1])
    search = a.text_input(t("news.search"))
    language = b.selectbox(t("news.language"), [any_value, "en", "it"])
    kind = c.selectbox(
        t("news.kind"), [any_value, "primary", "specialist", "general"],
        format_func=lambda k: k if k == any_value else t(f"kind.{k}"),
    )
    d.write("")
    only_cve = d.checkbox(t("news.only_cve"))
    data = get(
        "/api/v1/news", limit=500, search=search.strip(),
        language=None if language == any_value else language,
        kind=None if kind == any_value else kind,
        has_cve="true" if only_cve else None,
    )
    feeds = get("/api/v1/news/feeds")["items"]
    if data["total"] == 0 and not any(f["last_fetch_at"] for f in feeds):
        st.info(t("common.no_data"))
        return
    st.caption(t("news.count", n=data["total"]))
    table(
        data["items"],
        ["published_at", "feed_title", "language", "title", "cve_ids", "link", "summary", "first_seen_at"],
        links=("link",),
    )
    st.caption(t("news.help"))

    st.subheader(t("news.feeds"))
    active = [f for f in feeds if f["enabled"]]
    failing = [f for f in active if f["last_status"] == "failed"]
    st.caption(t("news.feeds_summary", ok=len(active) - len(failing), n=len(active)))
    table(
        feeds,
        ["title", "kind", "language", "enabled", "last_status", "last_fetch_at", "items_new", "total_items",
         "consecutive_failures", "last_message"],
    )


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


{"overview": page_overview, "pipeline": page_pipeline, "news": page_news, "kev": page_kev, "epss": page_epss}[page]()
