import json
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app import queries, runner, state
from app.main import app
from app.sources import SOURCES
from app.sources.news import clean_text, parse_date, parse_feed

RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Sec</title>
<item><title>Acme gateway flaw CVE-2026-1234 exploited &amp; patched</title>
  <link>https://example.org/a</link><guid isPermaLink="false">a-1</guid>
  <pubDate>Wed, 11 Nov 2026 09:30:00 +0100</pubDate>
  <description><![CDATA[<p>Attackers use <b>cve-2026-1234</b> and CVE-2025-99999.</p><script>x()</script>]]></description></item>
<item><title>No guid here</title><link>https://example.org/b</link>
  <pubDate>not a date</pubDate><description>Plain text.</description></item>
<item><title>Bad link</title><link>javascript:alert(1)</link><guid>c-3</guid></item>
<item><description>nothing usable</description></item>
</channel></rss>""".encode()

ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Adv</title>
<entry><title type="html">Advisory &lt;b&gt;one&lt;/b&gt;</title><id>urn:adv:1</id>
  <link rel="self" href="https://example.org/self"/><link rel="alternate" href="https://example.org/adv1"/>
  <updated>2026-11-12T08:00:00Z</updated><summary>Fix for CVE-2026-0001.</summary></entry>
</feed>""".encode()

GENERAL = """<rss version="2.0"><channel>
<item><title>Allarme bomba in una scuola, istituto evacuato</title><link>https://example.org/g1</link><guid>g1</guid></item>
<item><title>Il derby finisce in parità</title><link>https://example.org/g2</link><guid>g2</guid></item>
</channel></rss>""".encode()


@pytest.fixture
def news(settings, tmp_path, monkeypatch):
    """A feeds file with three feeds and a fake upstream whose replies can be changed."""
    feeds = {
        "general_keywords": ["allarme bomba", "hacker"],
        "feeds": [
            {"id": "rss", "title": "Sec", "url": "https://feeds.test/rss", "language": "en", "kind": "specialist"},
            {"id": "atom", "title": "Adv", "url": "https://feeds.test/atom", "language": "en", "kind": "primary"},
            {"id": "gen", "title": "Gen", "url": "https://feeds.test/gen", "language": "it", "kind": "general"},
            {"id": "off", "title": "Off", "url": "https://feeds.test/off", "language": "en", "kind": "primary", "enabled": False},
        ],
    }
    path = tmp_path / "feeds.json"
    path.write_text(json.dumps(feeds))
    settings.news_feeds_file = path
    upstream = {"rss": RSS, "atom": ATOM, "gen": GENERAL, "requests": []}

    def handler(request: httpx.Request) -> httpx.Response:
        name = request.url.path.strip("/")
        upstream["requests"].append((name, request.headers.get("if-none-match")))
        body = upstream.get(name)
        if isinstance(body, int):
            return httpx.Response(body)
        if request.headers.get("if-none-match") == f'"{name}-v1"' and not upstream.get(f"{name}_changed"):
            return httpx.Response(304)
        return httpx.Response(200, content=body, headers={"ETag": f'"{name}-v1"'})

    return settings, upstream, httpx.Client(transport=httpx.MockTransport(handler))


def test_parsing_helpers():
    assert clean_text("<p>A &amp;amp; B</p>\n<br/> c", 50) == "A & B c"
    assert clean_text("x" * 50, 10) == "x" * 9 + "…"
    assert parse_date("Wed, 11 Nov 2026 09:30:00 +0100") == datetime(2026, 11, 11, 8, 30, tzinfo=timezone.utc)
    assert parse_date("2026-11-12T08:00:00Z") == datetime(2026, 11, 12, 8, tzinfo=timezone.utc)
    assert parse_date("2026-11-12T08:00:00") == datetime(2026, 11, 12, 8, tzinfo=timezone.utc)
    assert parse_date("garbage") is None and parse_date(None) is None
    assert len(parse_feed(RSS)) == 4 and len(parse_feed(b"\xef\xbb\xbf\n" + ATOM)) == 1
    with pytest.raises(ValueError):
        parse_feed(b'<!DOCTYPE x [<!ENTITY a "b">]><rss/>')


def test_collects_normalises_and_filters(news):
    settings, upstream, client = news
    run = runner.run_source(settings, "news", client=client)
    assert run["status"] == "success", run["message"]
    assert run["rows"] == 5 and "feeds ok 3/3" in run["message"]
    assert "off" not in [name for name, _ in upstream["requests"]]

    items = {i["title"]: i for i in queries.news_list(settings, 50, 0, None, None, None, None, None, None)["items"]}
    assert len(items) == 5 and "Il derby finisce in parità" not in items

    first = items["Acme gateway flaw CVE-2026-1234 exploited & patched"]
    assert first["cve_ids"] == ["CVE-2025-99999", "CVE-2026-1234"]
    assert first["published_at"] == "2026-11-11T08:30:00Z" and first["first_seen_at"].endswith("Z")
    assert first["summary"] == "Attackers use cve-2026-1234 and CVE-2025-99999. x()"
    assert first["source_kind"] == "specialist" and first["language"] == "en"

    assert items["No guid here"]["published_at"] is None
    assert items["Bad link"]["link"] == ""  # only http(s) links are kept
    assert items["Advisory one"]["link"] == "https://example.org/adv1"
    assert items["Advisory one"]["published_at"] == "2026-11-12T08:00:00Z"
    assert items["Allarme bomba in una scuola, istituto evacuato"]["source_kind"] == "general"


def test_second_run_adds_nothing_and_uses_etags(news):
    settings, upstream, client = news
    runner.run_source(settings, "news", client=client)
    upstream["requests"].clear()
    again = runner.run_source(settings, "news", client=client)
    assert again["status"] == "success" and again["rows"] == 0 and again["changed"] is False
    assert sorted(upstream["requests"]) == [("atom", '"atom-v1"'), ("gen", '"gen-v1"'), ("rss", '"rss-v1"')]

    # The feed changes: one new entry next to the old ones. Only the new one is stored.
    upstream["rss_changed"] = True
    upstream["rss"] = RSS.replace(
        b"</channel>", b"<item><title>Fresh</title><link>https://example.org/new</link><guid>n-9</guid></item></channel>"
    )
    third = runner.run_source(settings, "news", client=client)
    assert third["rows"] == 1
    assert queries.news_list(settings, 50, 0, None, None, None, None, None, None)["total"] == 6
    assert len(SOURCES["news"].snapshot_dates(settings)) == 1
    rss_state = state.feed_states(settings.state_db)["rss"]
    assert rss_state["total_items"] == 4 and rss_state["items_new"] == 1


def test_one_broken_feed_does_not_stop_the_others(news):
    settings, upstream, client = news
    upstream["atom"] = 500
    upstream["gen"] = b"<html>not a feed"
    run = runner.run_source(settings, "news", client=client)
    assert run["status"] == "success" and run["rows"] == 3
    assert "feeds ok 1/3" in run["message"] and "failed: atom, gen" in run["message"]
    states = state.feed_states(settings.state_db)
    assert states["atom"]["last_status"] == "failed" and "500" in states["atom"]["last_message"]
    assert states["gen"]["consecutive_failures"] == 1 and states["rss"]["last_status"] == "ok"

    upstream["atom"] = ATOM
    runner.run_source(settings, "news", client=client)
    assert state.feed_states(settings.state_db)["atom"]["consecutive_failures"] == 0


def test_all_feeds_failing_is_a_failed_run(news):
    settings, upstream, client = news
    upstream.update(rss=503, atom=503, gen=503)
    run = runner.run_source(settings, "news", client=client)
    assert run["status"] == "failed" and "all 3 feeds failed" in run["message"]
    assert SOURCES["news"].snapshot_dates(settings) == []


def test_news_api(news):
    settings, upstream, client = news
    with TestClient(app) as api:
        assert api.get("/api/v1/news").json() == {"total": 0, "items": []}
        assert api.get("/api/v1/news/daily").json() == {"items": []}
        feeds = api.get("/api/v1/news/feeds").json()["items"]
        assert [f["id"] for f in feeds] == ["rss", "atom", "gen", "off"]
        assert feeds[0]["last_status"] is None and feeds[3]["enabled"] is False

        runner.run_source(settings, "news", client=client)
        assert api.get("/api/v1/news", params={"has_cve": True}).json()["total"] == 2
        assert api.get("/api/v1/news", params={"search": "cve-2026-0001"}).json()["total"] == 1
        assert api.get("/api/v1/news", params={"kind": "general", "language": "it"}).json()["total"] == 1
        assert api.get("/api/v1/news", params={"feed": "rss", "limit": 2}).json()["total"] == 3
        today = state.utcnow().date().isoformat()
        assert api.get("/api/v1/news", params={"since": today}).json()["total"] == 5
        assert api.get("/api/v1/news", params={"since": "2099-01-01"}).json()["total"] == 0
        daily = api.get("/api/v1/news/daily").json()["items"]
        assert {(d["seen_date"], d["source_kind"], d["items"], d["with_cve"]) for d in daily} == {
            (today, "general", 1, 0), (today, "primary", 1, 1), (today, "specialist", 3, 1)}
        feeds = {f["id"]: f for f in api.get("/api/v1/news/feeds").json()["items"]}
        assert feeds["rss"]["last_status"] == "ok" and feeds["rss"]["total_items"] == 3
        names = [s["name"] for s in api.get("/api/v1/sources").json()["sources"]]
        assert names == ["kev", "epss", "news"]


def test_shipped_feeds_file_is_valid(settings):
    from app.sources.news import load_feeds

    settings.news_feeds_file = None
    config = load_feeds(settings)
    assert len(config["feeds"]) >= 15 and config["general_keywords"]
    assert all(f["url"].startswith("https://") and f["language"] in ("en", "it") for f in config["feeds"])
