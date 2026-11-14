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
    with pytest.raises(ValueError, match="web page"):
        parse_feed(b"<!doctype html>\n<html lang='it'><head></head></html>")


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
        assert names == ["kev", "epss", "nvd", "exploits", "news", "scans"]


def test_shipped_feeds_file_is_valid(settings):
    from app.sources.news import load_feeds

    settings.news_feeds_file = None
    config = load_feeds(settings)
    assert len(config["feeds"]) >= 15 and config["general_keywords"]
    assert all(f["url"].startswith("https://") and f["language"] in ("en", "it") for f in config["feeds"])


# --- derived labels ------------------------------------------------------------
from app.enrich import news as enrich  # noqa: E402


@pytest.mark.parametrize(
    "title, kind, cves, event, exploited, claim, sectors",
    [
        ("Nuovi allarmi bomba a 1800 scuole, mail partita da più indirizzi", "general", [],
         "hoax_disruption", False, "reported", ["education"]),
        ("Fortinet warns of FortiWeb flaw actively exploited in the wild", "specialist", ["CVE-2026-1"],
         "vulnerability_exploitation", True, "reported", []),
        ("Risolte vulnerabilità in PrestaShop", "primary", [], "vulnerability_disclosure", False, "official", []),
        ("Hackers claim breach of airline, stolen data reportedly for sale", "specialist", [],
         "data_breach", False, "unverified", ["aviation"]),
        ("Attacco hacker ai frigoriferi dei supermercati in Europa", "specialist", [],
         "cyber_physical", False, "reported", ["retail_food"]),
        ("Romania says it stopped ransomware attack on water utility", "specialist", [],
         "ransomware", False, "reported", ["energy_utilities"]),
        ("Operation Endgame takes down botnet infrastructure", "specialist", [], "other", False, "reported", []),
        ("CVE-2026-20320 Windows Kernel Elevation of Privilege", "primary", ["CVE-2026-20320"],
         "vulnerability_disclosure", False, "official", []),
        ("Windows Internet Connection Sharing (ICS) Elevation of Privilege Vulnerability", "primary",
         ["CVE-2026-119859"], "vulnerability_disclosure", False, "official", []),
        ("ICS advisory: flaws in PLC firmware", "primary", [], "cyber_physical", False, "official", []),
        # the US flight ground stop of 13 November
        ("FAA Ground Stop Issued Due to 'Extraordinary Circumstances'", "specialist", [],
         "service_disruption", False, "reported", ["aviation"]),
        ("Fbi, 'blocco aereo Usa non è dovuto ad attacco informatico'", "general", [],
         "service_disruption", False, "reported", ["aviation"]),
        # a law granting sabotage powers is not a sabotage incident
        ("German parliament passes law giving spy agencies hacking, sabotage powers", "specialist", [],
         "other", False, "reported", ["government"]),
        # naming a culprit is a claim, whoever makes it
        ("France Blames Iran for Sabotage Attack on Refrigeration Controllers at 700 Retailers",
         "specialist", [], "cyber_physical", False, "unverified", ["retail_food"]),
        ("U.S. Agencies Warn Refrigeration Controller Attacks Could Cause Fires", "primary", [],
         "cyber_physical", False, "official", []),
    ],
)
def test_classification_rules(title, kind, cves, event, exploited, claim, sectors):
    assert enrich.classify(title, "", kind, cves) == {
        "event_type": event, "exploitation_signal": exploited, "claim_status": claim, "target_sectors": sectors}


def _item(item_id, feed, title, hours=0, language="en", cves=()):
    when = datetime(2026, 11, 10, tzinfo=timezone.utc) + __import__("datetime").timedelta(hours=hours)
    return {"item_id": item_id, "feed_id": feed, "title": title, "language": language, "when": when,
            "cves": frozenset(cves)}


def test_stories_group_the_same_report_across_feeds_only():
    items = [
        _item("a1", "feedA", "Fortinet patches critical FortiWeb flaw exploited in attacks"),
        _item("b1", "feedB", "Fortinet patches critical FortiWeb flaw exploited in the wild", hours=5),
        _item("c1", "feedC", "Critical FortiWeb flaw exploited in attacks, Fortinet patches", hours=30),
        _item("a2", "feedA", "Fortinet patches critical FortiWeb flaw exploited in attacks again", hours=1),
        _item("d1", "feedD", "Fortinet patches critical FortiWeb flaw exploited in attacks", hours=24 * 9),
        _item("e1", "feedE", "Fortinet corregge falla critica FortiWeb sfruttata negli attacchi", language="it"),
        _item("m1", "ms", "CVE-2026-0001 Windows Kernel Elevation of Privilege Vulnerability", cves=["CVE-2026-0001"]),
        _item("x1", "press", "CVE-2026-0002 Windows Kernel Elevation of Privilege Vulnerability", cves=["CVE-2026-0002"]),
        _item("s1", "feedA", "Short title"), _item("s2", "feedB", "Short title"),
    ]
    stories = enrich.assign_stories(items)
    assert stories["a1"] == stories["b1"] == stories["c1"] == ("a1", 3)
    assert stories["d1"] == ("d1", 1)  # nine days later: a different story
    assert stories["e1"] == ("e1", 1)  # another language: not merged yet
    assert stories["m1"][0] != stories["x1"][0]  # different CVEs never merge
    assert stories["s1"][0] != stories["s2"][0]  # too few words to compare safely


def test_stories_match_reworded_headlines_but_do_not_drift():
    items = [
        _item("p1", "feedA", "Poland takes its national e-government platform offline after a cyberattack"),
        _item("p2", "feedB", "Poland shuts down government services platform ePUAP following cyberattack", hours=3),
        _item("z1", "feedA", "Zoom fixes critical Windows vulnerability allowing privilege escalation", hours=4),
        _item("z2", "feedC", "Critical Zoom Workplace flaw could allow unauthenticated remote privilege escalation", hours=6),
        # shares words with z2 but not with z1, which opened the story: stays out
        _item("q1", "feedD", "Unauthenticated remote flaw could allow attackers into Acme Workplace routers", hours=7),
        _item("u1", "feedB", "Researchers publish a study on password habits among students", hours=8),
    ]
    stories = enrich.assign_stories(items)
    assert stories["p1"] == stories["p2"] == ("p1", 2)
    assert stories["z1"] == stories["z2"] == ("z1", 2)
    assert stories["q1"] == ("q1", 1) and stories["u1"] == ("u1", 1)


def test_labels_are_built_after_collection_and_served(news):
    settings, upstream, client = news
    upstream["gen"] = GENERAL.replace(
        b"</channel>",
        b"<item><title>Acme gateway flaw CVE-2026-1234 exploited and patched</title>"
        b"<link>https://example.org/g3</link><guid>g3</guid><description>hacker</description>"
        b"<pubDate>Wed, 11 Nov 2026 12:00:00 +0000</pubDate></item></channel>")
    with TestClient(app) as api:
        runner.run_source(settings, "news", client=client)
        assert enrich.enriched_path(settings).exists() and enrich.is_current(settings)

        items = {i["title"]: i for i in api.get("/api/v1/news").json()["items"]}
        bomb = items["Allarme bomba in una scuola, istituto evacuato"]
        assert (bomb["event_type"], bomb["claim_status"], bomb["target_sectors"]) == (
            "hoax_disruption", "reported", ["education"])
        assert items["Advisory one"]["claim_status"] == "official"

        # the same report from two feeds (one of them English text in an Italian feed: not merged)
        assert api.get("/api/v1/news", params={"event_type": "hoax_disruption"}).json()["total"] == 1
        assert api.get("/api/v1/news", params={"sector": "education"}).json()["total"] == 1
        assert api.get("/api/v1/news", params={"claim_status": "official"}).json()["total"] == 1
        assert api.get("/api/v1/news", params={"exploited": True}).json()["total"] == 0
        assert api.get("/api/v1/news", params={"collapse": True}).json()["total"] == 6

        trend = api.get("/api/v1/news/trend", params={"by": "sector", "days": 365}).json()["items"]
        assert [(t["key"], t["stories"]) for t in trend] == [("education", 1)]
        assert api.get("/api/v1/news/trend", params={"by": "nope"}).status_code == 422

        # deleting the derived table loses nothing: it is rebuilt from the raw items
        enrich.enriched_path(settings).unlink()
        assert api.get("/api/v1/news").json()["items"][0]["event_type"] is None
        assert api.post("/api/v1/news/relabel").json() == {"items": 6}
        assert api.get("/api/v1/news", params={"event_type": "hoax_disruption"}).json()["total"] == 1


def test_story_collapse_keeps_one_row_per_story(news):
    settings, upstream, client = news
    same = (b"<rss version='2.0'><channel><item><title>Acme gateway flaw CVE-2026-1234 exploited &amp; patched</title>"
            b"<link>https://example.org/dup</link><guid>dup</guid>"
            b"<pubDate>Wed, 11 Nov 2026 10:00:00 +0100</pubDate></item></channel></rss>")
    upstream["atom"] = same  # the 'atom' feed now repeats the story of the 'rss' feed
    runner.run_source(settings, "news", client=client)
    full = queries.news_list(settings, 50, 0, search="Acme gateway")
    assert full["total"] == 2 and {i["story_feeds"] for i in full["items"]} == {2}
    one = queries.news_list(settings, 50, 0, search="Acme gateway", collapse=True)
    assert one["total"] == 1 and one["items"][0]["feed_id"] == "rss"  # earliest report wins


def test_rules_and_taxonomy_agree():
    import json
    from pathlib import Path

    taxonomy = json.loads((Path(enrich.__file__).parents[1] / "taxonomy" / "categories.json").read_text())
    rules = json.loads(enrich.RULES_FILE.read_text())
    events = {e["id"] for e in taxonomy["event_types"]}
    sectors = {e["id"] for e in taxonomy["target_sectors"]}
    assert {r["id"] for r in rules["event_types"]} <= events
    assert {r["id"] for r in rules["target_sectors"]} == sectors
    assert {"vulnerability_exploitation", "vulnerability_disclosure", "other"} <= events
    assert {c["id"] for c in taxonomy["claim_statuses"]} == {"official", "reported", "unverified"}
