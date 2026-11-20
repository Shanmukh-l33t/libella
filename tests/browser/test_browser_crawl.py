"""Browser crawler against a real chromium and a local JS-rendered SPA.

The fixture app renders its links and fires its API calls in JavaScript, so a
static crawl of it finds one page and zero API routes. Passing here means the
rendered DOM and the observed XHR/fetch traffic were really captured.
"""
import pytest

from libella.browser_crawl import BrowserCrawler, browser_available

pytestmark = pytest.mark.skipif(not browser_available(), reason="playwright/chromium not installed")


@pytest.fixture
def crawled(engine, spa):
    db, ev, scope = engine
    with BrowserCrawler(db, ev, scope, "eng_browser", max_pages=10) as crawler:
        return crawler.crawl(spa.base)


def test_rendered_links_and_runtime_api(crawled, spa):
    assert spa.base + "/api/data" in crawled["endpoints"], crawled
    links = [link for page in crawled["pages"] for link in page["links"]]
    assert spa.base + "/admin" in links, crawled["pages"]
    # only reachable by following the JS-injected link, and only after render
    assert spa.base + "/api/admin/stats" in crawled["endpoints"], crawled["endpoints"]
    assert {r["method"] for r in crawled["api_requests"]} == {"GET"}
    assert any(p["title"] == "Libella SPA" for p in crawled["pages"])
    assert crawled["limit_hit"] is False
    assert len(crawled["pages"]) == 3  # /, /admin, /cross


def test_cross_origin_request_refused(engine, spa):
    db, ev, scope = engine
    with BrowserCrawler(db, ev, scope, "eng_browser", max_pages=5) as crawler:
        result = crawler.crawl(spa.base + "/cross")
    assert spa.sink_hits == [], "out-of-scope request was actually sent"
    assert not any(spa.sink_base in u for u in result["endpoints"])
    refusals = [e["payload_json"] for e in db.query(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind='scope_refusal'",
        ("eng_browser",))]
    assert any(spa.sink_base in p for p in refusals), refusals


def test_dead_target_degrades_without_hanging(engine):
    db, ev, scope = engine
    with BrowserCrawler(db, ev, scope, "eng_browser", max_pages=3, timeout_ms=4000) as crawler:
        result = crawler.crawl("http://127.0.0.1:9")
    assert result["pages"] == [] and result["limit_hit"] is False
    assert result["degraded"], "silent failure: no degradation recorded"


def test_screenshot_evidence_integrity(engine, crawled):
    db, ev, _ = engine
    shots = crawled["screenshots"]
    assert 0 < len(shots) <= 5
    assert len(shots) == len(crawled["pages"])  # fewer pages than the cap
    for eid in shots:
        data = ev.read(eid)  # re-hashes on read; raises if tampered
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
        assert db.one("SELECT kind FROM evidence WHERE id=?", (eid,))["kind"] == "browser_screenshot"
    assert ev.verify_chain("eng_browser")["ok"] is True
