"""Headless-browser crawler: renders JS apps and records their runtime traffic.

The static crawler (crawl.py) only sees the server-rendered shell. Angular /
React apps build their links and fire their API calls in JavaScript, so the
runtime side is where the interesting surface lives. This module drives
Chromium through Playwright with the same scope discipline as the HTTP probe:
one context-level route applies the egress policy to every request -- the
navigation, its subresources, XHR/fetch, websockets and popups -- so a page
cannot make the platform contact a host the engagement did not authorize.
Third-party hosts a page references are refused and counted, never contacted.
"""
import os
import time
from collections import deque
from urllib.parse import urldefrag, urlparse

from .assessment_window import stored_stop_refusal
from .egress import Egress, open_browser_context

SHOT_CAP = 5      # screenshots are evidence, not a video; five key pages is plenty
IDLE_MS = 3000    # bounded network-idle wait: polling SPAs (socket.io) never go idle
LINK_CAP = 200


def _clean(url: str) -> str:
    """Keep route-like fragments (on `/#/login` the fragment IS the page), drop plain anchors."""
    return url if urlparse(url).fragment.startswith("/") else urldefrag(url)[0]


def browser_available() -> bool:
    """True when playwright imports and a chromium build is actually installed."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            return os.path.exists(p.chromium.executable_path)
    except Exception:
        return False


def fetch_scoped(url: str, egress: Egress, timeout_s: int = 30) -> dict:
    """One page through a policy-enforcing context, for the challenged-page fallback.

    Same confinement as the crawler: the landing page and everything it pulls is
    gated per request, so this is not a way around the policy.
    """
    from playwright.sync_api import sync_playwright

    started = time.time()
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            ctx = open_browser_context(browser, egress)
            try:
                page = ctx.new_page()
                resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_s * 1000)
                if resp is None:
                    raise RuntimeError("the browser opened no response")
                return {"status": resp.status, "headers": dict(resp.headers),
                        "body": page.content().encode(), "url": page.url,
                        "duration_ms": round((time.time() - started) * 1000, 1)}
            finally:
                ctx.close()
        finally:
            browser.close()


class _CtxBrowser:
    """browser.new_page() shim onto one context, so cookies and the route persist."""

    def __init__(self, ctx):
        self.ctx = ctx

    def new_page(self):
        return self.ctx.new_page()

    def close(self):
        self.ctx.browser.close()


class BrowserCrawler:
    """Render pages in chromium, collect rendered links + XHR/fetch APIs."""

    def __init__(self, db, evidence, scope, engagement_id: str,
                 max_pages: int = 25, timeout_ms: int = 15000, egress: Egress | None = None):
        self.db = db
        self.evidence = evidence
        self.scope = scope
        self.eng = engagement_id
        self.egress = egress or Egress(db, scope, engagement_id, tool="browser_crawl")
        self.max_pages = max_pages
        self.timeout_ms = timeout_ms
        self._pw = None
        self._browser = None
        self._ctx = None
        self._reset()

    def _reset(self):
        self.pages: list[dict] = []
        self.api_requests: list[dict] = []
        self.endpoints: set[str] = set()
        self.shots: list[str] = []
        self.degraded: list[str] = []
        self._seen_api: set[tuple[str, str]] = set()
        self._refused: set[str] = set()
        self._page_url = ""

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            self._ctx = self._new_context()
            self._browser = _CtxBrowser(self._ctx)
        except BaseException:
            self._close()
            raise
        return self

    def _new_context(self):
        """One context per crawler; its route covers every page it opens."""
        return open_browser_context(self._browser, self.egress,
                                    on_request=self._on_request)

    def _on_request(self, req):
        if req.resource_type in ("xhr", "fetch"):
            self._note_api(req.method, req.url, self._page_url)

    def __exit__(self, *exc):
        self._close()
        return False

    def _close(self):
        for closer in (getattr(self._browser, "close", None), getattr(self._pw, "stop", None)):
            try:
                if closer:
                    closer()
            except Exception:
                pass
        self._browser = self._pw = None

    # -- scope -------------------------------------------------------------
    def _allowed(self, url: str) -> bool:
        d = self.egress.gate(url)
        if not d.allowed and url not in self._refused:
            self._refused.add(url)
            self.db.emit(self.eng, "scope_refusal",
                         {"url": url, "reason": d.reason, "tool": "browser_crawl"})
        return d.allowed

    def _stopped(self) -> str | None:
        """A pause, cancel or closed window stops the crawl: chromium is egress too."""
        return stored_stop_refusal(self.db, self.eng)

    def _same_origin(self, url: str, netloc: str) -> bool:
        p = urlparse(url)
        return p.scheme in ("http", "https") and p.netloc == netloc

    # -- crawl -------------------------------------------------------------
    def crawl(self, base_url: str) -> dict:
        """Crawl from base_url. Always returns partial results; never raises or hangs."""
        self._reset()
        if self._browser is not None:
            self._walk(base_url)
            return self._result()
        try:
            with self:
                self._walk(base_url)
        except Exception as e:
            self.degraded.append(f"browser_unavailable: {type(e).__name__}: {e}")
        return self._result()

    def _walk(self, base_url: str):
        base = base_url.rstrip("/")
        netloc = urlparse(base).netloc
        start = base + "/" if urlparse(base).path in ("", "/") else base
        if not self._allowed(start):
            self.degraded.append(f"start url out of scope: {start}")
            return
        seen: set[str] = set()
        queue = deque([start])
        while queue and len(self.pages) < self.max_pages:
            stop = self._stopped()
            if stop:
                self.degraded.append(f"stopped: {stop}")
                return
            url = _clean(queue.popleft())
            if url in seen or not self._same_origin(url, netloc):
                continue
            seen.add(url)
            if not self._allowed(url):
                continue
            try:
                page = self._render(url, netloc)
            except Exception as e:
                self.degraded.append(f"render_failed: {url}: {type(e).__name__}")
                continue
            if page is None:
                continue
            self.pages.append(page)
            self.endpoints.add(url)
            for link in page["links"]:
                if link not in seen:
                    queue.append(link)

    def _render(self, url: str, netloc: str) -> dict | None:
        page = self._browser.new_page()   # the context route already gates every request
        try:
            page.set_default_timeout(self.timeout_ms)
            self._page_url = url
            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            except Exception as e:
                self.degraded.append(f"navigation_failed: {url}: {type(e).__name__}")
                return None
            # redirect chains: the landing URL must still be our origin and in scope
            final = page.url
            if not self._same_origin(final, netloc) or not self._allowed(final):
                return None
            try:
                page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, IDLE_MS))
            except Exception:
                self.degraded.append(f"network_idle_timeout: {url}")  # partial render is still evidence
            try:
                title = page.title()[:120] or None
            except Exception:
                title = None
            links = []
            try:
                hrefs = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)")
                for h in hrefs:
                    h = _clean(h)
                    if self._same_origin(h, netloc) and h not in links and len(links) < LINK_CAP:
                        links.append(h)
            except Exception:
                self.degraded.append(f"link_extract_failed: {url}")
            shot = None
            if len(self.shots) < SHOT_CAP:
                shot = self._screenshot(page, url)
            return {"url": url, "status": resp.status if resp else None, "title": title,
                    "links": links, "screenshot": shot}
        finally:
            try:
                page.close()
            except Exception:
                pass

    def _note_api(self, method: str, url: str, page_url: str):
        url = _clean(url)
        key = (method.upper(), url)
        if key in self._seen_api:
            return
        self._seen_api.add(key)
        self.api_requests.append({"method": key[0], "url": url, "page": page_url})
        self.endpoints.add(url)

    def _screenshot(self, page, url: str) -> str | None:
        try:
            png = page.screenshot(full_page=False, timeout=self.timeout_ms)
            ev = self.evidence.put(self.eng, png, "browser_screenshot")
        except Exception as e:
            self.degraded.append(f"screenshot_failed: {url}: {type(e).__name__}")
            return None
        self.shots.append(ev["id"])
        return ev["id"]

    def _result(self) -> dict:
        blocked = self.egress.summary()
        if blocked["denied_requests"]:
            # the page referenced hosts it was never allowed to contact: a
            # degradation the report states, not an invisible aborted request
            self.degraded.append(
                f"egress_blocked_third_party: {blocked['denied_requests']} request(s) to "
                f"{len(blocked['blocked_hosts'])} host(s) not contacted: "
                + ", ".join(blocked["blocked_hosts"][:5]))
        return {"pages": self.pages, "api_requests": self.api_requests,
                "endpoints": sorted(self.endpoints), "screenshots": list(self.shots),
                "limit_hit": len(self.pages) >= self.max_pages,
                "egress": blocked,
                "degraded": list(self.degraded)}
