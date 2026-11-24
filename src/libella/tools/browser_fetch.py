"""Fetch a page through a real browser when the HTTP client is challenged.

A CDN/WAF may answer a plain HTTP client with a bot challenge while serving the
application to a browser. That is a non-answer, not a finding (see
http_probe.mitigation); this module is the supported second attempt: the same
page, read by the same authorized engagement, through Chromium.

It is used only after a challenge was detected, so an ordinary site never pays
for a browser launch.
"""
import os
import time
from pathlib import Path

TIMEOUT_S = 30


def available() -> bool:
    from ..browser_crawl import browser_available
    return browser_available()


def fetch(url: str, timeout_s: int = TIMEOUT_S) -> dict:
    """Return {status, headers, body, url, duration_ms} for one page, or raise."""
    from playwright.sync_api import sync_playwright

    started = time.time()
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_s * 1000)
            if resp is None:
                raise RuntimeError("the browser opened no response")
            # the rendered DOM: what a visitor sees, including client-rendered nodes
            body = page.content().encode()
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": body,
                    "url": page.url, "duration_ms": round((time.time() - started) * 1000, 1)}
        finally:
            browser.close()


def render_pdf(html: str, out_path, timeout_s: int = 60) -> Path:
    """Print an HTML document to PDF with the same Chromium we already ship.

    Every network request is aborted: report HTML embeds captured evidence, and
    rendering it must never fetch a remote resource an evidence blob names.
    """
    from playwright.sync_api import sync_playwright

    out_path = Path(out_path)
    tmp = out_path.with_suffix(".tmp.pdf")
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            context = browser.new_context()
            context.route("**/*", lambda route: route.abort())  # no egress from a render
            page = context.new_page()
            page.set_content(html, wait_until="domcontentloaded", timeout=timeout_s * 1000)
            page.pdf(path=str(tmp), format="A4", print_background=True,
                     margin={"top": "18mm", "bottom": "18mm", "left": "16mm", "right": "16mm"})
        finally:
            browser.close()
    os.replace(tmp, out_path)  # atomic: a failed print never leaves a half PDF
    return out_path
