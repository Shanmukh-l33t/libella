"""Browser journey check for the standards coverage screen.

Seeds a REAL engagement: a tiny loopback Flask app that sets an insecure session
cookie and no security headers, assessed by the deterministic orchestrator with a
`passive` profile (so no external scanner binary decides the runtime). Then drives
the UI as an operator would and asserts rendered state, not API state alone:

  standard title + version · level selection · summary numbers · status filter ·
  search · requirement drawer with executed evidence · evidence/finding link ·
  analyst note persisted across a reload · report download · no console errors.

Usage: PYTHONPATH=src python benchmarks/check_standards_ui.py <out-dir>
Requires a built web/dist and Playwright Chromium. Nothing outside loopback is touched.
"""
import json
import logging
import os
import re
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from flask import Flask, make_response
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from libella.api import App, create_api

NOTE = "Checked by hand on staging: header policy is set at the edge, not in Flask."


def _fixture() -> tuple[str, object]:
    """A deliberately unprotected app: no security headers, a bare session cookie."""
    web = Flask("fixture")
    page = ("<html><body><a href='/about'>About</a><a href='/login'>Sign in</a>"
            "<p>Fixture application for the coverage browser check.</p></body></html>")

    @web.get("/")
    def root():
        r = make_response(page)
        r.set_cookie("session_id", "abc123")
        return r

    @web.get("/about")
    def about():
        return "<html><body>About this fixture.</body></html>"

    @web.get("/login")
    def login():
        return ("<html><body><form method='post' action='/login'>"
                "<input name='username'><input name='password' type='password'></form></body></html>")

    @web.post("/login")
    def do_login():
        r = make_response("<html><body>signed in</body></html>")
        r.set_cookie("session_id", "abc123")
        return r

    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # the fixture's 404s are expected noise
    server = make_server("127.0.0.1", 0, web, threaded=True)  # ephemeral port, no race
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}", server


def _seed(app: App, base: str) -> str:
    scope = {"targets": [{"kind": "url", "value": base}], "categories": ["recon", "web"],
             "rate_limit_rps": 20, "max_concurrency": 2}
    app.db.execute(
        "INSERT INTO engagements(id,name,profile,status,scope_json,auth_json,budgets_json,"
        "created_at,standards_json) VALUES(?,?,?,?,?,?,?,?,?)",
        ("eng_std_ui", "Standards UI check", "passive", "draft", json.dumps(scope),
         json.dumps({"identities": []}), json.dumps({"max_duration_s": 300, "max_usd": 1}),
         time.time(), json.dumps({"asvs": {"level": 1}})))
    app.orchestrator().start("eng_std_ui", mode="deterministic")
    return "eng_std_ui"


def _api(page, base: str, path: str, token: str):
    r = page.request.get(f"{base}{path}", headers={"Authorization": f"Bearer {token}"})
    assert r.ok, (path, r.status, r.text())
    return r.json()


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    pages = Path("web/dist")
    if not (pages / "index.html").is_file():
        raise SystemExit("Build web/dist first (cd web && npm run build).")
    os.environ["LIBELLA_WEB_DIST"] = str(pages.resolve())

    base_url, fixture = _fixture()
    with tempfile.TemporaryDirectory() as data, socket.socket() as sock:
        app = App(data)
        eid = _seed(app, base_url)
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        api = create_api(app)
        server = uvicorn.Server(uvicorn.Config(api, log_level="warning"))
        threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True).start()
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started
        base = f"http://{host}:{port}"
        try:
            errors, failures = [], []
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_context(viewport={"width": 1440, "height": 900}).new_page()
                page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
                page.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error" else None)
                page.on("response", lambda r: failures.append(f"{r.status} {r.url}")
                        if r.status >= 400 and "/api/health" not in r.url else None)

                def connect():
                    page.get_by_label("API token").fill(app.token)
                    page.get_by_role("button", name="Connect", exact=True).click()

                def row_ids():
                    return [t.strip() for t in page.locator(
                        '[data-testid="chapter"] tbody tr td:first-child').all_inner_texts()]

                page.goto(f"{base}/coverage")
                connect()
                expect(page.get_by_role("heading", name="Security standards & coverage")).to_be_visible()

                # 1. engagement + standard + level, as an operator would
                page.get_by_label("Engagement").select_option(eid)
                page.get_by_label("Standard").select_option("asvs")
                expect(page.get_by_test_id("framework-title")).to_have_text(
                    "OWASP Application Security Verification Standard 5.0.0 v5.0.0", timeout=15000)
                l1 = _api(page, base, f"/api/engagements/{eid}/coverage/asvs", app.token)
                expect(page.get_by_label("Verification level")).to_have_value("1")
                page.get_by_label("Verification level").select_option("2")
                # the PUT lands, the workspace reloads, the selector reflects the stored level
                expect(page.get_by_label("Verification level")).to_have_value("2", timeout=15000)
                expect(page.get_by_text("at Level 2", exact=False).first).to_be_visible(timeout=15000)
                l2 = _api(page, base, f"/api/engagements/{eid}/coverage/asvs", app.token)
                assert l2["summary"]["level"] == 2, l2["summary"]
                assert l2["summary"]["total"] > l1["summary"]["total"], (l1["summary"], l2["summary"])

                # 2. summary numbers are the API's numbers, not a re-computation
                for key in ("applicable", "supported", "attempted", "completed", "partial",
                            "with_findings", "skipped", "manual_required", "not_tested"):
                    expect(page.get_by_test_id(f"summary-{key}")).to_have_text(
                        str(l2["summary"][key]), timeout=15000)

                # 3. status filter shows only finding_verified rows
                verified = l2["summary"]["statuses"]["finding_verified"]
                assert verified > 0, "seed produced no verified finding; the journey has nothing to show"
                page.get_by_label("Status filter").select_option("finding_verified")
                expect(page.locator('[data-testid="chapter"] tbody tr')).to_have_count(verified)
                for text in page.locator('[data-testid="chapter"] tbody tr').all_inner_texts():
                    lower = text.lower()  # badges are CSS-capitalised
                    assert "finding_verified" in lower, text
                    assert "requires_manual" not in lower, text

                # 4. search narrows to the V3.4 chapter
                page.get_by_label("Status filter").select_option("all")
                page.get_by_label("Search requirements").fill("V3.4")
                want = [t["id"] for c in l2["categories"] for t in c["tests"] if t["id"].startswith("V3.4")]
                expect(page.locator('[data-testid="chapter"] tbody tr')).to_have_count(len(want))
                assert row_ids() == want, (row_ids(), want)

                # 5. open a requirement that executed something and read the whole story
                page.get_by_label("Search requirements").fill("V3.4.4")
                page.locator('[data-testid="chapter"] tbody tr').first.click()
                drawer = page.get_by_role("dialog", name="Requirement V3.4.4")
                expect(drawer).to_be_visible()
                expect(drawer.get_by_text("What is required")).to_be_visible()
                expect(drawer.get_by_text("X-Content-Type-Options", exact=False).first).to_be_visible()
                expect(drawer.get_by_text("How Libella tested it")).to_be_visible()
                expect(drawer.get_by_text("security_headers", exact=False).first).to_be_visible()
                expect(drawer.get_by_text("What executed")).to_be_visible()
                expect(drawer.get_by_text("exchanges captured")).to_be_visible()
                expect(drawer.get_by_role("link", name=re.compile("Missing security headers")).first).to_be_visible()
                page.screenshot(path=out / "standards-drawer-1440.png")

                # 6. analyst note, then prove it survives a reload (token is memory-only)
                page.get_by_label("Review note").fill(NOTE)
                page.get_by_role("button", name="Save review").click()
                expect(drawer.get_by_text("review: manual")).to_be_visible(timeout=15000)
                assert page.get_by_label("Review note").input_value() == NOTE
                page.get_by_role("button", name="Close requirement").click()

                page.reload()
                connect()
                expect(page.get_by_role("heading", name="Security standards & coverage")).to_be_visible()
                page.get_by_label("Search requirements").fill("V3.4.4")
                row = page.locator('[data-testid="chapter"] tbody tr').first
                expect(row.locator(".chip", has_text=re.compile("^manual$", re.I)).first) \
                    .to_be_visible(timeout=15000)
                row.click()
                drawer = page.get_by_role("dialog", name="Requirement V3.4.4")
                assert drawer.get_by_label("Review note").input_value() == NOTE
                expect(drawer.get_by_text("What remains untested", exact=False)).to_have_count(0)

                # 7. analyst attribution correction is offered here and records history
                link = drawer.get_by_role("link", name=re.compile("Missing security headers")).first
                finding_id = link.get_attribute("href").rsplit("/", 1)[-1]
                drawer.get_by_label("Link finding").select_option(finding_id)
                drawer.get_by_label("Link note").fill("Attribution reviewed: the header evidence is this requirement's.")
                drawer.get_by_role("button", name="Record attribution").click()
                expect(drawer.get_by_text("Recorded: add", exact=False)).to_be_visible(timeout=15000)
                drawer.evaluate("el => el.scrollTo(0, el.scrollHeight)")
                page.wait_for_timeout(150)
                page.screenshot(path=out / "standards-drawer-review-1440.png")
                drawer.evaluate("el => el.scrollTo(0, 0)")

                # 8. the evidence link lands on a page that renders that finding
                link.click()
                page.wait_for_url(re.compile(r"/findings/f_"), timeout=15000)
                expect(page.get_by_text(finding_id, exact=False).first).to_be_visible(timeout=15000)
                expect(page.get_by_text("Missing security headers", exact=False).first).to_be_visible()

                # 9. report download through the existing export
                page.goto(f"{base}/coverage?engagement={eid}&framework=asvs")
                connect()  # a full navigation drops the in-memory token
                expect(page.get_by_test_id("summary-not_tested")).to_be_visible(timeout=15000)
                with page.expect_download() as dl:
                    page.get_by_role("button", name="Coverage report (MD)").click()
                assert dl.value.suggested_filename.endswith("-coverage.md"), dl.value.suggested_filename

                # 10. desktop + mobile screenshots of the ledger itself
                page.locator('[data-testid="chapter"] button[aria-expanded]').first.click()
                page.evaluate("window.scrollTo(0, 0)")
                page.wait_for_timeout(150)
                page.screenshot(path=out / "standards-list-1440.png")
                page.screenshot(path=out / "standards-full-1440.png", full_page=True)
                page.evaluate("() => { const el = document.querySelector('[data-testid=chapter]');"
                              " window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY - 60); }")
                page.wait_for_timeout(150)
                page.screenshot(path=out / "standards-table-1440.png")
                page.set_viewport_size({"width": 390, "height": 844})
                page.locator('[data-testid="chapter"]').first.scroll_into_view_if_needed()
                page.wait_for_timeout(150)
                assert page.evaluate("document.documentElement.scrollWidth === innerWidth"), "mobile overflow"
                page.screenshot(path=out / "standards-list-390.png")
                page.locator('[data-testid="chapter"] tbody tr').first.click()
                expect(page.get_by_role("dialog")).to_be_visible()
                assert page.evaluate("document.documentElement.scrollWidth === innerWidth"), "drawer overflow"
                page.screenshot(path=out / "standards-drawer-390.png")
                page.set_viewport_size({"width": 1440, "height": 900})
                page.get_by_role("button", name="Close requirement").click()

                text = page.content()
                assert "[object Object]" not in text
                assert errors == [], errors
                assert failures == [], failures
                browser.close()
        finally:
            server.should_exit = True
            time.sleep(0.3)
            fixture.shutdown()
    print(json.dumps({"ok": True, "engagement": eid, "screenshots":
                      [str(x) for x in sorted(out.glob("*.png"))]}))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots-standards")))