"""Browser smoke test for the new-engagement wizard against a loopback backend.

Walks all six steps with the local demo lab target and asserts the create payload,
the start call, and the landing route. The lab does not need to be running: the
point is the wizard, and the run failing target-wise is not a failure here.

Run from the repository root after `npm run build` in web/ and Playwright setup:
`PYTHONPATH=src python benchmarks/check_wizard_ui.py /absolute/path/to/artifacts`.
"""
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright

from libella.api import App, create_api


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    pages = Path("web/dist")
    if not (pages / "index.html").is_file():
        raise SystemExit("Build web/dist first.")

    with tempfile.TemporaryDirectory() as data, socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        os.environ["LIBELLA_WEB_DIST"] = str(pages.resolve())
        app = App(data)
        api = create_api(app)
        server = uvicorn.Server(uvicorn.Config(api, log_level="warning"))
        backend = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        backend.start()
        try:
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.05)
            assert server.started
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_context(viewport={"width": 1440, "height": 900}).new_page()
                errors, posts = [], []

                def record(request):
                    if request.method != "POST":
                        return
                    if request.url.endswith("/api/engagements") or re.search(
                            r"/api/engagements/[^/]+/(start|auth-contexts|workflows)$", request.url):
                        posts.append((request.url, json.loads(request.post_data or "{}")))

                page.on("pageerror", lambda e: errors.append(str(e)))
                page.on("request", record)

                page.goto(f"http://{host}:{port}")
                page.get_by_label("API token").fill(app.token)
                page.get_by_role("button", name="Connect", exact=True).click()
                page.get_by_role("button", name="New engagement").first.click()
                expect(page.get_by_role("heading", name="New engagement")).to_be_visible()

                # 1. target type — the demo lab prefills its own URL and categories.
                page.get_by_role("radio", name=re.compile(r"^Local demo lab")).check()
                page.get_by_role("button", name="Next", exact=True).click()

                # 2. scope — name, prefilled target, explicit authorization.
                page.get_by_label("Engagement name").fill("Demo lab smoke")
                assert page.get_by_label("Target 1 value").input_value() == "http://127.0.0.1:8801"
                page.get_by_role("button", name="Next", exact=True).click()
                # Fail-closed: the step is refused until the authorization box is ticked.
                expect(page.get_by_text("Confirm you are authorized", exact=False)).to_be_visible()
                assert page.url.endswith("/engagements/new")
                page.get_by_role("checkbox", name=re.compile("authorized to test")).check()
                page.get_by_role("button", name="Next", exact=True).click()

                # 3. access — unauthenticated. Enter in a form field advances: the wizard is fully keyboard driven.
                expect(page.get_by_role("heading", name=re.compile("How should checks get in"))).to_be_visible()
                page.get_by_label("OpenAPI file").press("Enter")
                expect(page.get_by_role("heading", name="How hard should it push?")).to_be_visible()

                # 4. profile — Standard, with what it runs and does not run.
                expect(page.get_by_text("Does not run", exact=False).first).to_be_visible()

                # A reload keeps the non-secret draft and offers to resume it (this route is
                # re-authenticated in place: the SPA keeps the URL, the token only lives in memory).
                page.reload()
                page.get_by_label("API token").fill(app.token)
                page.get_by_role("button", name="Connect", exact=True).click()
                expect(page.get_by_text("Unsaved draft from", exact=False)).to_be_visible()
                assert page.evaluate("localStorage.getItem('libella.wizard.draft.v1')").count("password") == 0
                page.get_by_role("button", name="Resume draft").click()
                expect(page.get_by_role("heading", name="How hard should it push?")).to_be_visible()
                page.get_by_role("button", name="Back", exact=True).click()
                page.get_by_role("button", name="Back", exact=True).click()
                assert page.get_by_label("Engagement name").input_value() == "Demo lab smoke"
                assert page.get_by_role("checkbox", name=re.compile("authorized to test")).is_checked()
                page.get_by_role("button", name="Next", exact=True).click()
                page.get_by_role("button", name="Next", exact=True).click()
                expect(page.get_by_role("heading", name="How hard should it push?")).to_be_visible()
                page.get_by_role("radio", name=re.compile(r"^Quick")).check()
                page.get_by_role("button", name="Next", exact=True).click()

                # 5. readiness
                expect(page.get_by_text("What you are about to create")).to_be_visible()
                expect(page.get_by_text("What will not work as chosen")).to_be_visible()
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
                page.screenshot(path=out / "wizard-readiness-mobile.png")
                page.set_viewport_size({"width": 1440, "height": 900})
                page.get_by_role("button", name="Next", exact=True).click()

                # 6. create and start
                expect(page.get_by_role("heading", name="Create and start")).to_be_visible()
                page.screenshot(path=out / "wizard-start.png")
                page.get_by_role("button", name="Create & start").click()
                page.wait_for_url(re.compile(r"/engagements/eng_[^/]+\?tab=overview"), timeout=15000)
                page.screenshot(path=out / "wizard-created.png")

                created = [body for url, body in posts if url.endswith("/api/engagements")]
                assert len(created) == 1, posts
                body = created[0]
                assert body["name"] == "Demo lab smoke", body["name"]
                assert body["profile"] == "passive", body["profile"]
                assert body["scope"]["targets"] == [{"kind": "url", "value": "http://127.0.0.1:8801"}], body["scope"]
                assert body["scope"]["categories"] == ["recon", "web"], body["scope"]["categories"]
                assert body["scope"]["advanced_validation"] is False
                started = [b for url, b in posts if url.endswith("/start")]
                assert started == [{"mode": "deterministic"}], posts
                assert not [b for url, b in posts if url.endswith("/auth-contexts")]

                row = app.db.one("SELECT name, profile, scope_json FROM engagements")
                assert row, "engagement was not persisted"
                assert row["profile"] == "passive" and json.loads(row["scope_json"])["targets"][0]["value"] == "http://127.0.0.1:8801"
                # The draft is dropped once the engagement exists, and it never held a credential.
                assert page.evaluate("localStorage.getItem('libella.wizard.draft.v1')") is None
                assert errors == [], errors
                page.context.close()
                browser.close()
        finally:
            server.should_exit = True
            backend.join(timeout=5)
    print(f"Wizard browser smoke passed: 6 steps, create+start, mobile. Evidence: {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
