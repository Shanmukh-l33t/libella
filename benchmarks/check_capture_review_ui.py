"""Chromium acceptance for offline ASVS evidence review; no scanner or model runs."""
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import uvicorn
from playwright.sync_api import expect, sync_playwright

from libella.api import App, create_api
from libella.scope import Scope


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Cache-Control", "private, no-store")
        self.end_headers()
        self.wfile.write(b"Synthetic account statement")


def main(out):
    out.mkdir(parents=True, exist_ok=True)
    os.environ["LIBELLA_WEB_DIST"] = str(Path("web/dist").resolve())
    app = App(out / "data")
    with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as fixture, socket.socket() as sock:
        lab = f"http://127.0.0.1:{fixture.server_port}"
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        sock.bind(("127.0.0.1", 0))
        base = f"http://127.0.0.1:{sock.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(create_api(app), log_level="warning"))
        worker = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        worker.start()
        try:
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.05)
            assert server.started
            scenario(app, base, lab, out)
        finally:
            server.should_exit = True
            worker.join(timeout=5)
            fixture.shutdown()


def scenario(app, base, lab, out):
    scope = {"targets": [{"kind": "url", "value": lab}], "categories": ["web"]}
    with httpx.Client(base_url=base, headers={"Authorization": f"Bearer {app.token}"}) as api:
        eid = api.post("/api/engagements", json={"name": "Cache review", "scope": scope,
                       "profile": "passive"}).raise_for_status().json()["id"]
        api.put(f"/api/engagements/{eid}/standards", json={"asvs": {"level": 1}}).raise_for_status()
        captured = app.probe.request(eid, Scope(scope), lab)
        assert captured["ok"], captured
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"{base}/coverage?engagement={eid}")
            page.get_by_label("API token").fill(app.token)
            page.get_by_role("button", name="Connect", exact=True).click()
            page.get_by_label("Verification level").select_option("2")
            expect(page.get_by_text("at Level 2", exact=False).first).to_be_visible()
            before = api.get(f"/api/engagements/{eid}/coverage/asvs").raise_for_status().json()["summary"]
            assert before["attempted"] == 0
            page.get_by_label("Search requirements").fill("V14.3.2")
            page.get_by_text("V14.3.2", exact=True).click()
            expect(page.get_by_role("dialog")).to_be_visible()
            page.get_by_label("Captured exchange ID").fill(captured["exchange_id"])
            page.get_by_label("The captured response contains sensitive data").check()
            page.get_by_role("button", name="Evaluate sample").click()
            expect(page.get_by_text("Explicit no-store is present.", exact=False)).to_be_visible()
            page.get_by_label("Inspect exchange").select_option(captured["exchange_id"])
            expect(page.get_by_text('"cache-control": "private, no-store"', exact=False)).to_be_visible()
            page.get_by_label("Review note").fill("Sample only; check other sensitive responses separately.")
            page.get_by_role("button", name="Save review").click()
            expect(page.get_by_role("region", name="Review history").get_by_text("Sample only", exact=False)).to_be_visible()
            page.screenshot(path=out / "desktop.png")
            page.set_viewport_size({"width": 390, "height": 844})
            expect(page.get_by_role("dialog")).to_be_in_viewport()
            assert page.get_by_role("dialog").evaluate("el => el.scrollWidth <= el.clientWidth")
            page.screenshot(path=out / "mobile.png")
            page.get_by_role("button", name="Close requirement").click()
            page.get_by_label("Status filter").select_option("partial_evidence")
            expect(page.get_by_text("V14.3.2", exact=True)).to_be_visible()
            with page.expect_download() as download:
                page.get_by_role("button", name="Coverage report (MD)").click()
            download.value.save_as(out / "coverage.md")
            exported = (out / "coverage.md").read_text()
            assert f"V14.3.2: conforms ({captured['evidence_id']})" in exported
            after = api.get(f"/api/engagements/{eid}/coverage/asvs").raise_for_status().json()["summary"]
            assert before["statuses"]["partial_evidence"] + 1 == after["statuses"]["partial_evidence"]
            assert after["attempted"] == 1
            assert after["total"] == before["total"] == 253
            assert not errors, errors
            print(f"ASVS L2 captured-evidence checks: {before['statuses']['partial_evidence']} -> "
                  f"{after['statuses']['partial_evidence']} / {after['total']} on this isolated fixture")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
