"""Browser check: the target-credential test in the new-engagement wizard.

Usage: PYTHONPATH=src python benchmarks/check_credential_ui.py <out-dir>
Starts a loopback target lab + the Libella backend serving web/dist. No assessment runs.
"""
import json
import socket
import sys
import threading
import time
from pathlib import Path

import uvicorn
from flask import Flask, request
from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from libella.api import App, create_api


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    lab = Flask("cred-ui-lab")

    @lab.get("/api/me")
    def me():
        if request.headers.get("Authorization") == "Bearer good-token":
            return {"user": "alice"}, 200
        return {"error": "unauthorized"}, 401

    srv = make_server("127.0.0.1", 0, lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    target = f"http://127.0.0.1:{srv.server_port}/api/me"

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        app = App(Path(tmp) / "data")
        api = create_api(app)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        host, port = s.getsockname()
        server = uvicorn.Server(uvicorn.Config(api, log_level="warning"))
        threading.Thread(target=server.run, kwargs={"sockets": [s]}, daemon=True).start()
        try:
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.05)
            assert server.started
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"http://{host}:{port}/engagements/new")
                page.get_by_label("API token").fill(app.token)
                page.get_by_role("button", name="Connect", exact=True).click()
                page.get_by_label("Endpoint URL", exact=True).fill(target)
                page.get_by_label("Value", exact=True).fill("good-token")
                page.get_by_label("Expected identity marker (optional)").fill("alice")
                page.get_by_role("button", name="Test credentials").click()
                expect(page.get_by_text("Credential accepted")).to_be_visible(timeout=15000)
                expect(page.get_by_text("identity confirmed")).to_be_visible()
                page.screenshot(path=out / "credential-accepted.png")
                # wrong token -> rejected, not success
                page.get_by_label("Value", exact=True).fill("wrong-token")
                page.get_by_role("button", name="Test credentials").click()
                expect(page.get_by_text("Credential rejected")).to_be_visible(timeout=15000)
                page.screenshot(path=out / "credential-rejected.png")
                assert "good-token" not in page.content()
                assert errors == [], errors
                browser.close()
        finally:
            server.should_exit = True
            srv.shutdown()
            time.sleep(0.3)
            s.close()
    print(json.dumps({"ok": True}))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
