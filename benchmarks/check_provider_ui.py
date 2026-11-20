"""Browser smoke test for AI provider setup with a loopback HTTP fixture.

Run from the repository root after `npm run build` in web/ and Playwright setup:
`PYTHONPATH=src python benchmarks/check_provider_ui.py /absolute/path/to/artifacts`.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright

from libella.api import App, create_api


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    pages = Path("web/dist")
    if not (pages / "index.html").is_file():
        raise SystemExit("Build web/dist first.")
    received = []

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            model = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["model"]
            valid = self.headers.get("Authorization") == "Bearer local-fixture-secret"
            received.append((self.path, model, valid))
            self.send_response(200 if valid else 401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"choices":[{"message":{"content":"OK"}}]}' if valid else b'{}')

        def log_message(self, format, *args):
            pass

    with (tempfile.TemporaryDirectory() as data, ThreadingHTTPServer(("127.0.0.1", 0), Provider) as provider,
          socket.socket() as sock):
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        base = f"http://127.0.0.1:{provider.server_port}/v1"
        os.environ["LIBELLA_PROVIDER_TEST_URLS"] = base
        os.environ["LIBELLA_WEB_DIST"] = str(pages.resolve())
        app = App(data)
        api = create_api(app)
        server = uvicorn.Server(uvicorn.Config(api, log_level="warning"))
        backend = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        companion = threading.Thread(target=provider.serve_forever, daemon=True)
        companion.start()
        backend.start()
        try:
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.05)
            assert server.started
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                context = browser.new_context(viewport={"width": 1440, "height": 900},
                                              record_har_path=out / "private.har", record_har_content="omit")
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"http://{host}:{port}")
                page.get_by_label("API token").fill(app.token)
                page.get_by_role("button", name="Connect", exact=True).click()
                page.get_by_role("link", name="Settings", exact=True).click()
                page.get_by_label("Base URL").fill(base)
                page.get_by_label("Default model").fill("fixture-model")
                page.get_by_label("API key").fill("incorrect-fixture-value")
                test_button = page.get_by_role("button", name="Test connection")
                test_button.focus()
                test_button.press("Enter")
                expect(page.get_by_text("The provider rejected the credentials.", exact=False)).to_be_visible()
                assert "/settings" in page.url
                page.screenshot(path=out / "provider-rejected.png")
                page.get_by_label("API key").fill("local-fixture-secret")
                test_button.click()
                expect(page.get_by_text("The selected model returned a text response.", exact=False)).to_be_visible()
                assert app.llm_settings() == {}
                assert not page.get_by_text("local-fixture-secret", exact=False).count()
                page.screenshot(path=out / "provider-connected.png")
                page.get_by_role("button", name="Save provider settings").click()
                expect(page.get_by_text("Leave blank to use the saved key.")).to_be_visible()
                assert page.get_by_label("API key").input_value() == ""
                expect(page.get_by_text("Settings saved.", exact=True)).to_have_count(0, timeout=8000)
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=out / "provider-mobile.png")
                assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
                assert errors == [], errors
                context.close()
            assert received == [("/v1/chat/completions", "fixture-model", False),
                                ("/v1/chat/completions", "fixture-model", True)]
            capture = out / "private.har"
            har = json.loads(capture.read_bytes())
            entries = har["log"]["entries"]
            har["log"]["entries"] = [e for e in entries if e["request"]["url"].endswith("/api/settings/provider-test")]
            assert len(har["log"]["entries"]) == 2
            for entry in har["log"]["entries"]:
                for direction in ("request", "response"):
                    entry[direction]["headers"] = []
                    entry[direction]["cookies"] = []
                    entry[direction].pop("postData", None)
            (out / "provider-sanitized.har").write_text(json.dumps(har))
        finally:
            (out / "private.har").unlink(missing_ok=True)
            server.should_exit = True
            backend.join(timeout=5)
            provider.shutdown()
            companion.join()
    print(f"Provider browser smoke passed: rejection, success, save, mobile. Evidence: {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
