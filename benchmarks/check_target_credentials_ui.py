"""Browser check for engagement-scoped target credentials (acceptance journey D).

Two loopback fixtures: an in-scope API (accepts one bearer token, redirects /redir
to the other fixture) and an out-of-scope sink that records every request. The
operator saves credentials in the engagement Overview and tests them; the check
asserts the rendered verdicts, that the sink never received a request, and that
the secret appears nowhere (page, API responses, events, database file).

Run from the repository root after `npm run build` in web/:
`PYTHONPATH=src python benchmarks/check_target_credentials_ui.py /absolute/out/dir`.
"""
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import uvicorn
from playwright.sync_api import expect, sync_playwright

from libella.api import App, create_api

SECRET = "tc-sentinel-7f3a9c"  # fixture value; must never surface anywhere
WRONG = "tc-wrong-0000"


def fixtures():
    hits = {"target": [], "sink": []}

    def handler(name, sink_port):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                hits[name].append((self.path, self.headers.get("Authorization")))
                if name == "sink":
                    code, body, extra = 200, b"sink", {}
                elif self.path == "/redir":
                    code, body, extra = 302, b"", {"Location": f"http://127.0.0.1:{sink_port()}/steal"}
                elif self.path == "/open":
                    code, body, extra = 200, b"public page", {}
                elif self.headers.get("Authorization") == f"Bearer {SECRET}":
                    code, body, extra = 200, b'{"user":"alice-fixture"}', {}
                else:
                    code, body, extra = 401, b'{"error":"unauthorized"}', {}
                self.send_response(code)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        return H

    sink = ThreadingHTTPServer(("127.0.0.1", 0), handler("sink", lambda: 0))
    target = ThreadingHTTPServer(("127.0.0.1", 0), handler("target", lambda: sink.server_port))
    return target, sink, hits


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    pages = Path("web/dist")
    if not (pages / "index.html").is_file():
        raise SystemExit("Build web/dist first.")
    target, sink, hits = fixtures()
    for srv in (target, sink):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    tbase = f"http://127.0.0.1:{target.server_port}"
    sbase = f"http://127.0.0.1:{sink.server_port}"
    with tempfile.TemporaryDirectory() as data, socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        os.environ["LIBELLA_WEB_DIST"] = str(pages.resolve())
        app = App(data)
        server = uvicorn.Server(uvicorn.Config(create_api(app), log_level="warning"))
        backend = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        backend.start()
        base = f"http://{host}:{port}"
        api = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {app.token}"}, timeout=30)
        result = {}
        try:
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.05)
            assert server.started
            eid = api.post("/api/engagements", json={
                "name": "Credential check",
                "scope": {"targets": [{"kind": "url", "value": tbase + "/"}], "categories": ["web", "api"]},
            }).raise_for_status().json()["id"]
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                ctx = browser.new_context(viewport={"width": 1440, "height": 900})
                page = ctx.new_page()
                errors, bodies = [], []
                page.on("pageerror", lambda e: errors.append(str(e)))
                # the SSE response never ends, so its body cannot be read; events are checked via the API below
                page.on("response", lambda r: bodies.append(r) if "/api/" in r.url and "/stream" not in r.url else None)
                page.goto(base)
                page.get_by_label("API token").fill(app.token)
                page.get_by_role("button", name="Connect", exact=True).click()
                page.get_by_role("link", name="Engagements", exact=True).click()
                page.get_by_text("Credential check", exact=True).first.click()
                expect(page.get_by_text("No credentials saved for this engagement.")).to_be_visible(timeout=15000)

                def add(name, value):
                    page.get_by_label("Name", exact=True).fill(name)
                    page.get_by_label(re.compile(r"^Token")).fill(value)
                    page.get_by_role("button", name="Save credential").click()
                    expect(page.get_by_text(name, exact=True)).to_be_visible(timeout=10000)
                    assert page.get_by_label(re.compile(r"^Token")).input_value() == ""

                def run(name, url, marker=""):
                    page.get_by_label(f"Test URL for {name}").fill(url)
                    page.get_by_label(f"Expected marker for {name}").fill(marker)
                    row = page.locator("li", has=page.get_by_text(name, exact=True))
                    before = row.inner_text()
                    row.get_by_role("button", name="Test credentials").click()
                    expect(row).not_to_have_text(before, timeout=15000)
                    return row

                add("Wrong token", WRONG)
                row = run("Wrong token", tbase + "/me")
                expect(row.get_by_text("Rejected", exact=True)).to_be_visible()
                expect(row.get_by_text("HTTP 401")).to_be_visible()
                page.screenshot(path=out / "d1-rejected.png", full_page=True)

                add("Good token", SECRET)
                row = run("Good token", tbase + "/me", "alice-fixture")
                expect(row.get_by_text("Accepted", exact=True)).to_be_visible()
                page.screenshot(path=out / "d2-accepted.png", full_page=True)

                row = run("Good token", tbase + "/open", "alice-fixture")
                expect(row.get_by_text("2xx, identity not proven", exact=True)).to_be_visible()

                row = run("Good token", tbase + "/redir")
                expect(row.get_by_text("Redirect", exact=True)).to_be_visible()
                expect(row.get_by_text("Redirects are never followed", exact=False)).to_be_visible()
                page.screenshot(path=out / "d3-redirect.png", full_page=True)

                row = run("Good token", sbase + "/steal")
                expect(row.get_by_text("Refused before sending", exact=True)).to_be_visible()
                page.screenshot(path=out / "d4-out-of-scope.png", full_page=True)

                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=out / "d5-mobile.png", full_page=True)
                mobile_overflow = page.evaluate("document.documentElement.scrollWidth > innerWidth")

                page.get_by_role("button", name="Delete Wrong token").click()
                expect(page.get_by_text("Wrong token", exact=True)).to_have_count(0, timeout=10000)

                dom = page.content()
                seen = []
                for r in bodies:
                    try:
                        seen.append(r.text())
                    except Exception:
                        pass
                ctx.close()
                browser.close()
            assert errors == [], errors
            assert hits["sink"] == [], f"out-of-scope sink received requests: {hits['sink']}"
            assert [p for p, _ in hits["target"]] == ["/me", "/me", "/open", "/redir"], hits["target"]
            leaks = {
                "dom": SECRET in dom,
                "api_responses": any(SECRET in t for t in seen),
                "events": SECRET in api.get(f"/api/engagements/{eid}/events?since=0").text,
                "credentials_api": SECRET in api.get(f"/api/engagements/{eid}/credentials").text,
                "db_files": any(SECRET.encode() in p.read_bytes() for p in Path(data).rglob("*") if p.is_file()),
            }
            assert not any(leaks.values()), leaks
            result = {"ok": True, "target_requests": [p for p, _ in hits["target"]], "sink_requests": 0,
                      "secret_leaks": leaks, "mobile_horizontal_overflow": mobile_overflow}
        finally:
            server.should_exit = True
            backend.join(timeout=5)
            for srv in (target, sink):
                srv.shutdown()
        (out / "target_credentials_ui.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
