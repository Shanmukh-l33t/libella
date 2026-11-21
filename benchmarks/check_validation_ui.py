"""Read-only /validation workspace check against a real completed engagement.

Usage: PYTHONPATH=src python benchmarks/check_validation_ui.py <data-dir> <out-dir>
The data dir is COPIED first; the original engagement is never modified.
Requires a built web/dist and Playwright Chromium. No assessment is run.
"""
import json
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright

from libella.api import App, create_api


def main(src: Path, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "data"
        shutil.copytree(src, copy)
        app = App(copy)
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
            writes, errors = [], []
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.on("request", lambda r: writes.append(r.url)
                        if r.method not in ("GET", "HEAD") and "/api/ticket" not in r.url else None)
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"http://{host}:{port}")
                page.get_by_label("API token").fill(app.token)
                page.get_by_role("button", name="Connect", exact=True).click()
                page.get_by_role("link", name="Validation", exact=True).click()
                expect(page.get_by_role("heading", name="Validation workspace")).to_be_visible()
                expect(page.locator("main").get_by_text("Verified", exact=True).first).to_be_visible(timeout=15000)
                assert "Impact demonstrated" not in page.content()
                page.screenshot(path=out / "validation-live-1440.png")
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
                page.screenshot(path=out / "validation-live-390.png")
                assert errors == [], errors
                browser.close()
            assert writes == [], writes
        finally:
            server.should_exit = True
            time.sleep(0.5)
            s.close()
    print(json.dumps({"ok": True, "non_get_writes": [], "shots": [str(x) for x in sorted(out.glob("*.png"))]}))


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
