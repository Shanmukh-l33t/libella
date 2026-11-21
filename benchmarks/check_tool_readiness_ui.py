"""Browser check for tool readiness levels in the Tool Center (acceptance journey C).

Fake binaries in LIBELLA_TOOL_PATH stand in for broken installs; real host tools
supply the healthy case:
  subfinder  reports v1.0.0, below the declared minimum      -> degraded
  gitleaks   version command crashes                          -> installed (broken)
  ffuf       valid version, but produces nothing on a scan    -> degraded (fixture failed)
  semgrep    absent from the host                             -> missing
  nmap       the real host binary scans the local fixture     -> assessment ready

Run from the repository root after `npm run build` in web/:
`PYTHONPATH=src python benchmarks/check_tool_readiness_ui.py /absolute/out/dir`.
"""
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright

FAKES = {
    "subfinder": 'echo "subfinder version v1.0.0"',
    "gitleaks": 'echo "fatal: corrupted build" >&2; exit 2',
    "ffuf": 'case "$1" in -V) echo "ffuf version: 2.1.0";; *) exit 0;; esac',
}
EXPECT = {
    "subfinder": ("degraded", "below the supported minimum"),
    "gitleaks": ("installed", "version command failed"),
    "ffuf": ("degraded", None),
    "semgrep": ("missing", "not installed"),
    "nmap": ("assessment ready", None),
}


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    pages = Path("web/dist")
    if not (pages / "index.html").is_file():
        raise SystemExit("Build web/dist first.")
    if shutil.which("semgrep") or not shutil.which("nmap"):
        raise SystemExit("this check expects semgrep absent and nmap installed on the host")
    with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as bins, socket.socket() as sock:
        for name, body in FAKES.items():
            p = Path(bins) / name
            p.write_text(f"#!/bin/sh\n{body}\n")
            p.chmod(0o755)
        os.environ["LIBELLA_TOOL_PATH"] = bins
        os.environ["LIBELLA_WEB_DIST"] = str(pages.resolve())
        from libella.api import App, create_api  # after LIBELLA_TOOL_PATH so the registry sees the fakes
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        app = App(data)
        server = uvicorn.Server(uvicorn.Config(create_api(app), log_level="warning"))
        backend = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        backend.start()
        result = {}
        try:
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.05)
            assert server.started
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"http://{host}:{port}")
                page.get_by_label("API token").fill(app.token)
                page.get_by_role("button", name="Connect", exact=True).click()
                page.get_by_role("link", name="Tools", exact=True).click()
                expect(page.get_by_text("assessment-ready", exact=False).first).to_be_visible(timeout=240000)

                def row(name):
                    return page.locator("tr", has=page.locator("span.font-mono", has_text=re.compile(f"^{name}$")))

                seen = {}
                for name, (level, note) in EXPECT.items():
                    r = row(name)
                    expect(r).to_contain_text(level, timeout=30000)
                    if note:
                        expect(r).to_contain_text(note)
                    assert "assessment ready" not in r.text_content() or level == "assessment ready", name
                    seen[name] = r.inner_text().replace("\n", " | ")
                page.screenshot(path=out / "c1-tool-center.png", full_page=True)
                # an on-demand rerun keeps the honest verdict (no cache masking a broken tool)
                row("gitleaks").get_by_role("button", name="Run diagnostic").click()
                expect(row("gitleaks")).to_contain_text("installed", timeout=60000)
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=out / "c2-mobile.png", full_page=True)
                browser.close()
            assert errors == [], errors
            result = {"ok": True, "rows": seen}
        finally:
            server.should_exit = True
            backend.join(timeout=5)
        (out / "tool_readiness_ui.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
