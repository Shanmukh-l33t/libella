"""Browser check: every report export downloads a valid, redacted file.

Usage: PYTHONPATH=src python benchmarks/check_report_exports.py <data-dir> <eid> <out-dir>
Copies the data dir; the original engagement is never modified. Requires built web/dist
and Playwright Chromium. No assessment is run.
"""
import json
import shutil
import socket
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

import uvicorn
from openpyxl import load_workbook
from playwright.sync_api import sync_playwright

from libella.api import App, create_api

SENTINEL = b"SI_SECRET"


def main(src: Path, eid: str, out: Path):
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
            results = {}
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"http://{host}:{port}/engagements/{eid}?tab=report")
                page.get_by_label("API token").fill(app.token)
                page.get_by_role("button", name="Connect", exact=True).click()
                page.get_by_role("button", name="Regenerate").wait_for(timeout=15000)
                for label, ext in [("PDF", "pdf"), ("HTML", "html"), ("Word", "docx"),
                                   ("Excel", "xlsx"), ("CSV", "csv"), ("Markdown", "md"),
                                   ("SARIF", "sarif"), ("DefectDojo", "dojo")]:
                    with page.expect_download(timeout=20000) as dl:
                        page.get_by_role("button", name=label, exact=True).click()
                    path = out / f"{eid}.{ext}"
                    dl.value.save_as(path)
                    data = path.read_bytes()
                    assert len(data) > 100, (label, len(data))
                    assert SENTINEL not in data, f"{label} leaked a credential sentinel"
                    results[ext] = len(data)
                assert errors == [], errors
                page.screenshot(path=out / "report-exports-1440.png")
                browser.close()
            # structural validation of the Office files
            assert zipfile.is_zipfile(out / f"{eid}.docx")
            with zipfile.ZipFile(out / f"{eid}.docx") as z:
                assert "word/document.xml" in z.namelist()
            wb = load_workbook(out / f"{eid}.xlsx")
            assert "Findings" in wb.sheetnames
            assert (out / f"{eid}.html").read_text().lstrip().lower().startswith("<!doctype html>")
            json.loads((out / f"{eid}.sarif").read_text())
        finally:
            server.should_exit = True
            time.sleep(0.5)
            s.close()
    print(json.dumps({"ok": True, "bytes": results}))


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
