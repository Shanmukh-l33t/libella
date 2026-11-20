"""Acceptance Test A: the beginner journey through the real application.

Fresh data dir -> token -> Get started -> Setup (offline AI) -> tool inventory ->
create an authorized engagement against a local PairLab instance -> start ->
watch live progress -> review findings -> coverage -> report -> PDF export ->
reopen the PDF. Real scanners and checks run against the lab; nothing is mocked.

Usage (repo root, after `npm run build` in web/ and Playwright Chromium installed):
    PYTHONPATH=src python benchmarks/acceptance_beginner.py <out-dir>
Every stage prints PASS/FAIL; the first failing stage is reported and exits 1.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
RUN_TIMEOUT_S = int(os.environ.get("ACCEPTANCE_RUN_TIMEOUT", "1500"))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Stage:
    def __init__(self):
        self.log = []

    def __call__(self, name, fn):
        t0 = time.time()
        try:
            out = fn()
        except Exception as e:  # report the exact failing stage
            self.log.append({"stage": name, "ok": False, "s": round(time.time() - t0, 1),
                             "error": f"{type(e).__name__}: {str(e)[:400]}"})
            print(f"FAIL {name}: {type(e).__name__}: {str(e)[:400]}", flush=True)
            raise
        self.log.append({"stage": name, "ok": True, "s": round(time.time() - t0, 1)})
        print(f"PASS {name} ({time.time() - t0:.1f}s)", flush=True)
        return out


def create_engagement_current_form(page, target):
    """Engagement creation through the new-assessment UI."""
    page.get_by_label("Engagement name").fill("First assessment (demo lab)")
    page.get_by_label("Target 1 value").fill(target)
    page.get_by_label("Rate limit (req/s)").fill("50")
    page.get_by_role("button", name="Create engagement").click()


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    lab_port = free_port()
    lab = subprocess.Popen([sys.executable, str(ROOT / "labs/pairlab/app.py")],
                           env={**os.environ, "LAB_PORT": str(lab_port), "LAB_MODE": "vuln"},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    target = f"http://127.0.0.1:{lab_port}"
    st = Stage()
    status = {"ok": False}
    with tempfile.TemporaryDirectory() as data:
        port = free_port()
        token = "acceptance-" + os.urandom(12).hex()
        base = f"http://127.0.0.1:{port}"
        backend = subprocess.Popen(
            [sys.executable, "-m", "libella.main", "--data-dir", str(Path(data) / "data"),
             "--port", str(port)],
            env={**os.environ, "LIBELLA_TOKEN": token, "PYTHONPATH": str(ROOT / "src"),
                 "LIBELLA_WEB_DIST": str(ROOT / "web/dist")},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        api = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=30)

        def eng_status(eid):
            return api.get(f"/api/engagements/{eid}").json()

        try:
            def wait_up():
                for _ in range(150):
                    try:
                        if api.get("/api/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        time.sleep(0.2)
                for _ in range(100):
                    try:
                        if httpx.get(target, timeout=1).status_code < 500:
                            return
                    except httpx.HTTPError:
                        time.sleep(0.2)
                raise RuntimeError("lab or backend did not start")
            st("0 backend and local lab start", wait_up)

            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                ctx = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
                page = ctx.new_page()
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))

                def connect():
                    page.goto(base)
                    page.get_by_label("API token").fill(token)
                    page.get_by_role("button", name="Connect", exact=True).click()
                    expect(page.get_by_role("heading", name="Get started")).to_be_visible(timeout=15000)
                st("1 fresh install: connect, Get started shown", connect)

                def setup():
                    page.get_by_role("button", name="Open setup").click()
                    expect(page.get_by_text("reachable", exact=False).first).to_be_visible(timeout=15000)
                    nav = page.get_by_role("navigation", name="Setup steps")
                    nav.get_by_role("button", name="AI provider").click()
                    # beginner chooses offline deterministic mode
                    skip = page.get_by_role("button", name="Skip", exact=False)
                    if skip.count():
                        skip.first.click()
                    nav.get_by_role("button", name="Tools").click()
                    expect(page.get_by_text("installed", exact=False).first).to_be_visible()
                    page.screenshot(path=out / "a1-setup-tools.png")
                    nav.get_by_role("button", name="Next steps").click()
                    page.get_by_role("button", name="Create an engagement").click()
                    expect(page).to_have_url(f"{base}/engagements/new")
                st("2 setup: offline AI, tool inventory, go to new assessment", setup)

                def create():
                    create_engagement_current_form(page, target)
                    page.wait_for_url(f"{base}/engagements/eng_*", timeout=20000)
                    page.screenshot(path=out / "a2-created.png")
                    return page.url.split("/engagements/")[1].split("?")[0]
                eid = st("3 create authorized engagement for the local lab", create)

                def start():
                    page.get_by_role("button", name="Start", exact=True).click()
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        if eng_status(eid)["status"] != "draft":
                            return
                        time.sleep(0.5)
                    raise RuntimeError("engagement did not leave draft after Start")
                st("4 start the real scan from the UI", start)

                def live():
                    seen_running = False
                    t0 = time.time()
                    last = None
                    while time.time() - t0 < RUN_TIMEOUT_S:
                        s = eng_status(eid)["status"]
                        if s == "running":
                            seen_running = True
                            if last is None or time.time() - last > 60:
                                page.screenshot(path=out / "a3-live.png")
                                last = time.time()
                        if s not in ("running", "draft"):
                            break
                        time.sleep(3)
                    s = eng_status(eid)
                    done_at = time.time()
                    if s["status"] != "done":
                        raise RuntimeError(f"run ended {s['status']}: {s['status_detail']}")
                    assert seen_running, "never observed the running state"
                    # the live workspace must reflect completion without a manual reload
                    # the engagement header (h1 + status badge) must flip to Done without a reload
                    expect(page.locator("h1").first.locator("xpath=..")).to_contain_text("Done", timeout=30000)
                    ui_lag = round(time.time() - done_at, 1)
                    page.screenshot(path=out / "a3-done.png")
                    calls = api.get(f"/api/engagements/{eid}/tool-calls").json()
                    ran = [c for c in calls if str(c.get("scope_decision", "")).startswith("executed")]
                    return {"tool_calls_executed": len(ran), "tools": sorted({c["tool"] for c in ran}),
                            "ui_done_lag_s": ui_lag}
                run = st("5 run to completion with live state", live)

                def findings():
                    page.get_by_role("tab", name="Findings").click(timeout=20000)
                    expect(page).to_have_url(f"{base}/engagements/{eid}?tab=findings", timeout=10000)
                    rows = api.get(f"/api/engagements/{eid}/findings").json()
                    verified = [r for r in rows if r["state"] in ("validated", "reported", "retested_persists")]
                    assert verified, f"no independently verified findings ({len(rows)} total)"
                    expect(page.get_by_text(verified[0]["title"], exact=False).first).to_be_visible(timeout=15000)
                    expect(page.locator("td", has_text="Validated").first).to_be_visible(timeout=15000)
                    page.screenshot(path=out / "a4-findings.png")
                    return {"findings": len(rows), "verified": len(verified)}
                fnd = st("6 review genuine findings in the UI", findings)

                def coverage():
                    page.get_by_role("link", name="Coverage", exact=True).click()
                    expect(page.get_by_text("WSTG", exact=False).first).to_be_visible(timeout=15000)
                    page.screenshot(path=out / "a5-coverage.png")
                st("7 inspect methodology coverage", coverage)

                def report():
                    page.get_by_role("link", name="Engagements", exact=True).click()
                    page.get_by_text("First assessment (demo lab)").first.click()
                    page.get_by_role("tab", name="Report").click(timeout=20000)
                    page.get_by_role("button", name="Regenerate").wait_for(timeout=20000)
                    page.screenshot(path=out / "a6-report.png")
                    with page.expect_download(timeout=60000) as dl:
                        page.get_by_role("button", name="PDF", exact=True).click()
                    pdf = out / f"{eid}.pdf"
                    dl.value.save_as(pdf)
                    from pypdf import PdfReader
                    text = "\n".join(p.extract_text() or "" for p in PdfReader(str(pdf)).pages)
                    title = next(f["title"] for f in api.get(f"/api/engagements/{eid}/findings").json()
                                 if f["state"] in ("validated", "reported"))
                    assert title.split()[0] in text, "verified finding missing from reopened PDF"
                    assert "Coverage" in text or "limitation" in text.lower() or "Degradation" in text
                    return {"pdf_bytes": pdf.stat().st_size, "pdf_pages": len(PdfReader(str(pdf)).pages)}
                rpt = st("8 generate, export and reopen the PDF report", report)

                assert not errors, errors
                browser.close()
            status = {"ok": True, "engagement": eid, "run": run, "findings": fnd, "report": rpt}
        finally:
            backend.terminate()
            lab.terminate()
            backend.wait(10)
            (out / "acceptance_beginner.json").write_text(json.dumps({**status, "stages": st.log}, indent=2))
    print(json.dumps(status))


if __name__ == "__main__":
    try:
        main(Path(sys.argv[1]))
    except Exception:
        sys.exit(1)
