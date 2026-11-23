"""Acceptance journey B: a real, authorized assessment of an external site through the UI.

Drives the built app as a beginner would: connect, new assessment wizard, real run,
live progress, findings, coverage, then every report kind downloaded and reopened.

The target is opt-in: set LIBELLA_TARGET to a host you are authorized to test.
Nothing here is run by CI (it needs the internet and an authorization).

    LIBELLA_TARGET=https://www.keyreed.com/ python benchmarks/acceptance_keyreed.py <outdir>
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
TARGET = os.environ.get("LIBELLA_TARGET", "")
RUN_TIMEOUT_S = int(os.environ.get("ACCEPTANCE_RUN_TIMEOUT", "2400"))


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Stage:
    def __init__(self):
        self.log = []

    def __call__(self, name, fn):
        t0 = time.time()
        out = fn()
        self.log.append({"stage": name, "ok": True, "s": round(time.time() - t0, 1)})
        print(f"PASS {name} ({time.time() - t0:.1f}s)", flush=True)
        return out


def wizard(page, target: str):
    import re
    page.get_by_role("radio", name=re.compile(r"^Website")).check()
    page.get_by_role("button", name="Next", exact=True).click()
    page.get_by_label("Engagement name").fill("Authorized external site assessment")
    page.get_by_label("Target 1 value").fill(target)
    page.get_by_label("Requests per second").fill("5")
    page.get_by_role("checkbox", name=re.compile("authorized to test")).check()
    page.get_by_role("button", name="Next", exact=True).click()   # access
    page.get_by_role("button", name="Next", exact=True).click()   # profile
    page.get_by_role("radio", name=re.compile(r"^Standard")).check()
    page.get_by_role("button", name="Next", exact=True).click()   # readiness
    page.get_by_text("What you are about to create").wait_for()
    page.get_by_role("button", name="Next", exact=True).click()   # start
    page.get_by_role("button", name="Create & start").click()


def main(out: Path):
    if not TARGET:
        raise SystemExit("set LIBELLA_TARGET to an authorized URL")
    out.mkdir(parents=True, exist_ok=True)
    st = Stage()
    data = tempfile.mkdtemp()
    port = free_port()
    token = "keyreed-" + os.urandom(12).hex()
    base = f"http://127.0.0.1:{port}"
    backend = subprocess.Popen(
        [sys.executable, "-m", "libella.main", "--data-dir", str(Path(data) / "data"),
         "--port", str(port)],
        env={**os.environ, "LIBELLA_TOKEN": token, "PYTHONPATH": str(ROOT / "src"),
             "LIBELLA_WEB_DIST": str(ROOT / "web" / "dist")},
        stdout=open(out / "backend.log", "w"), stderr=subprocess.STDOUT)
    api = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    result = {"ok": False, "target": TARGET}
    try:
        def up():
            for _ in range(150):
                try:
                    if api.get("/api/health").status_code == 200:
                        return
                except httpx.HTTPError:
                    time.sleep(0.2)
            raise RuntimeError("backend did not start")
        st("0 backend start", up)

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
            st("1 connect", connect)

            def create():
                page.goto(f"{base}/engagements/new")
                page.get_by_label("API token").fill(token)
                page.get_by_role("button", name="Connect", exact=True).click()
                wizard(page, TARGET)
                page.wait_for_url(f"{base}/engagements/eng_*", timeout=25000)
                page.screenshot(path=out / "b1-created.png")
                return page.url.split("/engagements/")[1].split("?")[0]
            eid = st("2 create the assessment through the wizard", create)

            def run():
                seen_running, done_at, progress_seen = False, None, False
                t0 = time.time()
                while time.time() - t0 < RUN_TIMEOUT_S:
                    s = api.get(f"/api/engagements/{eid}").json()["status"]
                    if s == "running":
                        seen_running = True
                    if page.get_by_text("% of", exact=False).count():
                        progress_seen = True
                        page.screenshot(path=out / "b2-progress.png")
                    if s not in ("running", "draft"):
                        done_at = time.time()
                        break
                    time.sleep(5)
                status = api.get(f"/api/engagements/{eid}").json()
                assert status["status"] in ("done", "budget_exhausted", "window_closed"), status
                assert seen_running, "never observed the running state"
                expect(page.locator("h1").first.locator("xpath=..")).to_contain_text(
                    "Done" if status["status"] == "done" else "Budget", timeout=30000,
                    use_inner_text=True)
                page.screenshot(path=out / "b3-done.png")
                ev = api.get(f"/api/engagements/{eid}/events?since=0").json()
                # what the egress policy refused, by host and reason: a denial is only
                # correct if it names a destination the operator never authorized
                denials = {}
                for e in ev:
                    if e["kind"] not in ("egress_denied", "scope_refusal"):
                        continue
                    p = e.get("payload") or {}
                    key = f"{p.get('host') or p.get('url') or '?'} :: {(p.get('reason') or '')[:80]}"
                    denials[key] = denials.get(key, 0) + 1
                kinds = {}
                for e in ev:
                    kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
                return {"status": status["status"], "events": len(ev), "kinds": kinds,
                        "denials": denials,
                        "ui_done_lag_s": round(time.time() - done_at, 1) if done_at else None,
                        "progress_events": kinds.get("scan_progress", 0),
                        "progress_rendered": progress_seen,
                        "mitigated": kinds.get("degradation", 0) and
                        sum(1 for e in ev if e["kind"] == "degradation"
                            and e["payload"].get("code") in ("target_mitigated", "scan_partial"))}
            run_info = st("3 real run to a terminal state", run)

            def findings():
                rows = api.get(f"/api/engagements/{eid}/findings").json()
                page.get_by_role("tab", name="Findings").click(timeout=20000)
                page.screenshot(path=out / "b4-findings.png")
                return {"total": len(rows),
                        "verified": sum(1 for r in rows if r["state"] in
                                        ("validated", "reported", "retested_persists")),
                        "titles": [r["title"] for r in rows]}
            findings_info = st("4 findings", findings)

            def coverage():
                cov = api.get(f"/api/engagements/{eid}/coverage/wstg").json()
                page.get_by_role("tab", name="Report").click()
                return cov.get("summary", {})
            cov_info = st("5 coverage", coverage)

            def reports():
                page.get_by_role("tab", name="Report").click()
                got = {}
                for kind, fmt, name in (("technical", "pdf", "technical.pdf"),
                                        ("executive", "pdf", "executive.pdf"),
                                        ("coverage", "pdf", "coverage.pdf"),
                                        ("evidence", "csv", "evidence.csv"),
                                        ("gitlab", "json", "gitlab.json")):
                    with page.expect_download(timeout=120000) as dl:
                        page.get_by_label("Report type").select_option(kind)
                        page.get_by_role("button", name={
                            "pdf": "PDF", "csv": "CSV", "json": "JSON"}[fmt]).click()
                    path = out / name
                    dl.value.save_as(str(path))
                    got[kind] = path.stat().st_size
                page.screenshot(path=out / "b5-reports.png", full_page=True)
                return got
            report_info = st("6 generate every report kind", reports)

            def reopen():
                info = {}
                try:
                    from pypdf import PdfReader
                    for name in ("technical.pdf", "executive.pdf", "coverage.pdf"):
                        reader = PdfReader(str(out / name))
                        text = "\n".join((p.extract_text() or "") for p in reader.pages)
                        assert text.strip(), f"{name} has no text"
                        info[name] = {"pages": len(reader.pages), "chars": len(text)}
                finally:
                    pass
                csv_text = (out / "evidence.csv").read_text()
                assert csv_text.startswith("evidence_id,kind,sha256"), csv_text[:80]
                info["evidence_rows"] = len(csv_text.strip().splitlines()) - 1
                gl = json.loads((out / "gitlab.json").read_text())
                assert gl["version"] == "15.0.0" and gl["scan"]["type"] == "dast"
                info["gitlab_vulns"] = len(gl["vulnerabilities"])
                return info
            reopen_info = st("7 reopen and validate the artifacts", reopen)

            assert errors == [], errors
            ctx.close()
            browser.close()

        result = {"ok": True, "engagement": eid, "run": run_info, "findings": findings_info,
                  "coverage": cov_info, "reports": report_info, "artifacts": reopen_info,
                  "stages": st.log}
    finally:
        backend.terminate()
        (out / "acceptance_keyreed.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
