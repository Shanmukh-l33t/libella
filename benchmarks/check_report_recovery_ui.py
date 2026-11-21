"""Journey F: evidence chain, every export reopened, render-failure recovery, tamper.

Usage: PYTHONPATH=src python benchmarks/check_report_recovery_ui.py <out-dir>
Starts PairLab and the backend as subprocesses on free ports, runs a real
deterministic engagement to done through the API, then in Chromium:
  1 Evidence tab: the hash chain verifies as intact.
  2 Report tab: every offered export downloads and reopens; none carries literal
    markup tags or an unredacted credential sentinel.
  3 A failing re-render surfaces an actionable error, the last good report stays
    byte-identical on disk, and regeneration succeeds once the cause is removed.
  4 A tampered evidence blob makes the UI report a broken chain, not "intact".

Failure injection: mode bits do not stop root (this box runs as root), so the
render is failed by setting the immutable attribute on report.json -- the kernel
enforces it for every user, and it fails the exact os.replace step an unwritable
file would. The old report.json is then never touched.
"""
import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from docx import Document
from openpyxl import load_workbook
from playwright.sync_api import expect, sync_playwright
from pypdf import PdfReader

from acceptance_beginner import Stage, free_port

ROOT = Path(__file__).resolve().parents[1]
RUN_TIMEOUT_S = int(os.environ.get("ACCEPTANCE_RUN_TIMEOUT", "1800"))
SENTINEL = "SI_SECRET"
# (button label, file extension, is it a markup format that legitimately emits tags)
EXPORTS = [("PDF", "pdf", False), ("HTML", "html", True), ("Word", "docx", False),
           ("Excel", "xlsx", False), ("CSV", "csv", False), ("Markdown", "md", False),
           ("SARIF", "sarif", False), ("DefectDojo", "dojo", False)]


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def chattr(path: Path, flag: str) -> None:
    r = subprocess.run(["chattr", f"{flag}i", str(path)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"chattr {flag}i {path} failed: {r.stderr.strip()}")


def is_immutable(path: Path) -> bool:
    r = subprocess.run(["lsattr", str(path)], capture_output=True, text=True)
    return "i" in r.stdout[:30]


def pdf_text(path: Path) -> str:
    return norm("\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages))


def docx_text(path: Path) -> str:
    return norm("\n".join(p.text for p in Document(str(path)).paragraphs))


def xlsx_text(path: Path) -> str:
    cells = []
    for ws in load_workbook(path).worksheets:
        for row in ws.iter_rows(values_only=True):
            cells.append(" ".join("" if c is None else str(c) for c in row))
    return norm("\n".join(cells))


def reopen(path: Path, ext: str) -> str:
    """Reopen a downloaded export with a real parser and return its text."""
    text = {".pdf": pdf_text, ".docx": docx_text, ".xlsx": xlsx_text}.get(
        path.suffix, lambda p: p.read_text())
    raw = text(path)
    if ext == "csv":
        rows = list(csv.reader(io.StringIO(raw)))
        assert len(rows) > 1 and len(rows[0]) == 10, f"CSV shape unexpected: {rows[:1]}"
    if ext in ("sarif", "dojo"):
        doc = json.loads(raw)
        assert doc, "empty JSON export"
    return raw


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    lab_port, lab = free_port(), None
    st = Stage()
    status = {"ok": False}

    lab = subprocess.Popen(
        [sys.executable, str(ROOT / "labs/pairlab/app.py")],
        env={**os.environ, "LAB_PORT": str(lab_port), "LAB_MODE": "vuln"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    target = f"http://127.0.0.1:{lab_port}"
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "data"
        port = free_port()
        token = "recovery-" + os.urandom(12).hex()
        base = f"http://127.0.0.1:{port}"
        backend = subprocess.Popen(
            [sys.executable, "-m", "libella.main", "--data-dir", str(data), "--port", str(port)],
            env={**os.environ, "LIBELLA_TOKEN": token, "PYTHONPATH": str(ROOT / "src"),
                 "LIBELLA_WEB_DIST": str(ROOT / "web/dist")},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        api = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=30)
        try:
            def wait_up():
                for _ in range(300):
                    try:
                        if api.get("/api/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.2)
                else:
                    raise RuntimeError("backend did not start")
                for _ in range(100):
                    try:
                        if httpx.get(target, timeout=1).status_code < 500:
                            return
                    except httpx.HTTPError:
                        time.sleep(0.2)
                raise RuntimeError("lab did not start")
            st("0 backend and lab subprocesses start", wait_up)

            def assess():
                scope = {"targets": [{"kind": "url", "value": target}],
                         "categories": ["recon", "web"], "rate_limit_rps": 40,
                         "max_concurrency": 4}
                r = api.post("/api/engagements", json={
                    "name": "Journey F recovery", "profile": "safe_active", "scope": scope,
                    "budgets": {"max_duration_s": 900, "max_usd": 1}})
                assert r.status_code == 200, r.text
                eid = r.json()["id"]
                assert api.post(f"/api/engagements/{eid}/start",
                                json={"mode": "deterministic"}).status_code == 200
                deadline = time.time() + RUN_TIMEOUT_S
                seen_running = False
                while time.time() < deadline:
                    s = api.get(f"/api/engagements/{eid}").json()
                    seen_running = seen_running or s["status"] == "running"
                    if s["status"] not in ("running", "draft"):
                        break
                    time.sleep(2)
                s = api.get(f"/api/engagements/{eid}").json()
                assert s["status"] == "done", f"run ended {s['status']}: {s.get('status_detail')}"
                assert seen_running, "never observed a running engagement"
                findings = api.get(f"/api/engagements/{eid}/findings").json()
                confirmed = [f for f in findings
                             if f["state"] in ("validated", "reported", "retested_persists")]
                assert confirmed, f"no independently validated finding among {len(findings)}"
                return {"engagement": eid, "findings": len(findings), "confirmed": len(confirmed),
                        "title": confirmed[0]["title"]}
            run = st("1 real engagement runs to done with a validated finding", assess)
            eid, title = run["engagement"], run["title"]
            needle = " ".join(title.split()[:3])
            report_dir = data / "evidence" / eid / "report"
            evid = next(x["evidence_id"] for x in
                        api.get(f"/api/engagements/{eid}/observations").json() if x.get("evidence_id"))

            def auth(page):
                page.get_by_label("API token").fill(token)
                page.get_by_role("button", name="Connect", exact=True).click()

            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                ctx = browser.new_context(viewport={"width": 1440, "height": 900},
                                          accept_downloads=True)
                page = ctx.new_page()
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"{base}/engagements/{eid}?tab=report")
                auth(page)
                page.get_by_role("button", name="Regenerate").wait_for(timeout=30000)

                def chain_intact():
                    page.get_by_role("tab", name="Evidence").click(timeout=20000)
                    row = page.locator("tbody tr").first
                    row.click(timeout=20000)
                    expect(page.get_by_text("intact", exact=True)).to_be_visible(timeout=20000)
                    expect(page.get_by_text(re.compile(r"\d+ artifacts verified"))).to_be_visible()
                    page.screenshot(path=out / "f1-evidence-chain-desktop.png", full_page=True)
                    api_chain = api.get(f"/api/evidence/{evid}/chain")
                    assert api_chain.status_code == 200, api_chain.text
                    assert api_chain.json()["ok"] is True, api_chain.json()
                    return {"checked": api_chain.json()["checked"]}
                chain = st("2 evidence chain shows intact", chain_intact)

                def exports():
                    page.get_by_role("tab", name="Report").click(timeout=20000)
                    page.get_by_role("button", name="Regenerate").wait_for(timeout=20000)
                    sizes = {}
                    for label, ext, markup in EXPORTS:
                        with page.expect_download(timeout=60000) as dl:
                            page.get_by_role("button", name=label, exact=True).click()
                        path = out / f"{eid}.{ext}"
                        dl.value.save_as(path)
                        raw = path.read_bytes()
                        assert len(raw) > 100, f"{label} export is {len(raw)} bytes"
                        assert SENTINEL not in raw.decode("utf-8", "ignore"), f"{label} leaked a credential"
                        text = reopen(path, ext)
                        assert needle in text, f"{label} lost the validated title {title!r}"
                        assert SENTINEL not in text, f"{label} text leaked a credential"
                        if not markup:  # HTML is markup: real <b> tags are correct there
                            assert "<b>" not in text and "<strong>" not in text, \
                                f"{label} shipped literal markup tags"
                        sizes[ext] = len(raw)
                    # JSON is not a button; it is the document the UI renders (bearer fetch)
                    js = api.get(f"/api/engagements/{eid}/report?format=json")
                    assert js.status_code == 200, js.text
                    doc = js.json()
                    assert needle in json.dumps(doc), "report.json lost the validated title"
                    assert SENTINEL not in js.text and "<b>" not in json.dumps(doc["findings"])
                    sizes["json"] = len(js.content)
                    page.screenshot(path=out / "f2-report-exports-desktop.png", full_page=True)
                    return sizes
                sizes = st("3 every export downloads and reopens", exports)

                def mobile_views():
                    m = browser.new_context(viewport={"width": 390, "height": 844},
                                            accept_downloads=True, is_mobile=True)
                    mp = m.new_page()
                    mp.goto(f"{base}/engagements/{eid}?tab=evidence")
                    auth(mp)
                    mp.locator("tbody tr").first.click(timeout=30000)
                    expect(mp.get_by_text("intact", exact=True)).to_be_visible(timeout=30000)
                    mp.screenshot(path=out / "f1-evidence-chain-390.png", full_page=True)
                    mp.get_by_role("tab", name="Report").click(timeout=20000)
                    expect(mp.get_by_role("button", name="PDF", exact=True)).to_be_visible(timeout=30000)
                    mp.screenshot(path=out / "f2-report-exports-390.png", full_page=True)
                    m.close()
                st("4 desktop and 390px renders", mobile_views)

                baseline = {p.name: p.read_bytes() for p in report_dir.iterdir() if p.is_file()}

                def render_failure():
                    chattr(report_dir / "report.json", "+")
                    try:
                        assert is_immutable(report_dir / "report.json"), "immutable flag not set"
                        page.get_by_role("button", name="Regenerate").click()
                        note = page.locator("div", has_text="Report render failed").last
                        expect(note).to_be_visible(timeout=30000)
                        shown = note.inner_text()
                        assert "previous report" in shown, f"error is not actionable: {shown!r}"
                        assert re.search(r"Operation not permitted|Permission denied", shown), shown
                        # the controls survive the error, so the operator can retry
                        expect(page.get_by_role("button", name="Regenerate")).to_be_enabled()
                        expect(page.locator("td", has_text=needle).first).to_be_visible()
                        page.screenshot(path=out / "f3-render-failure-desktop.png", full_page=True)
                        # no partial artifacts, and the last good report is untouched
                        assert (report_dir / "report.json").read_bytes() == baseline["report.json"], \
                            "failed render modified the previous report.json"
                        assert {p.name for p in report_dir.iterdir()} == set(baseline), \
                            "failed render left a partial artifact behind"
                        assert needle in pdf_text(out / f"{eid}.pdf"), "previous PDF reports changed"
                        r = api.get(f"/api/engagements/{eid}/report?format=pdf")
                        assert r.status_code == 500, r.status_code
                        assert "Report render failed" in r.json()["detail"], r.text
                        assert not r.content.startswith(b"%PDF-"), "served a partial PDF"
                        return {"error": shown[:200], "status": r.status_code}
                    finally:
                        chattr(report_dir / "report.json", "-")
                failed = st("5 failing re-render shows an actionable error, keeps the last report",
                            render_failure)

                def recover():
                    page.get_by_role("button", name="Regenerate").click()
                    expect(page.get_by_text("Report render failed")).to_have_count(0, timeout=30000)
                    expect(page.locator("td", has_text=needle).first).to_be_visible(timeout=20000)
                    with page.expect_download(timeout=60000) as dl:
                        page.get_by_role("button", name="PDF", exact=True).click()
                    pdf = out / f"{eid}-recovered.pdf"
                    dl.value.save_as(pdf)
                    assert needle in pdf_text(pdf), "recovered PDF lost the validated title"
                    doc = json.loads((report_dir / "report.json").read_text())
                    assert any(needle in f["title"] for f in doc["findings"]), \
                        "regenerated report.json lost the finding"
                    page.screenshot(path=out / "f4-report-recovered-desktop.png", full_page=True)
                    return {"pdf_bytes": pdf.stat().st_size}
                rec = st("6 regenerate succeeds after the cause is removed", recover)

                def tamper():
                    blob = next(p for p in (data / "evidence" / eid).rglob("*")
                                if p.is_file() and p.parent.parent.name == eid
                                and re.fullmatch(r"[0-9a-f]{2}", p.parent.name))
                    blob.write_bytes(blob.read_bytes() + b" tampered")
                    page.get_by_role("tab", name="Evidence").click(timeout=20000)
                    page.locator("tbody tr").first.click(timeout=20000)
                    expect(page.get_by_text(re.compile(r"broken at ev_"))).to_be_visible(timeout=30000)
                    expect(page.get_by_text("intact", exact=True)).to_have_count(0)
                    page.screenshot(path=out / "f5-evidence-tampered-desktop.png", full_page=True)
                    body = api.get(f"/api/evidence/{evid}/chain").json()
                    assert body["ok"] is False and body["broken_at"].startswith("ev_"), body
                    return {"broken_at": body["broken_at"], "checked": body["checked"],
                            "reason": (body.get("error") or "chain hash mismatch")[:80]}
                tam = st("7 tampered blob shows a broken chain", tamper)

                assert not errors, errors
                browser.close()
            status = {"ok": True, "engagement": eid, "finding_title": title, "chain": chain,
                      "exports": sizes, "render_failure": failed, "recovered": rec,
                      "tamper": tam}
        finally:
            backend.terminate()
            lab.terminate()
            backend.wait(10)
            (out / "journey-f.json").write_text(json.dumps({**status, "stages": st.log}, indent=2))
    print(json.dumps(status))


if __name__ == "__main__":
    try:
        main(Path(sys.argv[1]))
    except Exception:
        sys.exit(1)
