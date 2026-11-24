"""Journey E: execution controls through the real application.

Start -> Running -> Pause -> Paused -> Resume -> Running -> Cancel -> Cancelled,
then a second engagement whose authorized window closes mid-run, plus the
declared request rate. Everything is measured at the target: a counting reverse
proxy sits in front of PairLab, so "no egress after a stop" is a request log, not
a claim.

Usage (repo root, after `npm run build` in web/):
    PYTHONPATH=src python benchmarks/check_execution_controls_ui.py <out-dir>
Every stage prints PASS/FAIL; the first failing stage is reported and exits 1.
"""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
CAP_RPS = 5
WINDOW_S = 20          # authorized window closes this long after Start
SCANNER_WAIT_S = 240   # how long to wait for nuclei to appear before cancelling

# The counting proxy: forwards to the lab and appends one JSON line per egress
# attempt, so the harness can measure rate and post-stop silence exactly.
PROXY_SRC = r'''
import http.client, json, os, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UP = os.environ["PROXY_UPSTREAM"].split("//", 1)[1]
HOST, _, PORT = UP.partition(":")
PORT = int(PORT or 80)
LOG = os.environ["PROXY_LOG"]


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _proxy(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        with open(LOG, "a") as f:
            f.write(json.dumps({"t": time.time(), "m": self.command, "p": self.path}) + "\n")
        hdrs = {k: v for k, v in self.headers.items()
                if k.lower() not in ("host", "connection", "content-length")}
        try:
            conn = http.client.HTTPConnection(HOST, PORT, timeout=20)
            conn.request(self.command, self.path, body=body, headers=hdrs)
            r = conn.getresponse()
            data = r.read()
        except OSError:
            self.send_error(502)
            return
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in ("transfer-encoding", "content-length", "connection"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _proxy


ThreadingHTTPServer(("127.0.0.1", int(os.environ["PROXY_PORT"])), H).serve_forever()
'''


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
            import traceback
            tb = traceback.format_exc().strip().splitlines()[-6:]
            self.log.append({"stage": name, "ok": False, "s": round(time.time() - t0, 1),
                             "error": f"{type(e).__name__}: {str(e)[:400]}", "trace": tb})
            print(f"FAIL {name}: {type(e).__name__}: {str(e)[:400]}", flush=True)
            print("\n".join(tb), flush=True)
            raise
        self.log.append({"stage": name, "ok": True, "s": round(time.time() - t0, 1),
                         "result": out})
        print(f"PASS {name} ({time.time() - t0:.1f}s)", flush=True)
        return out


def hits(log: Path) -> list[float]:
    try:
        return [json.loads(line)["t"] for line in log.read_text().splitlines() if line.strip()]
    except (OSError, ValueError):
        return []


def descendants(pid: int) -> list[str]:
    """cmdlines of every descendant of pid (no psutil dependency)."""
    parent, cmd = {}, {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            parent[int(entry.name)] = int(stat.rsplit(")", 1)[1].split()[1])
            cmd[int(entry.name)] = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                errors="replace")
        except (OSError, IndexError, ValueError):
            continue
    out, frontier = [], [pid]
    while frontier:
        p = frontier.pop()
        for child, ppid in parent.items():
            if ppid == p:
                out.append(cmd.get(child, ""))
                frontier.append(child)
    return out


def scanners(pid: int) -> list[str]:
    return [c for c in descendants(pid)
            if any(t in c.lower() for t in ("nuclei", "httpx", "nmap", "ffuf", "chrom"))]


def tool_scanners(pid: int) -> list[str]:
    """External scanners only: the browser crawl is egress too, but it is not the
    long-running tool a cancel has to kill."""
    return [c for c in descendants(pid)
            if any(t in c.lower() for t in ("nuclei", "httpx", "nmap", "ffuf"))]


def rate_stats(stamps: list[float]) -> dict:
    """Requests per second: peak one-second bucket and mean over the measured span."""
    if len(stamps) < 2:
        return {"hits": len(stamps), "mean_rps": 0.0, "peak_rps": len(stamps), "span_s": 0.0}
    stamps = sorted(stamps)
    span = stamps[-1] - stamps[0]
    buckets = {}
    for t in stamps:
        buckets[int(t)] = buckets.get(int(t), 0) + 1
    return {"hits": len(stamps), "span_s": round(span, 1),
            "mean_rps": round(len(stamps) / span, 2) if span > 0 else 0.0,
            "peak_rps": max(buckets.values())}


def header(page):
    """The engagement header (h1 + status badge) — rendered text, not the DOM textContent."""
    return page.locator("h1").first.locator("xpath=..")


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    st = Stage()
    status = {"ok": False}
    scratch = Path(tempfile.mkdtemp(prefix="exec-controls-"))
    log = scratch / "lab-hits.jsonl"
    log.write_text("")
    proxy_src = scratch / "proxy.py"
    proxy_src.write_text(PROXY_SRC)
    lab_port, proxy_port = free_port(), free_port()
    lab = subprocess.Popen([sys.executable, str(ROOT / "labs/pairlab/app.py")],
                           env={**os.environ, "LAB_PORT": str(lab_port), "LAB_MODE": "vuln"},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = subprocess.Popen([sys.executable, str(proxy_src)],
                             env={**os.environ, "PROXY_UPSTREAM": f"http://127.0.0.1:{lab_port}",
                                  "PROXY_PORT": str(proxy_port), "PROXY_LOG": str(log)},
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    target = f"http://127.0.0.1:{proxy_port}"

    with tempfile.TemporaryDirectory() as data:
        port = free_port()
        token = "exec-" + os.urandom(12).hex()
        base = f"http://127.0.0.1:{port}"
        backend = subprocess.Popen(
            [sys.executable, "-m", "libella.main", "--data-dir", str(Path(data) / "data"),
             "--port", str(port)],
            env={**os.environ, "LIBELLA_TOKEN": token, "PYTHONPATH": str(ROOT / "src"),
                 "LIBELLA_WEB_DIST": str(ROOT / "web/dist")},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        api = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=30)

        def engagement(name, window_end=None):
            body = {"name": name, "profile": "safe_active",
                    "scope": {"targets": [{"kind": "url", "value": target}],
                              "categories": ["recon", "web", "api", "infra"],
                              "rate_limit_rps": CAP_RPS},
                    "budgets": {"max_duration_s": 900},
                    "window_start": time.time() - 60 if window_end else None,
                    "window_end": window_end}
            r = api.post("/api/engagements", json=body)
            r.raise_for_status()
            return r.json()["id"]

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
                        if httpx.get(target, timeout=2).status_code < 500:
                            return
                    except httpx.HTTPError:
                        time.sleep(0.2)
                raise RuntimeError("lab, proxy or backend did not start")

            st("0 lab, counting proxy and backend start", wait_up)
            eid = engagement("Execution controls (demo lab)")

            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                ctx = browser.new_context(viewport={"width": 1440, "height": 900})
                page = ctx.new_page()
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))

                def shot(name, mobile=False):
                    if mobile:
                        page.set_viewport_size({"width": 390, "height": 844})
                        page.screenshot(path=out / f"e-{name}-390.png", full_page=False)
                        page.set_viewport_size({"width": 1440, "height": 900})
                    else:
                        page.screenshot(path=out / f"e-{name}.png", full_page=False)

                def connect():
                    page.goto(base)
                    page.get_by_label("API token").fill(token)
                    page.get_by_role("button", name="Connect", exact=True).click()
                    expect(page.get_by_role("link", name="Engagements", exact=True)).to_be_visible(
                        timeout=20000)
                    page.get_by_role("link", name="Engagements", exact=True).click()
                    page.get_by_text("Execution controls (demo lab)").first.click()
                    expect(page).to_have_url(re.compile(rf"/engagements/{re.escape(eid)}"),
                                             timeout=20000)
                st("1 connect and open the engagement", connect)

                def start():
                    page.get_by_role("button", name="Start", exact=True).click(timeout=15000)
                    expect(header(page)).to_contain_text("Running", timeout=30000, use_inner_text=True)
                    deadline = time.time() + 20
                    while time.time() < deadline and not hits(log):
                        time.sleep(0.2)
                    assert hits(log), "the run reported Running but the target saw no requests"
                    shot("1-running")
                    shot("1-running", mobile=True)
                st("2 Start -> Running (target traffic observed)", start)

                def paused():
                    page.get_by_role("button", name="Pause", exact=True).click(timeout=15000)
                    expect(header(page)).to_contain_text("Paused", timeout=20000, use_inner_text=True)
                    shot("2-paused")
                    shot("2-paused", mobile=True)
                    time.sleep(2)  # let the in-flight step settle
                    before = len(hits(log))
                    time.sleep(3)
                    after = len(hits(log))
                    assert after == before, f"{after - before} target requests while paused"
                    assert not scanners(backend.pid), f"paused but scanning: {scanners(backend.pid)}"
                    return {"hits_while_paused": after - before}
                st("3 Pause -> Paused, no target traffic and no live scanner", paused)

                def resumed():
                    page.get_by_role("button", name="Resume", exact=True).click(timeout=15000)
                    expect(header(page)).to_contain_text("Running", timeout=30000, use_inner_text=True)
                    before = len(hits(log))
                    deadline = time.time() + 40
                    while time.time() < deadline and len(hits(log)) == before:
                        time.sleep(0.3)
                    assert len(hits(log)) > before, "resume did not restart target traffic"
                    shot("3-resumed")
                    t0 = time.time()  # a clean 12s sample of the declared rate
                    time.sleep(12)
                    return rate_stats([t for t in hits(log) if t0 <= t <= time.time()])
                sample = st("4 Resume -> Running, target traffic restarts", resumed)

                def rate():
                    page.get_by_role("tab", name="Overview").click(timeout=15000)
                    expect(page.get_by_text(f"{CAP_RPS} req/s", exact=False).first).to_be_visible(
                        timeout=15000)
                    assert sample["hits"] >= 10, f"too little traffic to judge the rate: {sample}"
                    # the probe dispatches one request per 1/rps; a 1s bucket can also
                    # catch a browser page-load burst, so judge materially
                    assert sample["mean_rps"] <= CAP_RPS * 1.2, f"rate {sample} exceeded cap {CAP_RPS}"
                    assert sample["peak_rps"] <= CAP_RPS * 3, f"burst {sample} far above cap {CAP_RPS}"
                    return {"cap_rps": CAP_RPS, **sample}
                rate_seen = st("5 declared rate shown in the UI and held at the target", rate)

                def cancelled():
                    deadline = time.time() + SCANNER_WAIT_S
                    while time.time() < deadline and not tool_scanners(backend.pid):
                        if api.get(f"/api/engagements/{eid}").json()["status"] != "running":
                            break
                        time.sleep(0.5)
                    running = tool_scanners(backend.pid)
                    assert running, f"no scanner subprocess appeared to cancel ({running})"
                    page.get_by_role("button", name="Cancel", exact=True).click(timeout=15000)
                    expect(page.get_by_role("button", name="Cancel engagement")).to_be_visible(
                        timeout=15000)
                    t_click = time.time()
                    page.get_by_role("button", name="Cancel engagement").click()
                    expect(header(page)).to_contain_text("Cancelled", timeout=30000, use_inner_text=True)
                    ui_s = round(time.time() - t_click, 1)
                    time.sleep(2)  # settle: the worker notices within one poll
                    settle = time.time()
                    time.sleep(10)
                    after = hits(log)
                    leaked = [t for t in after if t > settle]
                    assert not leaked, f"{len(leaked)} target requests after cancel settled"
                    assert not scanners(backend.pid), f"scanner still alive: {scanners(backend.pid)}"
                    last = max([t for t in hits(log) if t <= time.time()], default=t_click)
                    shot("4-cancelled")
                    shot("4-cancelled", mobile=True)
                    return {"cancel_to_ui_s": ui_s,
                            "hits_10s_before_cancel": len([t for t in hits(log)
                                                           if t_click - 10 <= t <= t_click]),
                            "cancel_to_last_egress_s": round(last - t_click, 1),
                            "egress_silent_s": round(time.time() - settle, 1),
                            "scanners_killed": len(running)}
                cancel = st("6 Cancel -> Cancelled, scanner killed, zero egress for 10s", cancelled)

                def window_closed():
                    # a fresh engagement: the authorized window closes WINDOW_S after it starts
                    wid = engagement("Window expiry (demo lab)", window_end=time.time() + WINDOW_S)
                    page.get_by_role("link", name="Engagements", exact=True).click()
                    page.get_by_text("Window expiry (demo lab)").first.click()
                    expect(page).to_have_url(re.compile(rf"/engagements/{re.escape(wid)}"),
                                             timeout=20000)
                    page.get_by_role("button", name="Start", exact=True).click(timeout=20000)
                    try:
                        expect(header(page)).to_contain_text("Running", timeout=30000,
                                                             use_inner_text=True)
                        expect(header(page)).to_contain_text(re.compile("window closed", re.I),
                                                            timeout=120000, use_inner_text=True)
                    except AssertionError:
                        page.screenshot(path=out / "f-window-failed.png")
                        raise AssertionError(
                            f"header reads {header(page).inner_text()[:120]!r}; "
                            f"api status {api.get(f'/api/engagements/{wid}').json()['status']!r}")
                    expect(page.get_by_text("Create a new engagement with an authorized window",
                                            exact=False).first).to_be_visible(timeout=20000)
                    row = api.get(f"/api/engagements/{wid}").json()
                    assert row["status"] == "window_closed", row["status"]
                    assert "window_end" in (row["status_detail"] or ""), row["status_detail"]
                    end = float(row["window_end"])  # the window columns are text-typed
                    time.sleep(5)
                    late = [t for t in hits(log) if t > end + 2]  # 2s for the kill to land
                    assert not late, f"{len(late)} target requests after the window closed"
                    shot("5-window-closed")
                    shot("5-window-closed", mobile=True)
                    return {"engagement": wid, "status": row["status"],
                            "detail": row["status_detail"],
                            "hits_last_20s_before_close": len([t for t in hits(log) if end - 20 <= t <= end]),
                            "requests_after_close": len(late)}
                window = st("7 window expiry -> Window closed, actionable message, no egress", window_closed)

                assert not errors, errors
                browser.close()
            status = {"ok": True, "engagement": eid,
                      "rate": rate_seen, "cancel": cancel, "window": window}
        finally:
            for p in (backend, proxy, lab):
                p.terminate()
            for p in (backend, proxy, lab):
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()
            (out / "execution_controls.json").write_text(
                json.dumps({**status, "stages": st.log}, indent=2, default=str))
    print(json.dumps(status, default=str))


if __name__ == "__main__":
    try:
        main(Path(sys.argv[1]))
    except Exception:
        sys.exit(1)
