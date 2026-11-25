"""Operations workspace acceptance: refresh, reconnect and restart during a live assessment.

Usage (repo root, after `npm run build` in web/):
    PYTHONPATH=src python benchmarks/acceptance_operations.py <out-dir>

Real backend, real PairLab (vuln mode, port 8841), a real engagement created with the
exact POST body the wizard builds, no seeded rows and no mocked events. nuclei is
reported absent to the server process (launcher below patches resolve_binary) so the
run stays short; that choice is recorded in facts. After each disturbance (reload,
offline 5s, fresh browser context) and at the terminal state, what the browser shows
is compared with the run's SQLite opened read-only. Writes checks.json {name: bool}
and facts.json; exits non-zero when any check fails.
"""
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
LAB_PORT = 8841
RPS = 3  # slower than the wizard default (10) so the run lasts long enough to disturb

LAUNCHER = '''
import sys
import libella.tools as t
import libella.main as m
real = t.resolve_binary
def resolve(name):
    return None if name == "nuclei" else real(name)
for mod in list(sys.modules.values()):
    if getattr(mod, "__name__", "").startswith("libella") and getattr(mod, "resolve_binary", None) is real:
        mod.resolve_binary = resolve
m.cli()
'''

checks: dict[str, bool] = {}
facts: dict = {"nuclei": "absent (resolve_binary patched in the server process)", "phases": {}}


def check(name: str, ok, detail=None):
    checks[name] = bool(ok)
    if not ok:
        print(f"FAIL {name}: {detail}", flush=True)
        facts.setdefault("failures", {})[name] = str(detail)[:600]
    else:
        print(f"PASS {name}", flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CutProxy:
    """TCP pass-through between the browser and Libella that can really sever the link:
    cut() resets every open connection (including the SSE stream) and refuses new ones
    until restore(). context.set_offline() does not drop an established stream."""

    def __init__(self, upstream: int):
        self.upstream, self.down, self.conns = upstream, False, set()
        self.lock = threading.Lock()
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            if self.down:
                c.close()
                continue
            try:
                u = socket.create_connection(("127.0.0.1", self.upstream), timeout=10)
            except OSError:
                c.close()
                continue
            u.settimeout(None)
            with self.lock:
                self.conns |= {c, u}
            for a, b in ((c, u), (u, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    def _pipe(self, a, b):
        try:
            while (d := a.recv(65536)):
                b.sendall(d)
        except OSError:
            pass
        for x in (a, b):
            try:
                x.close()
            except OSError:
                pass

    def cut(self):
        self.down = True
        with self.lock:
            victims, self.conns = list(self.conns), set()
        for x in victims:
            try:
                x.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            x.close()

    def restore(self):
        self.down = False


# ------------------------------------------------------------------ database

class RunDB:
    def __init__(self, path: Path, eid: str):
        self.path, self.eid = path, eid

    def q(self, sql, *args):
        c = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10)
        c.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in c.execute(sql, args)]
        finally:
            c.close()

    def snap(self) -> dict:
        e = self.eid
        events = self.q("SELECT seq, kind, payload_json FROM events WHERE engagement_id=?", e)
        return {
            "status": self.q("SELECT status FROM engagements WHERE id=?", e)[0]["status"],
            "intents": self.q("SELECT id, role, objective, status, attempts FROM intents "
                              "WHERE engagement_id=? ORDER BY created_at, id", e),
            "calls": self.q("SELECT id, tool, exit_code, scope_decision FROM tool_calls "
                            "WHERE engagement_id=? ORDER BY created_at, id", e),
            "findings": self.q("SELECT id, title, state FROM findings WHERE engagement_id=? ORDER BY id", e),
            "verifs": self.q("SELECT v.finding_id, v.attempt, v.verdict FROM verifications v "
                             "JOIN findings f ON f.id=v.finding_id WHERE f.engagement_id=? "
                             "ORDER BY v.finding_id, v.attempt", e),
            "n_events": len(events),
            "max_seq": max((x["seq"] for x in events), default=0),
            "kinds": Counter(x["kind"] for x in events),
            "degradations": [json.loads(x["payload_json"]).get("code") for x in events
                             if x["kind"] == "degradation"],
            "n_exchanges": self.q("SELECT COUNT(*) n FROM exchanges WHERE engagement_id=?", e)[0]["n"],
            "n_assets": self.q("SELECT COUNT(*) n FROM assets WHERE engagement_id=?", e)[0]["n"],
            "n_evidence": self.q("SELECT COUNT(*) n FROM evidence WHERE engagement_id=?", e)[0]["n"],
            "n_runs": self.q("SELECT COUNT(*) n FROM agent_runs WHERE engagement_id=?", e)[0]["n"],
            "spend": self.q("SELECT COALESCE(SUM(cost_usd),0) c FROM llm_usage WHERE engagement_id=?", e)[0]["c"],
        }


def sig(s: dict):
    return (s["status"], tuple(map(tuple, (i.values() for i in s["intents"]))), len(s["calls"]),
            tuple(map(tuple, (f.values() for f in s["findings"]))), len(s["verifs"]), s["max_seq"])


def stable_snap(db: RunDB, quiet=1.5, timeout=60) -> dict:
    """A DB snapshot that has not changed for `quiet` seconds (the UI debounces 600 ms)."""
    end, last, since = time.time() + timeout, None, time.time()
    while time.time() < end:
        s = db.snap()
        if last is not None and sig(s) == sig(last):
            if time.time() - since >= quiet:
                return s
        else:
            last, since = s, time.time()
        time.sleep(0.3)
    raise AssertionError("database never settled")


# ------------------------------------------------------------------------ UI

SCRAPE = r'''() => {
  const txt = (e) => (e ? e.innerText.replace(/\s+/g, " ").trim() : "");
  const section = (t) => [...document.querySelectorAll("section")]
    .find((s) => txt(s.querySelector("h2")) === t);
  const rows = (t) => {
    const s = section(t);
    return s ? [...s.querySelectorAll("tbody tr")].map((r) => [...r.children].map(txt))
                   .filter((r) => r.length > 2) : null;
  };
  const stat = (label) => {
    const d = [...document.querySelectorAll("div")].find((e) => e.children.length === 0 && txt(e) === label);
    return d && d.nextElementSibling ? txt(d.nextElementSibling) : null;
  };
  const h1 = document.querySelector("h1");
  const head = h1 ? h1.parentElement.parentElement : null;
  const tiles = {};
  const st = section("Findings by state");
  if (st) st.querySelectorAll(".grid > div").forEach((d) => {
    const k = [...d.children].map(txt); tiles[k[1].toLowerCase()] = Number(k[0]); });
  const banners = [...document.querySelectorAll(".bg-\\[\\#FFFAEB\\]")].map((b) => {
    const c = b.querySelector(".font-mono"); return c ? txt(c) : null; }).filter(Boolean);
  const act = section("Activity");
  const m = act ? txt(act.querySelector("header")).match(/(\d+) events/) : null;
  return {
    id: head ? txt(head.querySelector("button.font-mono")).replace(/\s/g, "") : null,
    headText: head ? txt(head) : "",
    status: h1 ? txt(h1.nextElementSibling) : null,
    live: (() => { const l = head && head.querySelector("[title='Live event stream']"); return l ? txt(l) : null; })(),
    intents: rows("Intents"), calls: rows("Tool calls"),
    agentRunsEmpty: !!section("Agent runs") && /No agent runs yet/.test(txt(section("Agent runs"))),
    stats: {assets: stat("Assets"), findings: stat("Findings"), intents: stat("Intents"),
            calls: stat("Tool calls"), refusals: stat("Scope refusals")},
    tiles, banners, activity: m ? Number(m[1]) : null,
    evidenceIds: [...document.querySelectorAll("tbody td .font-mono")].map(txt).filter((x) => /^ev_/.test(x)),
  };
}'''


def norm(s):
    return (s or "").replace("_", " ").lower()


def call_badge(decision):
    if not decision:
        return "—"
    if re.match(r"refused: (missing binary|argv build error|bad argv)", decision):
        return "not run"  # never reached a scope verdict
    return "refused" if decision.startswith("refused") else "allowed"


def money(n):
    return f"${n:.2f}" if (n == 0 or n >= 0.01) else f"${n:.4f}"


def compare(ui: dict, s: dict, tab: str, phase: str) -> dict:
    """Map check-name -> (ok, detail) for what `tab` shows against snapshot `s`."""
    out = {}
    eid = s["eid"]
    out["engagement_id"] = (ui["id"] == eid, ui["id"])
    out["status_matches"] = (norm(ui["status"]) == norm(s["status"]), (ui["status"], s["status"]))
    out["spend_matches"] = (f"spend {money(s['spend'])}" in ui["headText"], (ui["headText"], s["spend"]))
    if tab == "operations":
        want = Counter((norm(i["role"]), i["objective"], norm(i["status"]), str(i["attempts"]))
                       for i in s["intents"])
        got = Counter((r[0].lower(), r[1], r[2].lower(), r[3]) for r in (ui["intents"] or []))
        out["intents_match"] = (want == got, (dict(want), dict(got)))
        out["no_duplicate_plan"] = (
            max(Counter((i["role"], i["objective"]) for i in s["intents"]).values(), default=0) == 1
            and max(got.values(), default=0) == 1 and s["kinds"]["intent_created"] == len(s["intents"])
            and s["kinds"]["engagement_started"] == 1 and not s["kinds"]["plan_resumed"],
            {"created_events": s["kinds"]["intent_created"], "intents": len(s["intents"]),
             "started": s["kinds"]["engagement_started"]})
        want = Counter((c["tool"], "—" if c["exit_code"] is None else str(c["exit_code"]),
                        call_badge(c["scope_decision"])) for c in s["calls"])
        got = Counter((r[1], r[4], r[3].lower()) for r in (ui["calls"] or []))
        out["tool_calls_match"] = (want == got, (dict(want), dict(got)))
        out["agent_state_matches"] = ((s["n_runs"] == 0) == ui["agentRunsEmpty"], s["n_runs"])
    else:  # overview
        refusals = sum(1 for c in s["calls"] if call_badge(c["scope_decision"]) == "refused")
        done = sum(1 for i in s["intents"] if i["status"] == "done")
        want = {"assets": str(s["n_assets"]), "findings": str(len(s["findings"])),
                "intents": f"{done}/{len(s['intents'])}", "calls": str(len(s["calls"])),
                "refusals": str(refusals)}
        out["overview_stats_match"] = (ui["stats"] == want, (ui["stats"], want))
        by_state = Counter(norm(f["state"]) for f in s["findings"])
        out["finding_states_match"] = (ui["tiles"] == dict(by_state), (ui["tiles"], dict(by_state)))
        out["verification_counts_consistent"] = (
            all(f["state"] != "validated" or any(v["finding_id"] == f["id"] and v["verdict"] for v in s["verifs"])
                for f in s["findings"]), len(s["verifs"]))
        # newest five degradation events are the banners; scan_partial must be among them when it exists
        want_b = [c for c in reversed(s["degradations"])][:5]
        out["degradation_banners_match"] = (ui["banners"] == want_b, (ui["banners"], want_b))
        if "scan_partial" in s["degradations"]:
            out["partial_scan_indicator"] = ("scan_partial" in ui["banners"], ui["banners"])
        out["activity_count_matches"] = (ui["activity"] == min(s["n_events"], 400), (ui["activity"], s["n_events"]))
    return out


def judge(page, db: RunDB, tab: str, phase: str, timeout=45):
    """Open `tab`, wait until DB and UI agree on a quiet snapshot (or time out), record checks."""
    end = time.time() + timeout
    res = {}
    while True:
        page.get_by_role("tab", name=tab.capitalize(), exact=True).click()
        time.sleep(1.0)
        s = stable_snap(db)
        s["eid"] = db.eid
        ui = page.evaluate(SCRAPE)
        res = compare(ui, s, tab, phase)
        if all(ok for ok, _ in res.values()) or time.time() > end:
            break
        time.sleep(1.5)
    for name, (ok, detail) in res.items():
        check(f"{phase}/{tab}/{name}", ok, detail)
    facts["phases"].setdefault(phase, {})[tab] = {"status": s["status"], "live": ui["live"],
                                                  "intents": len(s["intents"]), "calls": len(s["calls"]),
                                                  "events": s["n_events"], "exchanges": s["n_exchanges"]}
    return s, ui


def evidence_resolves(api, page, db: RunDB, phase: str):
    page.get_by_role("tab", name="Evidence", exact=True).click()
    time.sleep(1.5)
    ids = page.evaluate(SCRAPE)["evidenceIds"]
    known = {r["id"] for r in db.q("SELECT id FROM evidence WHERE engagement_id=?", db.eid)}
    bad = [i for i in ids if api.get(f"/api/evidence/{i}").status_code != 200 or i not in known]
    check(f"{phase}/evidence/links_resolve", ids and not bad, {"shown": len(ids), "bad": bad[:5]})


# ---------------------------------------------------------------------- main

def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="ops-accept-"))
    (scratch / "launch.py").write_text(LAUNCHER)
    lab = subprocess.Popen([sys.executable, str(ROOT / "labs/pairlab/app.py")],
                           env={**os.environ, "LAB_PORT": str(LAB_PORT), "LAB_MODE": "vuln"},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port = free_port()
    token = "ops-" + os.urandom(12).hex()
    base = f"http://127.0.0.1:{port}"
    data = scratch / "data"
    backend = subprocess.Popen(
        [sys.executable, str(scratch / "launch.py"), "--data-dir", str(data), "--port", str(port)],
        env={**os.environ, "LIBELLA_TOKEN": token, "PYTHONPATH": str(ROOT / "src"),
             "LIBELLA_WEB_DIST": str(ROOT / "web/dist")},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cutter = CutProxy(port)
    browser_base = f"http://127.0.0.1:{cutter.port}"  # the browser reaches Libella through the cutter
    api = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    try:
        for _ in range(150):
            try:
                if api.get("/api/health").status_code == 200 and httpx.get(
                        f"http://127.0.0.1:{LAB_PORT}", timeout=2).status_code < 500:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            raise RuntimeError("lab or backend did not start")

        import libella
        check("worktree_is_under_test", Path(libella.__file__).resolve().is_relative_to(ROOT), libella.__file__)
        # the served bundle must be the one just built
        built = re.search(r"assets/(index-[\w-]+\.js)", (ROOT / "web/dist/index.html").read_text()).group(1)
        check("served_bundle_is_current", built in api.get("/").text, built)

        body = {"name": "Operations acceptance (demo lab)", "profile": "safe_active",
                "scope": {"targets": [{"kind": "url", "value": f"http://127.0.0.1:{LAB_PORT}"}],
                          "exclusions": [], "categories": ["recon", "web"], "rate_limit_rps": RPS,
                          "max_concurrency": 4, "advanced_validation": False},
                "budgets": {}, "auth": {"identities": []}}
        r = api.post("/api/engagements", json=body)
        r.raise_for_status()
        eid = r.json()["id"]
        facts.update(engagement=eid, rps=RPS, target=f"http://127.0.0.1:{LAB_PORT}", categories=["recon", "web"])
        db = RunDB(data / "libella.db", eid)
        url = f"{browser_base}/engagements/{eid}?tab=operations"

        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            ctx = browser.new_context(viewport={"width": 1440, "height": 900})
            page = ctx.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            def login(pg, target_url):
                pg.goto(target_url)
                pg.get_by_label("API token").fill(token)
                pg.get_by_role("button", name="Connect", exact=True).click()
                expect(pg.locator("h1").first).to_be_visible(timeout=20000)

            def shot(pg, name):
                for w, h, suffix in ((1440, 900, ""), (390, 844, "-390")):
                    pg.set_viewport_size({"width": w, "height": h})
                    time.sleep(0.4)
                    pg.screenshot(path=out / f"ops-{name}{suffix}.png", full_page=True)
                pg.set_viewport_size({"width": 1440, "height": 900})

            login(page, url)
            expect(page.locator("h1").first).to_contain_text("Operations acceptance")
            page.get_by_role("button", name="Start", exact=True).click()
            end = time.time() + 60
            while time.time() < end:
                s = db.snap()
                if any(i["status"] == "running" for i in s["intents"]) and s["n_exchanges"] > 0:
                    break
                time.sleep(0.3)
            else:
                raise AssertionError("no running intent with exchanges")
            facts["first_running_intent"] = [i["role"] for i in s["intents"] if i["status"] == "running"]

            def running_now(phase):
                st = db.snap()["status"]
                check(f"{phase}/disturbed_mid_run", st == "running", st)

            # A: running
            running_now("running")
            baseline, _ = judge(page, db, "operations", "running")
            judge(page, db, "overview", "running")
            evidence_resolves(api, page, db, "running")
            page.get_by_role("tab", name="Operations", exact=True).click()
            shot(page, "running")
            ids_before = {i["id"]: (i["role"], i["objective"]) for i in db.snap()["intents"]}

            # B: reload mid-run (the token lives in memory only, so the app asks for it again)
            page.reload()
            check("reload/asks_for_token_not_state", page.get_by_label("API token").is_visible())
            page.get_by_label("API token").fill(token)
            page.get_by_role("button", name="Connect", exact=True).click()
            expect(page.locator("h1").first).to_be_visible(timeout=20000)
            check("reload/route_kept", "tab=operations" in page.url and eid in page.url, page.url)
            running_now("reload")
            judge(page, db, "operations", "reload")
            judge(page, db, "overview", "reload")
            page.get_by_role("tab", name="Operations", exact=True).click()
            shot(page, "after-reload")

            # C: browser restart: a second, empty context
            ctx2 = browser.new_context(viewport={"width": 1440, "height": 900})
            page2 = ctx2.new_page()
            page2.on("pageerror", lambda e: errors.append(str(e)))
            login(page2, url)
            running_now("fresh_context")
            judge(page2, db, "operations", "fresh_context")
            judge(page2, db, "overview", "fresh_context")
            now = {i["id"]: (i["role"], i["objective"]) for i in db.snap()["intents"]}
            check("plan_ids_stable", all(now.get(k) == v for k, v in ids_before.items()),
                  {"before": len(ids_before), "now": len(now)})
            ctx2.close()

            # D: real network interruption: the link is severed until Libella has produced events
            # the browser cannot have seen (at least 5 s, at most 75 s)
            running_now("reconnect")
            ev_before = db.snap()["max_seq"]
            t_cut = time.time()
            cutter.cut()
            seen = None
            while time.time() - t_cut < 75:
                seen = page.evaluate(SCRAPE)["live"] or seen
                if time.time() - t_cut >= 5 and db.snap()["max_seq"] > ev_before:
                    break
                time.sleep(0.5)
            facts["offline_indicator"] = seen
            facts["events_while_offline"] = db.snap()["max_seq"] - ev_before
            check("reconnect/stream_drop_is_visible", seen == "offline", seen)
            check("reconnect/events_missed_while_cut", facts["events_while_offline"] > 0, facts["events_while_offline"])
            cutter.restore()
            facts["cut_seconds"] = round(time.time() - t_cut, 1)
            end = time.time() + 40
            while time.time() < end and page.evaluate(SCRAPE)["live"] != "live" and db.snap()["status"] == "running":
                time.sleep(0.5)
            check("reconnect/stream_back_live", page.evaluate(SCRAPE)["live"] == "live" or db.snap()["status"] != "running",
                  page.evaluate(SCRAPE)["live"])
            judge(page, db, "operations", "reconnect")
            judge(page, db, "overview", "reconnect")
            page.get_by_role("tab", name="Operations", exact=True).click()
            shot(page, "after-reconnect")

            # E: terminal
            end = time.time() + 240
            while time.time() < end and db.snap()["status"] in ("running", "queued"):
                time.sleep(1)
            fin = db.snap()
            check("terminal/db_status_done", fin["status"] == "done", fin["status"])
            page.reload()
            page.get_by_label("API token").fill(token)
            page.get_by_role("button", name="Connect", exact=True).click()
            expect(page.locator("h1").first).to_be_visible(timeout=20000)
            judge(page, db, "operations", "terminal")
            s, ui = judge(page, db, "overview", "terminal")
            check("terminal/live_indicator_gone", ui["live"] is None, ui["live"])
            evidence_resolves(api, page, db, "terminal")
            page.get_by_role("tab", name="Operations", exact=True).click()
            shot(page, "terminal")

            # report availability through the UI's own download path
            page.get_by_role("tab", name="Report", exact=True).click()
            expect(page.get_by_role("button", name="JSON", exact=True)).to_be_visible(timeout=20000)
            with page.expect_download(timeout=30000) as dl:
                page.get_by_role("button", name="JSON", exact=True).click()
            path = out / "downloaded-report.json"
            dl.value.save_as(path)
            rep = json.loads(path.read_text())
            fin = stable_snap(db)
            check("terminal/report_reopens", rep["engagement"]["id"] == eid and rep["engagement"]["status"] == "done",
                  rep["engagement"])
            check("terminal/report_counts_match_db",
                  rep["summary"]["intents"] == len(fin["intents"])
                  and rep["summary"]["findings_total"] == len(fin["findings"])
                  and rep["summary"]["tool_calls"] == len(fin["calls"]), rep["summary"])
            # verification column on the Report tab vs the verifications table
            last = {}
            for v in fin["verifs"]:
                last[v["finding_id"]] = v["verdict"]
            shown = page.evaluate(r'''() => [...document.querySelectorAll("section")]
              .find((s) => /^Findings \(/.test(s.querySelector("h2")?.innerText || ""))
              ?.querySelectorAll("tbody tr") ? [...[...document.querySelectorAll("section")]
              .find((s) => /^Findings \(/.test(s.querySelector("h2").innerText)).querySelectorAll("tbody tr")]
              .map((r) => [...r.children].map((c) => c.innerText.trim())) : []''')
            want = Counter((f["title"], last.get(f["id"], "none")) for f in fin["findings"])
            got = Counter((r[1], r[4]) for r in shown)
            check("terminal/verification_statuses_match", want == got and len(shown) == len(fin["findings"]),
                  {"want": dict(want), "got": dict(got)})
            shot(page, "terminal-report")
            facts["report_summary"] = rep["summary"]
            facts["final"] = {"intents": Counter(norm(i["role"]) for i in fin["intents"]), "events": fin["n_events"],
                              "verifications": len(fin["verifs"]), "degradations": fin["degradations"]}
            check("no_page_errors", not errors, errors[:3])
            browser.close()
    finally:
        cutter.cut()
        for p in (backend, lab):
            p.terminate()
        for p in (backend, lab):
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        (out / "checks.json").write_text(json.dumps(checks, indent=2))
        (out / "facts.json").write_text(json.dumps(facts, indent=2, default=str))
    failed = [k for k, v in checks.items() if not v]
    print(json.dumps({"passed": len(checks) - len(failed), "failed": failed}))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
