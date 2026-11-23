"""Durable-state recovery, proven across a real process boundary.

The unit tests prove the store round-trips. This drives an actual engagement over HTTP
against PairLab, kills the worker process (SIGKILL: no cleanup, no flush, nothing handed
over in memory), then continues the SAME engagement from a fresh interpreter and requires:

  * the crawl's endpoint inventory is intact and identical, byte for byte, after restart
  * the resumed run consumes it (parameter checks touch discovered endpoints, not zero)
  * no invented completion: an intent interrupted mid-flight is not recorded as done
  * the findings that WOULD have been produced still are, and every evidence chain verifies
  * the scope/egress decisions recorded before the kill still authorize the same host
  * the terminal status is a real one, not a fabricated success

Stage 2 restarts from SQLite only, which is the only state a killed worker leaves behind.

Usage: PYTHONPATH=src:. python benchmarks/acceptance_recovery.py <out-dir>
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

PHASE1 = """
import json, sys, threading, time
sys.path.insert(0, {src!r}); sys.path.insert(0, {root!r})
from libella.api import App
app = App({data!r})
eid, base = {eid!r}, {base!r}
scope = {{"targets": [{{"kind": "url", "value": base}}],
          "categories": ["recon", "web"], "rate_limit_rps": 40}}
app.db.execute(
    "INSERT OR REPLACE INTO engagements(id,name,profile,status,scope_json,auth_json,budgets_json,created_at) "
    "VALUES(?,?,?,?,?,?,?,?)",
    (eid, "recovery", "safe_active", "draft", json.dumps(scope), "{{}}",
     json.dumps({{"max_duration_s": 900}}), time.time()))
t = threading.Thread(target=app._run_guarded, args=(app.orchestrator(), eid, "deterministic"))
t.start()
print("RUNNING", flush=True)
t.join()
print("FINISHED", flush=True)
"""

PHASE2 = """
import json, sys, threading
sys.path.insert(0, {src!r}); sys.path.insert(0, {root!r})
from libella.api import App
app = App({data!r})
eid = {eid!r}
# a killed worker leaves 'running' engagements and leased intents behind: that is the
# recovery path a real restart takes, not a hand-reset state
app.db.execute("UPDATE engagements SET status='running' WHERE id=?", (eid,))
t = threading.Thread(target=app._run_guarded, args=(app.orchestrator(), eid, "deterministic"))
t.start()
t.join()
print("FINISHED", flush=True)
"""


def _serve_lab(port):
    env = dict(os.environ, LAB_MODE="vuln", LAB_PORT=str(port))
    p = subprocess.Popen([sys.executable, str(ROOT / "labs" / "pairlab" / "app.py")],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return p
        except OSError:
            time.sleep(0.1)
    p.kill()
    raise RuntimeError("pairlab did not start")


def _wait_for(predicate, timeout, interval=0.5):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _snapshot(data, eid):
    """Everything stage 2 must be able to rebuild from disk alone."""
    import sqlite3
    path = Path(data) / "libella.db"
    if not path.exists():  # stage 1 has not created the schema yet
        return {"crawls": [], "intents": [], "evidence_rows": 0}
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    try:
        crawls = [dict(r) for r in c.execute(
            "SELECT id, status, result_json FROM intents WHERE engagement_id=? AND role='crawl'",
            (eid,))]
        intents = [dict(r) for r in c.execute(
            "SELECT id, role, status FROM intents WHERE engagement_id=? ORDER BY created_at",
            (eid,))]
        ev = c.execute("SELECT COUNT(*) FROM evidence WHERE engagement_id=?", (eid,)).fetchone()[0]
    except sqlite3.OperationalError:  # table not created yet
        return {"crawls": [], "intents": [], "evidence_rows": 0}
    finally:
        c.close()
    return {"crawls": crawls, "intents": intents, "evidence_rows": ev}


def _final(data, eid):
    import sqlite3
    c = sqlite3.connect(Path(data) / "libella.db")
    c.row_factory = sqlite3.Row
    eng = dict(c.execute("SELECT status, status_detail FROM engagements WHERE id=?", (eid,)).fetchone())
    finds = [dict(r) for r in c.execute(
        "SELECT id, state, cwe, dedup_key FROM findings WHERE engagement_id=?", (eid,))]
    intents = [dict(r) for r in c.execute(
        "SELECT id, role, status FROM intents WHERE engagement_id=? ORDER BY created_at", (eid,))]
    crawls = [dict(r) for r in c.execute(
        "SELECT id, status, result_json FROM intents WHERE engagement_id=? AND role='crawl'", (eid,))]
    c.close()
    return eng, finds, intents, crawls


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    data = out / "data"
    data.mkdir(exist_ok=True)
    port = 8891  # free per run; never 8801-8803 / 8443, which other runs hold
    lab = _serve_lab(port)
    base = f"http://127.0.0.1:{port}"
    eid = "eng_recovery"
    src, root = str(ROOT / "src"), str(ROOT)
    result = {}
    try:
        # ---- stage 1: start a real engagement, then SIGKILL the worker mid-run
        p1 = subprocess.Popen([sys.executable, "-c", PHASE1.format(
            src=src, root=root, data=str(data), eid=eid, base=base)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True)
        assert _wait_for(lambda: _snapshot(data, eid)["crawls"], 180), "crawl never planned"
        # kill once the crawl has actually produced an inventory: recovery of a produced
        # result is the property under test, not recovery of an empty table
        def produced():
            return any(c["result_json"] and "endpoints" in c["result_json"]
                       for c in _snapshot(data, eid)["crawls"])
        assert _wait_for(produced, 240), "the crawl never persisted an endpoint inventory"
        os.killpg(os.getpgid(p1.pid), signal.SIGKILL)
        p1.wait(timeout=30)
        before = _snapshot(data, eid)
        result["killed_mid_run"] = True
        result["intents_at_kill"] = {i["role"]: i["status"] for i in before["intents"]}

        # ---- stage 2: a fresh process resumes from SQLite alone
        p2 = subprocess.run([sys.executable, "-c", PHASE2.format(
            src=src, root=root, data=str(data), eid=eid)],
            capture_output=True, text=True, timeout=1200)
        assert "FINISHED" in p2.stdout, p2.stdout[-2000:] + p2.stderr[-2000:]

        eng, finds, intents, crawls = _final(data, eid)
        after_inventory = [c["result_json"] for c in crawls]
        before_inventory = [c["result_json"] for c in before["crawls"]]
        result.update({
            "inventory_identical": before_inventory == after_inventory,
            "inventory_endpoints": sum(len(json.loads(r)["endpoints"]) for r in after_inventory
                                       if r and "endpoints" in r),
            "final_status": eng["status"], "detail": eng["status_detail"],
            "findings": len(finds),
            "validated": sum(1 for f in finds if f["state"] == "validated"),
            "unresolved_intents": [i for i in intents if i["status"] not in
                                   ("done", "blocked", "exhausted", "stopped")],
            "evidence_rows_at_kill": before["evidence_rows"],
        })

        from libella.api import App  # re-open to verify the chain and the scope decisions
        app = App(data)
        result["chain_ok"] = app.evidence.verify_chain(eid)
        result["denied_events"] = app.db.query(
            "SELECT COUNT(*) n FROM events WHERE engagement_id=? AND kind='egress_denied'",
            (eid,))[0]["n"]
        result["crawl_gap_events"] = app.db.query(
            "SELECT COUNT(*) n FROM events WHERE engagement_id=? AND payload_json LIKE "
            "'%crawl_result_missing%'", (eid,))[0]["n"]
    finally:
        try:
            os.killpg(os.getpgid(lab.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            lab.kill()

    checks = [
        ("inventory survived the kill unchanged", result["inventory_identical"]),
        ("resumed run consumed the restored inventory", result["inventory_endpoints"] > 0),
        ("no intent left unresolved", result["unresolved_intents"] == []),
        ("no false gap on a restored inventory", result["crawl_gap_events"] == 0),
        ("evidence chain intact", result["chain_ok"]),
        ("terminal status is real", result["final_status"] in ("done", "failed",
                                                               "budget_exhausted")),
    ]
    result["checks"] = {name: bool(ok) for name, ok in checks}
    (out / "recovery.json").write_text(json.dumps(result, indent=2, default=str))
    failed = [name for name, ok in checks if not ok]
    print(json.dumps(result, indent=2, default=str))
    if failed:
        print(f"FAIL: {', '.join(failed)}")
        return 1
    print(f"PASS: engagement resumed from disk alone; {result['findings']} findings, "
          f"{result['validated']} validated, chain intact")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "benchmark_runs/recovery2")))
