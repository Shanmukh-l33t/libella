"""Retest cycle proof: validated finding -> remediation -> retest verdicts.

Phase 1: assess lab on :8803 (vuln), retest a validated finding -> persists.
Phase 2: after operator swaps :8803 to hardened mode, retest -> fixed.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.api import App
from libella.scope import Scope

ROOT = Path(__file__).parent.parent
PORT = os.environ.get("LAB_PORT", "8803")
BASE = f"http://127.0.0.1:{PORT}"
DATA = Path(os.environ.get("RETEST_DATA") or ROOT / "benchmark_runs" / "retest")


def get_app():
    return App(DATA)


def phase1():
    app = get_app()
    scope = {"targets": [{"kind": "url", "value": BASE}],
             "categories": ["recon", "web", "api"], "rate_limit_rps": 20}
    eid = "eng_retest"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, "Retest cycle", "safe_active", "draft", json.dumps(scope), "{}",
         json.dumps({"max_duration_s": 600}), time.time()))
    app.orchestrator().start(eid, mode="deterministic")
    findings = app.pipeline.list(eid)
    target = next((f for f in findings if f["state"] == "validated" and "/debug" in (f["endpoint"] or "")), None)
    if target is None:
        target = next((f for f in findings if f["state"] == "validated"), None)
    if target is None:
        print("FAIL: no validated finding to retest")
        return
    v = app.verifier.retest(eid, Scope(scope), target["id"])
    out = {"phase": 1, "finding_id": target["id"], "title": target["title"],
           "retest_verdict": v["verdict"], "detail": v["detail"],
           "state_after": app.db.one("SELECT state FROM findings WHERE id=?", (target["id"],))["state"]}
    (DATA / "phase1.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


def phase2():
    app = get_app()
    p1 = json.loads((DATA / "phase1.json").read_text())
    fid = p1["finding_id"]
    eng = app.db.one("SELECT scope_json FROM engagements WHERE id='eng_retest'")
    v = app.verifier.retest("eng_retest", Scope(json.loads(eng["scope_json"])), fid)
    out = {"phase": 2, "finding_id": fid, "retest_verdict": v["verdict"], "detail": v["detail"],
           "state_after": app.db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"],
           "retests": app.db.query("SELECT verdict, detail FROM retests WHERE finding_id=? ORDER BY created_at", (fid,))}
    (DATA / "phase2.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    {"1": phase1, "2": phase2}[sys.argv[1]]()
