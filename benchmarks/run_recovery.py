"""Reliability proof: cancel mid-assessment, resume, complete with valid state."""
import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.api import App

ROOT = Path(__file__).parent.parent


def main():
    app = App(ROOT / "benchmark_runs" / "recovery")
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
             "categories": ["recon", "web", "api", "infra"], "rate_limit_rps": 20}
    eid = "eng_recovery"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, "Recovery test", "safe_active", "draft", json.dumps(scope), "{}",
         json.dumps({"max_duration_s": 900}), time.time()))
    t = threading.Thread(target=app._run_guarded, args=(app.orchestrator(), eid, "deterministic"),
                         daemon=True)
    t.start()
    time.sleep(3)
    app.orchestrator().cancel(eid)
    time.sleep(2)
    mid = app.db.one("SELECT status FROM engagements WHERE id=?", (eid,))
    stopped = app.db.query("SELECT COUNT(*) n FROM intents WHERE engagement_id=? AND status='stopped'", (eid,))[0]["n"]
    print(f"after cancel: status={mid['status']} stopped_intents={stopped}")
    assert mid["status"] == "cancelled"
    # resume
    app.db.execute("UPDATE intents SET status='open' WHERE engagement_id=? AND status='stopped'", (eid,))
    t2 = threading.Thread(target=app._run_guarded, args=(app.orchestrator(), eid, "deterministic"),
                          daemon=True)
    app.db.execute("UPDATE engagements SET status='running' WHERE id=?", (eid,))
    t2.start()
    t2.join(timeout=600)
    end = app.db.one("SELECT status, status_detail FROM engagements WHERE id=?", (eid,))
    findings = app.pipeline.list(eid)
    validated = sum(1 for f in findings if f["state"] == "validated")
    chain = app.evidence.verify_chain(eid)
    out = {"cancelled_status": mid["status"], "stopped_intents": stopped,
           "resumed_final_status": end["status"], "detail": end["status_detail"],
           "findings": len(findings), "validated": validated, "chain": chain}
    (ROOT / "benchmark_runs" / "recovery_results.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
