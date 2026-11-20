"""Juice Shop assessment: real-world lab capability measurement (no ground truth scoring).

Juice Shop is a complex intentionally-vulnerable app. This measures what the
platform detects on a real application, honestly (no seeded hints).
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.api import App

ROOT = Path(__file__).parent.parent


def main():
    base = "http://127.0.0.1:3001"
    data_dir = ROOT / "benchmark_runs" / "juice"
    app = App(data_dir)
    scope = {"targets": [{"kind": "url", "value": base}],
             "categories": ["recon", "web", "api", "infra"],
             "rate_limit_rps": 15, "max_concurrency": 4}
    eid = "eng_juice"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, "OWASP Juice Shop", "safe_active", "draft", json.dumps(scope), "{}",
         json.dumps({"max_duration_s": 1200, "max_usd": 5}), time.time()))
    started = time.time()
    app.orchestrator().start(eid, mode="deterministic")
    duration = time.time() - started
    findings = app.pipeline.list(eid)
    confirmed = [f for f in findings if f["state"] in ("validated", "reported", "retested_persists")]
    assets = app.db.query("SELECT COUNT(*) n FROM assets WHERE engagement_id=?", (eid,))[0]["n"]
    degradations = app.db.query("SELECT payload_json FROM events WHERE engagement_id=? AND kind='degradation'", (eid,))
    out = {
        "target": base, "duration_s": round(duration, 1), "assets": assets,
        "findings_total": len(findings), "confirmed": len(confirmed),
        "confirmed_findings": [{"title": f["title"], "severity": f["severity"],
                                "cwe": f["cwe"], "endpoint": f["endpoint"], "state": f["state"]}
                               for f in confirmed],
        "other_findings": [{"title": f["title"], "state": f["state"]} for f in findings
                           if f not in confirmed],
        "degradations": [json.loads(d["payload_json"]) for d in degradations],
        "chain": app.evidence.verify_chain(eid),
    }
    (data_dir / "juice_results.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
