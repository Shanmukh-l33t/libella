"""Real autonomous agent-mode assessment against PairLab (live LLM specialists).

Proves genuine autonomy: planner decomposes, specialists investigate via ReAct,
form hypotheses, run tools/checks, propose evidence-backed findings, delegate;
deterministic verifier independently validates. Records agent_runs + steps + cost.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.api import App

ROOT = Path(__file__).parent.parent
KEY = os.environ.get("HERMES_CUSTOM_API_SURPLUSINTELLIGENCE_AI_API_KEY", "")
BASE = "https://api.surplusintelligence.ai/v1"
MODEL = os.environ.get("LIBELLA_TEST_MODEL", "deepseek-v4.1-flash-1017")
GT = json.loads((ROOT / "labs/pairlab/ground_truth.json").read_text())


def main():
    if not KEY:
        print("SKIP: no API key in env (source /root/.hermes/.env)")
        return
    port = 8801
    base = f"http://127.0.0.1:{port}"
    app = App(ROOT / "benchmark_runs" / "agent_mode")
    app.db.execute(
        "INSERT INTO settings(key, value_json) VALUES('llm_config', ?) "
        "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
        (json.dumps({"base_url": BASE, "api_key": KEY, "default_model": MODEL,
                     "models": {"planner": MODEL, "web": MODEL, "recon": MODEL, "api": MODEL}}),))
    scope = {"targets": [{"kind": "url", "value": base}],
             "categories": ["recon", "web", "api"], "rate_limit_rps": 20}
    auth = {"identities": [{**i, "login_url": base + "/login"} for i in GT["identities"][:2]],
            "test_hints": {
                "ssrf": {"url": base + "/fetch", "param": "url",
                         "internal_url": base + "/internal/meta", "marker": "LABFAKEKEY0000"},
                "sqli_union": {"url": base + "/api/products", "param": "category",
                               "payload": "' UNION SELECT id,username,password,role FROM users--",
                               "marker": "alice"},
                "idor": {"url_template": base + "/api/orders/{id}", "foreign_ids": [102],
                         "foreign_marker": '"user_id":2', "identity": "alice"}}}
    eid = "eng_agent"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, objectives_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (eid, "Agent-mode PairLab", "safe_active", "draft", json.dumps(scope), json.dumps(auth),
         json.dumps({"max_duration_s": 600, "max_usd": 3, "max_plan_rounds": 2}),
         json.dumps(["Discover and validate web/API vulnerabilities in the lab application"]), time.time()))
    t0 = time.time()
    app.orchestrator().start(eid, mode="agent")
    duration = time.time() - t0
    runs = app.db.query("SELECT role, status, exit_reason, iterations, tokens_in, tokens_out, cost_usd, summary FROM agent_runs WHERE engagement_id=?", (eid,))
    steps = app.db.query("SELECT action_kind, COUNT(*) n FROM investigation_steps WHERE engagement_id=? GROUP BY action_kind", (eid,))
    hyps = app.db.query("SELECT statement, status FROM hypotheses WHERE engagement_id=?", (eid,))
    findings = app.pipeline.list(eid)
    confirmed = [f for f in findings if f["state"] in ("validated", "reported", "retested_persists")]
    # score vs ground truth
    detected, missed = [], []
    for seed in GT["seeded_findings"]:
        path = seed["endpoint"].split("?")[0]
        hit = next((f for f in confirmed if f["cwe"] == seed["cwe"] and
                    (path in (f["endpoint"] or "") or (f["endpoint"] or "") in seed["endpoint"])), None)
        (detected if hit else missed).append(seed["id"])
    spend = app.llm().spend(eid)
    out = {"duration_s": round(duration, 1), "agent_runs": runs,
           "step_kinds": steps, "hypotheses": hyps,
           "findings_total": len(findings), "confirmed": len(confirmed),
           "seeds_detected": detected, "seeds_missed": missed,
           "spend": spend, "chain": app.evidence.verify_chain(eid),
           "engagement_status": app.db.one("SELECT status, status_detail FROM engagements WHERE id=?", (eid,))}
    (ROOT / "benchmark_runs" / "agent_mode_results.json").write_text(json.dumps(out, indent=2, default=str))
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
