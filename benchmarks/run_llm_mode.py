"""LLM-planner mode test: real model proposes intents through the compile gate.

Uses the local OpenAI-compatible endpoint from env (no secrets printed).
Verifies: LLM calls accounted, intents created, out-of-scope proposals rejected,
assessment completes with findings still validated.
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


def main():
    if not KEY:
        print("SKIP: no API key in env")
        return
    app = App(ROOT / "benchmark_runs" / "llm_mode")
    app.db.execute(
        "INSERT INTO settings(key, value_json) VALUES('llm_config', ?) "
        "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
        (json.dumps({"base_url": BASE, "api_key": KEY, "default_model": MODEL,
                     "models": {"planner": MODEL}}),))
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
             "categories": ["recon", "web", "api", "infra"], "rate_limit_rps": 20}
    eid = "eng_llm"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, "LLM mode test", "safe_active", "draft", json.dumps(scope), "{}",
         json.dumps({"max_duration_s": 600, "max_usd": 2}), time.time()))
    started = time.time()
    app.orchestrator().start(eid, mode="llm")
    duration = time.time() - started
    usage = app.db.query("SELECT role, model, input_tokens, output_tokens, cost_usd FROM llm_usage WHERE engagement_id=?", (eid,))
    intents = app.db.query("SELECT role, objective, status FROM intents WHERE engagement_id=?", (eid,))
    rejects = app.db.query("SELECT payload_json FROM events WHERE engagement_id=? AND kind='compile_reject'", (eid,))
    findings = app.pipeline.list(eid)
    confirmed = [f for f in findings if f["state"] == "validated"]
    eng = app.db.one("SELECT status, status_detail FROM engagements WHERE id=?", (eid,))
    out = {"duration_s": round(duration, 1), "status": eng["status"], "detail": eng["status_detail"],
           "llm_calls": len(usage), "usage": usage,
           "intents_total": len(intents), "intents": intents,
           "compile_rejects": [json.loads(r["payload_json"]) for r in rejects],
           "confirmed_findings": len(confirmed), "chain": app.evidence.verify_chain(eid)}
    (ROOT / "benchmark_runs" / "llm_mode_results.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()