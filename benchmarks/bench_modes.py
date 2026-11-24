"""Four-way independence benchmark against a controlled ground-truth target.

    A  native deterministic  - Libella's own checks, nuclei unavailable to the runner
    B  autonomous agents     - ReAct specialists, nuclei unavailable (needs an LLM provider)
    C  nuclei-only baseline  - a bounded, documented nuclei workload; no Libella checks
    D  full Libella          - native + agents + nuclei, with scoring

Every run gets its own data directory (deleted first, so a rerun measures a fresh
assessment), its own engagement id, and the same target, scope, rate and budgets.
Nothing is inferred: a value that was not measured is null.

Nuclei is made unavailable to A and B the way a deployment without it behaves: the
runner's own availability check resolves nothing, so a call is audited as a missing tool
rather than silently skipped. That is not proof of a host without nuclei; run
`benchmarks/acceptance_isolated_worker.py` for the stronger claim.

    python benchmarks/bench_modes.py --modes A,C --twins vuln,hardened
    python benchmarks/bench_modes.py --modes B --llm --twins vuln
    python benchmarks/bench_modes.py --modes C --nuclei-profile comprehensive
"""
import argparse
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from libella.api import App  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools import runner as runner_mod  # noqa: E402

ROOT = Path(__file__).parent.parent
GT = json.loads((ROOT / "labs/pairlab/ground_truth.json").read_text())
CONFIRMED = ("validated", "reported", "retested_persists")

# A documented, bounded nuclei workload. "focused" targets the classes PairLab actually
# contains; "comprehensive" is the full medium+ template tree, which cannot finish inside
# the 600s tool cap and is recorded as partial. Comparing "focused" to native keeps the
# workloads comparable; the comprehensive run measures the timeout, not a fair race.
NUCLEI_PROFILES = {
    "focused": {"tags": "exposure,misconfig,headers,cors,redirect,xss,sqli,traversal,ssrf,file",
                "severity": "medium,high,critical"},
    "comprehensive": {"severity": "medium,high,critical"},
}


def declared_hints(base: str) -> dict:
    """What an operator declares in the product UI: the endpoints they want probed."""
    return {
        "ssrf": {"url": base + "/fetch", "param": "url",
                 "internal_url": base + "/internal/meta", "marker": "LABFAKEKEY0000"},
        "sqli_union": {"url": base + "/api/products", "param": "category",
                       "payload": "' UNION SELECT id,username,password,role FROM users--",
                       "marker": "alice"},
        "idor": {"url_template": base + "/api/orders/{id}", "foreign_ids": [102],
                 "foreign_marker": '"user_id":2', "identity": "alice"},
    }


def score(findings: list) -> dict:
    """Map confirmed findings onto seeds. A confirmed finding on no seed is a false positive."""
    confirmed = [f for f in findings if f["state"] in CONFIRMED]
    detected, missed, hit_ids = [], [], set()
    for seed in GT["seeded_findings"]:
        path = seed["endpoint"].split("?")[0]
        for f in confirmed:
            if f["cwe"] == seed["cwe"] and (path in (f["endpoint"] or "") or
                                            (f["endpoint"] or "") in seed["endpoint"]):
                detected.append(seed["id"])
                hit_ids.add(f["id"])
                break
        else:
            missed.append({"seed": seed["id"], "cwe": seed["cwe"], "title": seed["title"]})
    unmatched = [{"id": f["id"], "title": f["title"], "cwe": f["cwe"], "endpoint": f["endpoint"],
                  "state": f["state"]} for f in confirmed if f["id"] not in hit_ids]
    denom = len(detected) + len(unmatched)
    return {"seeds_total": len(GT["seeded_findings"]), "detected": len(detected),
            "detected_seeds": detected, "missed": missed, "confirmed_total": len(confirmed),
            "unmatched_confirmed": unmatched, "findings_total": len(findings),
            "precision": None if not denom else round(len(detected) / denom, 3)}


def attribution(app, findings: list) -> list[dict]:
    """Which component produced each finding, from the recorded dedup key."""
    out = []
    for f in findings:
        key = f.get("dedup_key") or ""
        source = ("nuclei" if key.startswith("nuclei:")
                  else "agent" if key.split(":")[0] in ("agent", "specialist") else "native")
        out.append({"id": f["id"], "title": f["title"], "cwe": f.get("cwe"),
                    "state": f["state"], "endpoint": f.get("endpoint"), "source": source})
    return out


def counts(app, eid: str) -> dict:
    def one(sql):
        return app.db.one(sql, (eid,))["n"]
    return {
        "exchanges": one("SELECT COUNT(*) n FROM exchanges WHERE engagement_id=?"),
        "tool_calls": one("SELECT COUNT(*) n FROM tool_calls WHERE engagement_id=?"),
        "nuclei_calls": one("SELECT COUNT(*) n FROM tool_calls WHERE engagement_id=? "
                            "AND tool='nuclei'"),
        "tool_refused": one("SELECT COUNT(*) n FROM tool_calls WHERE engagement_id=? AND "
                            "scope_decision LIKE 'refused%'"),
        "egress_denied": one("SELECT COUNT(*) n FROM events WHERE engagement_id=? AND "
                             "kind='egress_denied'"),
        "assets": one("SELECT COUNT(*) n FROM assets WHERE engagement_id=?"),
        "agent_runs": one("SELECT COUNT(*) n FROM agent_runs WHERE engagement_id=?"),
        "intents": one("SELECT COUNT(*) n FROM intents WHERE engagement_id=?"),
        "intents_done": one("SELECT COUNT(*) n FROM intents WHERE engagement_id=? AND status='done'"),
        "degradations": [json.loads(r["payload_json"]) for r in app.db.query(
            "SELECT payload_json FROM events WHERE engagement_id=? AND kind='degradation'", (eid,))],
    }


def nuclei_stats(app, eid: str) -> dict | None:
    """The scanner's own counters, from its persisted progress samples."""
    rows = [json.loads(r["payload_json"]) for r in app.db.query(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind='scan_progress' ORDER BY seq",
        (eid,))]
    if not rows:
        return None
    last = rows[-1]
    return {"samples": len(rows), "templates_selected": last.get("templates"),
            "requests": last.get("requests"), "total_requests": last.get("total_requests"),
            "percent_last": last.get("percent"), "errors": last.get("errors"),
            "matched": last.get("matched"), "elapsed": last.get("elapsed")}


def spend(app, eid: str) -> dict:
    if app.llm() is None:
        return {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "provider": None}
    return {**app.llm().spend(eid), "provider": getattr(app.llm(), "default_model", None)}


def no_nuclei() -> object:
    """Model a deployment without nuclei. Returns the previous resolver for restore."""
    prev = runner_mod.resolve_binary
    if prev("nuclei") is None:
        raise SystemExit("nuclei is already unresolvable here: mode C cannot run")
    runner_mod.resolve_binary = lambda n: None if n == "nuclei" else prev(n)
    assert runner_mod.resolve_binary("nuclei") is None
    return prev


def run_mode(mode, twin, hints, data_root, *, llm=None, nuclei_profile="focused",
             budgets=None) -> dict:
    base = "http://127.0.0.1:8801" if twin == "vuln" else "http://127.0.0.1:8802"
    data_dir = data_root / mode / twin / ("hints" if hints else "nohints")
    shutil.rmtree(data_dir, ignore_errors=True)  # a rerun measures a fresh assessment
    app = App(data_dir)
    eid = f"b{mode}_{twin}"
    if llm:
        app.db.execute("INSERT INTO settings(key, value_json) VALUES('llm_config', ?) "
                       "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                       (json.dumps(llm),))
    auth = {"identities": [{**i, "login_url": base + "/login", "username_field": "username",
                            "password_field": "password"} for i in GT["identities"][:2]]}
    if hints:
        auth["test_hints"] = declared_hints(base)
    scope_spec = {"targets": [{"kind": "url", "value": base}],
                  "categories": ["recon", "web", "api", "infra"],
                  "rate_limit_rps": 20, "max_concurrency": 4}
    b = budgets or ({"max_duration_s": 1800, "max_usd": 4, "max_plan_rounds": 2}
                    if mode == "B" else {"max_duration_s": 1800, "max_usd": 4})
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, f"{mode} {twin}", "safe_active", "draft", json.dumps(scope_spec),
         json.dumps(auth), json.dumps(b), time.time()))
    extra = {}
    restore = no_nuclei() if mode in ("A", "B") else None
    try:
        started = time.time()
        if mode == "C":
            prof = NUCLEI_PROFILES[nuclei_profile]
            r = app.runner.run(app.registry.get("nuclei"),
                               {"target": base, "severity": prof["severity"],
                                "tags": prof["tags"], "rate_limit": 20},
                               Scope(scope_spec), eid, None, base, "web")
            from libella.orchestrator import PARSERS
            for rec in PARSERS["nuclei"](r.get("stdout") or ""):
                app.pipeline.submit_candidate(eid, {
                    "title": f"[nuclei] {rec.get('name') or rec.get('template_id')}",
                    "cwe": (rec.get("classification") or {}).get("cwe-id", [None])[0]
                    if isinstance(rec.get("classification"), dict) else None,
                    "owasp": None, "severity": rec.get("severity", "info"), "confidence": "medium",
                    "endpoint": rec.get("matched_at") or base,
                    "description": f"nuclei template {rec.get('template_id')} matched.",
                    "impact": "Scanner-reported; requires independent validation.",
                    "remediation": "See template references.",
                    "evidence_ids": [r["artifact_id"]] if r.get("artifact_id") else [],
                    "quote": rec.get("template_id") or "", "quote_in": "body",
                    "proof_request": {"method": "GET", "url": rec.get("matched_at") or base},
                    "dedup_key": f"nuclei:{rec.get('template_id')}:{rec.get('matched_at')}",
                }, None)
            extra = {"nuclei_ok": r.get("ok"), "nuclei_error": r.get("error"),
                     "nuclei_profile": prof,
                     "nuclei_runtime_s": round((r.get("duration_ms") or 0) / 1000, 1)}
            app.db.execute("UPDATE engagements SET status='done', finished_at=? WHERE id=?",
                           (time.time(), eid))
        else:
            app.orchestrator().start(eid, mode="agent" if mode == "B" else "deterministic")
        duration = time.time() - started
    finally:
        if restore is not None:
            runner_mod.resolve_binary = restore
    findings = app.pipeline.list(eid)
    row = app.db.one("SELECT status FROM engagements WHERE id=?", (eid,)) or {}
    out = {"mode": mode, "twin": twin, "hints": hints, "duration_s": round(duration, 1),
           "status": row.get("status"),
           "target": base, "scope": scope_spec, "budgets": b,
           "nuclei_available": mode in ("C", "D"),
           "score": score(findings), "attribution": attribution(app, findings),
           "counts": counts(app, eid), "nuclei_stats": nuclei_stats(app, eid),
           "spend": spend(app, eid), "chain": app.evidence.verify_chain(eid), **extra}
    app.db.close()
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--modes", default="A,C")
    p.add_argument("--twins", default="vuln,hardened")
    p.add_argument("--hints", default="none", choices=["none", "declared"])
    p.add_argument("--nuclei-profile", default="focused", choices=sorted(NUCLEI_PROFILES))
    p.add_argument("--out-dir", default=str(ROOT / "benchmark_runs"))
    p.add_argument("--llm", action="store_true", help="configure the LLM provider from env")
    a = p.parse_args()
    llm = None
    if a.llm:
        import os

        def _key() -> str:
            """The provider key, from the environment or the owner's env file.

            The background runner sanitises HERMES_* variables out of the child, so a key
            exported in the parent shell does not arrive here; reading the file the user
            actually maintains is the reliable path.
            """
            from_env = os.environ.get("HERMES_CUSTOM_API_SURPLUSINTELLIGENCE_AI_API_KEY", "")
            if from_env:
                return from_env
            env_file = Path.home() / ".hermes/.env"
            if env_file.is_file():
                for line in env_file.read_text().splitlines():
                    name, sep, value = line.partition("=")
                    if sep and name.strip().lstrip("export ").strip() == \
                            "HERMES_CUSTOM_API_SURPLUSINTELLIGENCE_AI_API_KEY":
                        return value.strip().strip('"').strip("'")
            return ""

        key = _key()
        if not key:
            raise SystemExit("--llm needs HERMES_CUSTOM_API_SURPLUSINTELLIGENCE_AI_API_KEY "
                             "(in the environment or ~/.hermes/.env)")
        model = os.environ.get("LIBELLA_TEST_MODEL", "deepseek-v4.1-flash-1017")
        llm = {"base_url": "https://api.surplusintelligence.ai/v1", "api_key": key,
               "default_model": model,
               "models": {k: model for k in ("planner", "web", "api", "recon", "authz")}}
    out_dir = Path(a.out_dir)
    data_root = out_dir / "modes_data"
    results = []
    for mode in a.modes.split(","):
        for twin in a.twins.split(","):
            print(f"--- mode {mode} / {twin} / hints={a.hints} / nuclei={a.nuclei_profile}",
                  flush=True)
            res = run_mode(mode, twin, a.hints == "declared", data_root, llm=llm,
                           nuclei_profile=a.nuclei_profile)
            results.append(res)
            s, ns = res["score"], res.get("nuclei_stats") or {}
            print(f"    {res['duration_s']}s status={res['status']} "
                  f"detected {s['detected']}/{s['seeds_total']} confirmed={s['confirmed_total']} "
                  f"unmatched={len(s['unmatched_confirmed'])} precision={s['precision']} "
                  f"exchanges={res['counts']['exchanges']} "
                  f"nuclei_reqs={ns.get('requests')}/{ns.get('total_requests')} "
                  f"cost=${res['spend']['cost_usd']}", flush=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"modes_{a.modes.replace(',', '')}_{a.hints}.json"
    target.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nwrote {target}")


if __name__ == "__main__":
    main()
