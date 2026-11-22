"""Acceptance: does the offence chain run end to end through a real engagement?

The audit modules have their own lab tests. What none of them prove is the chain
that matters to an operator: an engagement declares what it wants tested, the
deterministic planner creates the intent, the executor runs the audit against a
real lab, the finding reaches the pipeline with evidence, and the coverage ledger
accounts for it.

Credentials are read from the lab modules at runtime, never copied into this file.

Usage: PYTHONPATH=src python benchmarks/acceptance_offence.py <out-dir>
Starts the labs in-process on ephemeral ports, so nothing is mocked and no fixed
port is taken.
"""
import json
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from werkzeug.serving import make_server  # noqa: E402

from libella import coverage  # noqa: E402
from libella.api import App  # noqa: E402


def _serve(module: str):
    mod = __import__(module, fromlist=["app"])
    srv = make_server("127.0.0.1", 0, mod.app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return mod, srv


def _engagement(app, eid, targets, categories, identities, hints):
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, eid, "safe_active", "draft",
         json.dumps({"targets": targets, "categories": categories, "rate_limit_rps": 16}),
         json.dumps({"identities": identities, "test_hints": hints,
                     **({"openapi": hints.pop("openapi")} if "openapi" in hints else {})}),
         json.dumps({"max_duration_s": 420, "max_usd": 2}), time.time()))


def _intents(app, eid):
    return {r["role"]: r["status"] for r in
            app.db.query("SELECT role, status FROM intents WHERE engagement_id=?", (eid,))}


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    jwt_mod, jwt_srv = _serve("labs.jwtlab.app")
    role_mod, role_srv = _serve("labs.rolelab.app")
    jwt = f"http://127.0.0.1:{jwt_srv.server_port}"
    role = f"http://127.0.0.1:{role_srv.server_port}"
    loop = {"kind": "ip", "value": "127.0.0.1"}
    app = App(out / "data")
    failures = []

    # --- 1. token forgery: an identity that owns a weak-secret token --------
    jwt_user = next(iter(jwt_mod.USERS))
    jwt_pw = jwt_mod.USERS[jwt_user][1]
    _engagement(app, "eng_jwt", [{"kind": "url", "value": jwt}, loop], ["recon", "web", "api"],
                [{"username": jwt_user, "password": jwt_pw, "login_url": jwt + "/login"}],
                {"jwt": {"url": jwt + "/api/profile", "header_name": "Authorization"}})
    # --- 2. role matrix: two identities of the same rank --------------------
    # A JSON API publishes no links for a crawler, so the operator supplies the
    # endpoint inventory as an OpenAPI description: that is the real workflow.
    spec = out / "rolelab-openapi.json"
    spec.write_text(json.dumps({
        "openapi": "3.0.0", "info": {"title": "rolelab", "version": "1"},
        "paths": {
            "/api/me": {"get": {"responses": {"200": {"description": "me"}}}},
            "/api/reports": {"get": {"responses": {"200": {"description": "reports"}}}},
            "/reports-all": {"get": {"responses": {"200": {"description": "all"}}}},
            "/api/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path",
                                                       "required": True,
                                                       "schema": {"type": "integer"}}],
                                        "responses": {"200": {"description": "user"}}}},
            "/api/orders/{id}": {"get": {"parameters": [{"name": "id", "in": "path",
                                                        "required": True,
                                                        "schema": {"type": "integer"}}],
                                         "responses": {"200": {"description": "order"}}}},
        }}))
    names = [n for n, row in role_mod.USERS.items() if row[2] == "user"][:2]
    _engagement(app, "eng_role", [{"kind": "url", "value": role}, loop], ["recon", "web", "api"],
                [{"username": n, "password": role_mod.USERS[n][1],
                  "login_url": role + "/login"} for n in names],
                {"openapi": str(spec)})

    results = {}
    for eid in ("eng_jwt", "eng_role"):
        started = time.time()
        app.orchestrator().start(eid, mode="deterministic")
        findings = app.pipeline.list(eid)
        wstg = coverage.workspace(app.db, eid, "wstg", app.evidence)
        asvs = coverage.workspace(app.db, eid, "asvs", app.evidence)
        flat = {t["id"]: t for c in wstg["categories"] for t in c["tests"]}
        results[eid] = {
            "elapsed_s": round(time.time() - started, 1),
            "intents": _intents(app, eid),
            "findings": [{"id": f["id"], "cwe": f["cwe"], "state": f["state"],
                          "title": (f["title"] or "")[:70]} for f in findings],
            "wstg": {"total": wstg["summary"]["total"],
                     "completed": wstg["summary"]["completed"],
                     "with_findings": wstg["summary"]["with_findings"]},
            "asvs": {"total": asvs["summary"]["total"],
                     "with_findings": asvs["summary"]["with_findings"]},
            "ledger": {k: flat[k]["automatic"]["status"] for k in
                       ("WSTG-SESS-01", "WSTG-ATHN-04", "WSTG-ATHZ-02", "WSTG-ATHZ-04")
                       if k in flat},
            "evidence_chain": app.evidence.verify_chain(eid).get("ok", True),
        }
        for f in findings:
            ev = json.loads(app.db.one("SELECT evidence_ids_json e FROM findings WHERE id=?",
                                       (f["id"],))["e"])
            if not ev:
                failures.append(f"{eid}: {f['id']} has no bound evidence")
        if not results[eid]["evidence_chain"]:
            failures.append(f"{eid}: evidence chain verification failed")

    jwt_res, role_res = results["eng_jwt"], results["eng_role"]
    if jwt_res["intents"].get("jwt_audit") != "done":
        failures.append(f"jwt_audit did not complete: {jwt_res['intents'].get('jwt_audit')}")
    if not any(f["cwe"] == "CWE-347" for f in jwt_res["findings"]):
        failures.append("the weak-secret lab produced no CWE-347 token-forgery finding")
    if role_res["intents"].get("privesc_audit") != "done":
        failures.append(f"privesc_audit did not complete: "
                        f"{role_res['intents'].get('privesc_audit')}")
    if not any(f["cwe"] in ("CWE-639", "CWE-285", "CWE-306") for f in role_res["findings"]):
        failures.append("the role lab produced no authorization finding")
    if not any(r["wstg"]["with_findings"] for r in results.values()):
        failures.append("the coverage ledger counted no finding against a WSTG test")

    payload = {"engagements": results, "failures": failures}
    (out / "acceptance_offence.json").write_text(json.dumps(payload, indent=1, default=str))
    print(json.dumps(payload, indent=1, default=str))
    for srv in (jwt_srv, role_srv):
        srv.shutdown()
    if failures:
        print("FAIL")
        return 1
    total = sum(len(r["findings"]) for r in results.values())
    print(f"PASS: {total} findings across 2 real engagements, ledgers and evidence chains intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp())))
