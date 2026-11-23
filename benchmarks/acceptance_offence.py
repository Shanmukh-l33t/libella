"""Acceptance: does the offence chain run end to end through a real engagement?

The audit modules have their own lab tests. What none of them prove is the chain
that matters to an operator: an engagement declares what it wants tested, the
deterministic planner creates the intent, the executor runs the audit against a
real lab, the finding reaches the pipeline with evidence, and the coverage ledger
accounts for it.

Six engagements cover the six audits: JWT forgery, the role matrix, OAuth
redirect_uri bypass, session fixation/logout, LFI and host-header injection.

Credentials are read from the lab modules at runtime, never copied into this file.

Usage: PYTHONPATH=src python benchmarks/acceptance_offence.py <out-dir>
Starts the labs in-process on ephemeral ports, so nothing is mocked and no fixed
port is taken. The engagements run concurrently, one thread each, as the product
runs them; each carries its own 900s budget.
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


def _serve(module: str, attr: str = "app", host: str = "127.0.0.1"):
    mod = __import__(module, fromlist=[attr])
    # single-threaded, like the labs' own tests: a scan that opens 25 sockets makes
    # werkzeug refuse the surplus, and nuclei then stops the host at its error cap
    # instead of walking 16k requests for a quarter of an hour.
    srv = make_server(host, 0, getattr(mod, attr))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return mod, srv


def _engagement(app, eid, targets, categories, identities, hints, **auth):
    """`auth` keys (oauth, session) sit beside test_hints, where the audits read them."""
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, eid, "safe_active", "draft",
         json.dumps({"targets": targets, "categories": categories, "rate_limit_rps": 16}),
         json.dumps({"identities": identities, "test_hints": hints, **auth,
                     **({"openapi": hints.pop("openapi")} if "openapi" in hints else {})}),
         json.dumps({"max_duration_s": 900, "max_usd": 2}), time.time()))


def _intents(app, eid):
    return {r["role"]: r["status"] for r in
            app.db.query("SELECT role, status FROM intents WHERE engagement_id=?", (eid,))}


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    jwt_mod, jwt_srv = _serve("labs.jwtlab.app")
    role_mod, role_srv = _serve("labs.rolelab.app")
    # the OAuth lab binds 0.0.0.0 so its attacker page answers on the 127.0.0.2 alias
    oauth_mod, oauth_srv = _serve("labs.oauthlab.app", host="0.0.0.0")
    oauth = f"http://127.0.0.1:{oauth_srv.server_port}"
    oauth_mod.app.config["BASE"] = oauth
    attacker = f"http://127.0.0.2:{oauth_srv.server_port}"
    inj_mod, inj_srv = _serve("labs.injlab.app")
    proto_mod, proto_srv = _serve("labs.protolab.app", "application")
    jwt = f"http://127.0.0.1:{jwt_srv.server_port}"
    role = f"http://127.0.0.1:{role_srv.server_port}"
    inj = f"http://127.0.0.1:{inj_srv.server_port}"
    proto = f"http://127.0.0.1:{proto_srv.server_port}"
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
                  "login_url": role + "/api/login"} for n in names],
                {"openapi": str(spec)})
    # --- 3. oauth: a redirect_uri compare that is a prefix, not an equality --
    oauth_user, oauth_pw = next(iter(oauth_mod.USERS.items()))
    _engagement(app, "eng_oauth", [{"kind": "url", "value": oauth}, loop], ["recon", "web", "api"],
                [], {}, oauth={"authorize_url": oauth + "/authorize",
                               "token_url": oauth + "/token",
                               "client_id": oauth_mod.CLIENT_ID,
                               "redirect_uri": oauth + oauth_mod.REDIRECT_PATH,
                               "scope": "profile", "pkce": True,
                               # the attacker page exists but is not an authorized target:
                               # the Location header alone must prove delivery
                               "attacker_origin": attacker})
    # --- 4. session: the same lab also hosts the fixation/logout app --------
    _engagement(app, "eng_session", [{"kind": "url", "value": oauth}, loop],
                ["recon", "web", "api"], [], {},
                session={"login_url": oauth + "/session/login",
                         "username": oauth_user, "password": oauth_pw,
                         "protected_url": oauth + "/session/me",
                         "logout_url": oauth + "/session/logout",
                         "password_change_url": f"{oauth}/session/password"})
    # --- 5. injection: the cheap class, LFI on a declared parameter ---------
    _engagement(app, "eng_inj", [{"kind": "url", "value": inj}, loop], ["recon", "web", "api"],
                [], {"injection": {"targets": [{"url": inj + "/download", "param": "file",
                                                "kind": "lfi"}]}})
    # --- 6. web protocol: the proxy shim trusts X-Forwarded-Host ------------
    _engagement(app, "eng_proto", [{"kind": "url", "value": proto}, loop],
                ["recon", "web", "api"], [],
                {"web_protocol": {"url": proto + "/portal",
                                  "host_header": "libella-lab.invalid"}})

    eids = ("eng_jwt", "eng_role", "eng_oauth", "eng_session", "eng_inj", "eng_proto")
    results = {}
    for eid in eids:
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

    def has(eid, *cwes):
        return any(f["cwe"] in cwes for f in results[eid]["findings"])

    jwt_res, role_res = results["eng_jwt"], results["eng_role"]
    if jwt_res["intents"].get("jwt_audit") != "done":
        failures.append(f"jwt_audit did not complete: {jwt_res['intents'].get('jwt_audit')}")
    if not has("eng_jwt", "CWE-347"):
        failures.append("the weak-secret lab produced no CWE-347 token-forgery finding")
    if role_res["intents"].get("privesc_audit") != "done":
        failures.append(f"privesc_audit did not complete: "
                        f"{role_res['intents'].get('privesc_audit')}")
    if not has("eng_role", "CWE-639", "CWE-285", "CWE-306"):
        failures.append("the role lab produced no authorization finding")
    oauth_res = results["eng_oauth"]
    if oauth_res["intents"].get("oauth_audit") != "done":
        failures.append(f"oauth_audit did not complete: {oauth_res['intents'].get('oauth_audit')}")
    if not has("eng_oauth", "CWE-601"):
        failures.append("the OAuth lab produced no CWE-601 redirect_uri bypass finding")
    session_res = results["eng_session"]
    if session_res["intents"].get("session_audit") != "done":
        failures.append(f"session_audit did not complete: "
                        f"{session_res['intents'].get('session_audit')}")
    if not has("eng_session", "CWE-384", "CWE-613"):
        failures.append("the session lab produced no fixation/logout finding")
    inj_res = results["eng_inj"]
    if inj_res["intents"].get("injection_audit") != "done":
        failures.append(f"injection_audit did not complete: "
                        f"{inj_res['intents'].get('injection_audit')}")
    if not has("eng_inj", "CWE-22"):
        failures.append("the injection lab produced no CWE-22 file-read finding")
    proto_res = results["eng_proto"]
    if proto_res["intents"].get("web_protocol_audit") != "done":
        failures.append(f"web_protocol_audit did not complete: "
                        f"{proto_res['intents'].get('web_protocol_audit')}")
    if not has("eng_proto", "CWE-601"):
        failures.append("the protocol lab produced no CWE-601 host-header finding")
    if not any(r["wstg"]["with_findings"] for r in results.values()):
        failures.append("the coverage ledger counted no finding against a WSTG test")

    payload = {"engagements": results, "failures": failures}
    (out / "acceptance_offence.json").write_text(json.dumps(payload, indent=1, default=str))
    for eid, r in results.items():
        cwes = ",".join(sorted({f["cwe"] for f in r["findings"] if f["cwe"]})) or "-"
        done = sum(1 for s in r["intents"].values() if s == "done")
        print(f"{eid:12s} {r['elapsed_s']:6.1f}s  intents {done}/{len(r['intents'])}  "
              f"findings {len(r['findings']):2d}  {cwes}")
    print(f"json: {out / 'acceptance_offence.json'}")
    for srv in (jwt_srv, role_srv, oauth_srv, inj_srv, proto_srv):
        srv.shutdown()
    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1
    total = sum(len(r["findings"]) for r in results.values())
    print(f"PASS: {total} findings across {len(results)} real engagements, "
          "ledgers and evidence chains intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp())))
