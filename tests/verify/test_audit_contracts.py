"""The audit modules must emit the typed proof contracts the fail-closed verifier demands.

Each contract kind has a negative test (prerequisite missing -> 'unsupported', finding stays
'observed') and a positive test (a genuine finding reaches 'validated'). The positive halves
for the role matrix, JWT and injection run the real audit against the real lab, then the
real verifier: a contract the audit cannot fill would show up here as a refusal.
"""
import importlib.util
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella import injection_audit as inj  # noqa: E402
from libella import proof  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402
from libella.jwt_audit import audit_jwt  # noqa: E402
from libella.privesc_audit import _contract, audit_role_matrix  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402
from libella.verifier import Verifier  # noqa: E402


def _lab(path: str, name: str, attr: str = "app"):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    srv = make_server("127.0.0.1", 0, getattr(mod, attr), threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return mod, f"http://127.0.0.1:{srv.server_port}", srv


def _env(tmp_path, base: str, categories=("web", "api")):
    db = DB(tmp_path / "db.sqlite")
    evidence = EvidenceStore(db, tmp_path / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": base}], "categories": list(categories),
                   "rate_limit_rps": 1000, "max_concurrency": 2})
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng", "c", "safe_active", "running", json.dumps(scope.spec), "{}", "{}", time.time()))
    probe, pipeline = HttpProbe(db, evidence), FindingPipeline(db, evidence)
    return SimpleNamespace(db=db, evidence=evidence, probe=probe, pipeline=pipeline,
                           scope=scope, verifier=Verifier(db, evidence, probe, pipeline), eid="eng")


def _rows(env):
    return env.db.query("SELECT * FROM findings WHERE engagement_id=?", (env.eid,))


def _spec(env, finding) -> dict:
    for e in json.loads(finding["evidence_ids_json"]):
        if env.db.one("SELECT kind FROM evidence WHERE id=?", (e,))["kind"] == "proof_spec":
            return json.loads(env.evidence.read(e))
    raise AssertionError("no proof spec")


def _verify_all(env) -> dict:
    return {f["cwe"] + ":" + f["title"][:40]: env.verifier.verify(env.eid, env.scope, f["id"])
            for f in _rows(env)}


# ------------------------------------------------------------ contract shapes (unit)

REQ = {"url": "http://x/o/2", "headers": {"Cookie": "s=1"}}


def test_privesc_contract_reads_the_owner_from_the_served_body():
    c = _contract("alice", 1, "http://x/o/2", '{"id": 9, "user_id": 2}')
    assert (c["owner_field"], c["owner_value"]) == ("user_id", 2)
    assert c["benign_request"] == {"method": "GET", "url": "http://x/o/2"}
    assert proof.missing(proof.AUTHORIZATION, c, REQ, "t") == []


def test_privesc_contract_finds_the_field_that_names_the_expected_owner():
    c = _contract("alice", 1, "http://x/u/2", '{"id": 2, "username": "bob"}', owner="bob")
    assert (c["owner_field"], c["owner_value"]) == ("username", "bob")
    assert c["identity"] == {"name": "alice", "value": "alice"}  # compared by name, not uid
    assert proof.missing(proof.AUTHORIZATION, c, REQ, "t") == []


def test_privesc_contract_without_a_stated_owner_is_incomplete_not_guessed():
    c = _contract("alice", 1, "http://x/o/2", '{"id": 9, "item": "Widget"}')
    assert {"owner_field", "privilege"} <= set(proof.missing(proof.AUTHORIZATION, c, REQ, "t"))


def test_privesc_privilege_contract_is_complete_and_needs_no_owner():
    c = _contract("alice", 1, "http://x/admin", privilege="admin")
    assert "owner_field" not in c
    assert proof.missing(proof.AUTHORIZATION, c, REQ, "t") == []
    assert proof.missing(proof.AUTHORIZATION, {**c, "identity": {"name": "alice"}}, REQ, "t") \
        == ["identity.value"]


def test_cwe_613_is_not_judged_as_a_cookie_flag_claim():
    # SESSION demands cookie+missing flags; a stale logout/expired token has neither
    assert proof.kind_for("CWE-613") == proof.GENERIC
    assert proof.kind_for("CWE-614") == proof.SESSION


# ------------------------------------------------------------ verifier, authorization

class Shop:
    """/order/2 owned by uid 2 and /admin both answer a cookie and refuse anonymous."""

    def __init__(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                authed = "session=alice" in self.headers.get("Cookie", "")
                route = self.path.split("?")[0]
                if route in ("/order/2", "/admin") and authed:
                    status, body = 200, '{"id":2,"user_id":2,"item":"Gadget"}'
                elif route == "/open":
                    status, body = 200, '{"id":2,"user_id":2,"item":"Gadget"}'
                else:
                    status, body = 401, "unauthorized"
                payload = body.encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_port}"


@pytest.fixture
def shop(tmp_path):
    s = Shop()
    env = _env(tmp_path, s.base)
    env.shop = s
    yield env
    s.srv.shutdown()
    env.db.close()


def _authz(env, path, cwe, contract, cookie="session=alice"):
    url = env.shop.base + path
    r = env.probe.request(env.eid, env.scope, url, headers={"Cookie": cookie}, tool="check")
    cand = {"title": f"authz on {path}", "cwe": cwe, "severity": "high", "endpoint": url,
            "evidence_ids": [r["evidence_id"]], "quote": '"user_id":2',
            "proof_request": {"method": "GET", "url": url, "headers": {"Cookie": cookie}},
            "dedup_key": f"a:{path}:{cwe}", "proof": contract}
    fid = env.pipeline.submit_candidate(env.eid, cand)["id"]
    return env.verifier.verify(env.eid, env.scope, fid), fid


def _state(env, fid):
    return env.db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"]


def test_ownership_contract_from_the_served_body_validates(shop):
    url = shop.shop.base + "/order/2"
    body = '{"id":2,"user_id":2,"item":"Gadget"}'
    out, fid = _authz(shop, "/order/2", "CWE-639", _contract("alice", 1, url, body))
    assert out["verdict"] == "reproduced", out
    assert _state(shop, fid) == "validated"


def test_ownership_contract_without_an_owner_field_is_refused(shop):
    url = shop.shop.base + "/order/2"
    out, fid = _authz(shop, "/order/2", "CWE-639", _contract("alice", 1, url, '{"item":"x"}'))
    assert out["verdict"] == "unsupported" and "owner_field" in out["detail"], out
    assert _state(shop, fid) == "observed"


def test_privilege_contract_validates_when_anonymous_is_refused(shop):
    url = shop.shop.base + "/admin"
    out, fid = _authz(shop, "/admin", "CWE-284", _contract("alice", 1, url, privilege="user"))
    assert out["verdict"] == "reproduced", out
    assert _state(shop, fid) == "validated"


def test_privilege_contract_without_a_privilege_is_refused(shop):
    url = shop.shop.base + "/admin"
    out, fid = _authz(shop, "/admin", "CWE-284", _contract("alice", 1, url))
    assert out["verdict"] == "unsupported" and "privilege" in out["detail"], out
    assert _state(shop, fid) == "observed"


def test_privilege_claim_on_an_anonymously_readable_route_is_refused(shop):
    url = shop.shop.base + "/open"
    out, fid = _authz(shop, "/open", "CWE-284", _contract("alice", 1, url, privilege="user"))
    assert out["verdict"] == "unsupported" and "anonymously" in out["detail"], out
    assert _state(shop, fid) == "observed"


# ------------------------------------------------------------ role matrix, real lab

def test_role_matrix_findings_all_validate_against_the_lab(tmp_path):
    mod, base, srv = _lab("labs/rolelab/app.py", "rolelab_contracts")
    try:
        env = _env(tmp_path, base)
        spec = tmp_path / "openapi.json"
        spec.write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "r", "version": "1"},
                                    "paths": {p: {"get": {"responses": {"200": {"description": "x"}}}}
                                              for p in ("/api/me", "/api/reports", "/reports-all",
                                                        "/api/users/{id}", "/api/orders/{id}")}}))
        names = [n for n, row in mod.USERS.items() if row[2] == "user"][:2]
        auth = {"identities": [{"username": n, "password": mod.USERS[n][1],
                                "login_url": base + "/api/login"} for n in names],
                "test_hints": {}, "openapi": str(spec)}
        out = audit_role_matrix(env.db, env.evidence, env.probe, env.scope, env.eid, auth,
                                env.pipeline)
        assert out["candidates"], out
        for f in _rows(env):
            assert proof.missing(proof.kind_for(f["cwe"]), _spec(env, f).get("proof"),
                                 _spec(env, f)["proof_request"], f["title"]) == [], f["title"]
        verdicts = _verify_all(env)
        assert {v["verdict"] for v in verdicts.values()} == {"reproduced"}, verdicts
    finally:
        srv.shutdown()


# ------------------------------------------------------------ JWT claim trust

def test_jwt_claim_trust_and_expiry_validate_and_need_their_contract(tmp_path):
    mod, base, srv = _lab("labs/jwtlab/app.py", "jwtlab_contracts")
    try:
        env = _env(tmp_path, base)
        auth = {"identities": [{"login_url": base + "/login", "username": "alice",
                                "password": "alice" + "-lab-pass"}],
                "test_hints": {"jwt": {"url": base + "/api/profile"}}}
        audit_jwt(env.db, env.evidence, env.probe, env.scope, env.eid, auth, env.pipeline)
        claim = next(f for f in _rows(env) if f["cwe"] == "CWE-863")
        spec = _spec(env, claim)
        assert spec["proof"]["privilege"] and spec["proof"]["benign_request"]["url"].endswith("/api/profile")
        # negative: the same finding with the privilege struck out is refused, not defaulted
        gaps = proof.missing(proof.AUTHORIZATION, {**spec["proof"], "privilege": ""},
                             spec["proof_request"], claim["title"])
        assert "owner_field" in gaps and "privilege" in gaps
        verdicts = _verify_all(env)
        by_cwe = {k.split(":")[0]: v["verdict"] for k, v in verdicts.items()}
        assert by_cwe["CWE-863"] == "reproduced", verdicts
        assert by_cwe["CWE-613"] == "reproduced", verdicts
    finally:
        srv.shutdown()


# ------------------------------------------------------------ command injection (timing)

def test_command_injection_emits_a_timing_contract_with_the_benign_control(tmp_path, monkeypatch):
    class Quiet(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"pong")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        env = _env(tmp_path, base)
        steps = iter([0.0, 0.18, 1.0, 1.18, 2.0, 7.12, 8.0, 13.05])
        monkeypatch.setattr(inj, "_clock", lambda: next(steps))
        monkeypatch.setattr(inj, "SLEEP_SECONDS", 0)
        out = inj.audit_injection(
            env.db, env.evidence, env.probe, env.scope, env.eid,
            {"test_hints": {"injection": {"targets": [
                {"url": base + "/ping", "param": "host", "kind": "command"}]}}}, env.pipeline)
        assert len(out["candidates"]) == 1, out
        f = _rows(env)[0]
        spec = _spec(env, f)
        assert f["cwe"] == "CWE-78" and spec["proof"]["signal"] == "timing"
        assert spec["proof"]["benign_request"]["url"] == base + "/ping?host=127.0.0.1"
        assert proof.missing(proof.BLIND_COMMAND, spec["proof"], spec["proof_request"], f["title"]) == []
        # negative: without the control a delay is just load
        bare = {k: v for k, v in spec["proof"].items() if k != "benign_request"}
        assert proof.missing(proof.BLIND_COMMAND, bare, spec["proof_request"], f["title"]) \
            == ["benign_request.url"]
    finally:
        srv.shutdown()
