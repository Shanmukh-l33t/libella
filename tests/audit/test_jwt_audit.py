"""JWT audit against the in-process lab: the vulnerable endpoints prove, the hardened one does not.

Every assertion reads captured exchange rows and evidence blobs, never the
audit's own return value alone.
"""
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402
from libella.jwt_audit import audit_jwt  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402

PASSWORD = "alice" + "-lab-pass"


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("jwtlab_app", str(ROOT / "labs/jwtlab/app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    srv = make_server("127.0.0.1", 0, mod.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"base": f"http://127.0.0.1:{srv.server_port}", "mod": mod}
    srv.shutdown()


@pytest.fixture
def env(tmp_path, lab):
    db = DB(tmp_path / "db.sqlite")
    evidence = EvidenceStore(db, tmp_path / "ev")
    eid = "eng_jwt"
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, "jwt", "safe_active", "draft",
         json.dumps({"targets": [{"kind": "url", "value": lab["base"]}], "categories": ["api"]}),
         "{}", "{}", time.time()))
    scope = Scope({"targets": [{"kind": "url", "value": lab["base"]}], "categories": ["api"],
                   "rate_limit_rps": 1000, "max_concurrency": 2})
    return SimpleNamespace(db=db, evidence=evidence, probe=HttpProbe(db, evidence),
                           pipeline=FindingPipeline(db, evidence), scope=scope, eid=eid)


def run(env, url, login="/login", **hint):
    jwt_hint = {"url": url, **hint}
    auth = {"identities": [{"login_url": f"{env.scope.targets[0]['value']}{login}",
                            "username": "alice", "password": PASSWORD}],
            "test_hints": {"jwt": jwt_hint}}
    return audit_jwt(env.db, env.evidence, env.probe, env.scope, env.eid, auth, env.pipeline)


def findings(env):
    return env.db.query("SELECT * FROM findings WHERE engagement_id=?", (env.eid,))


def proof_spec(env, finding) -> dict:
    for e in json.loads(finding["evidence_ids_json"]):
        if env.db.one("SELECT kind FROM evidence WHERE id=?", (e,))["kind"] == "proof_spec":
            return json.loads(env.evidence.read(e))
    raise AssertionError("finding carries no proof spec")


def quote_hits_evidence(env) -> None:
    """Every finding's quote must occur in the response body of its bound evidence."""
    rows = findings(env)
    assert rows
    for f in rows:
        assert f["state"] == "observed"  # bound to a captured exchange, not a guess
        kinds = {e: env.db.one("SELECT kind FROM evidence WHERE id=?", (e,))["kind"]
                 for e in json.loads(f["evidence_ids_json"])}
        spec = next(json.loads(env.evidence.read(e)) for e, k in kinds.items() if k == "proof_spec")
        bodies = [json.loads(env.evidence.read(e))["response"]["body"]
                  for e, k in kinds.items() if k == "http_exchange"]
        assert bodies and any(spec["quote"] in b for b in bodies), f["title"]
        assert spec["proof_request"]["url"] == f["endpoint"]
        assert spec["proof_request"]["headers"]


def exchanges(env, path):
    return env.db.query("SELECT * FROM exchanges WHERE engagement_id=? AND url LIKE ?",
                        (env.eid, "%" + path + "%"))


def test_weak_secret_expiry_and_claim_trust_are_proven(env, lab):
    url = lab["base"] + "/api/profile"
    out = run(env, url)
    cwes = {f["cwe"] for f in out["findings"]}
    assert {"CWE-347", "CWE-613", "CWE-863"} <= cwes
    assert out["candidates"] == len(findings(env)) == len(out["findings"]) >= 3
    # a 200 exists only on requests that carried a token: the anonymous control got 401
    statuses = [r["status"] for r in exchanges(env, "/api/profile")]
    assert 200 in statuses and 401 in statuses
    quote_hits_evidence(env)
    assert any("token from Set-Cookie" in o or "token from response body" in o
               for o in out["observations"])


def test_alg_none_is_proven(env, lab):
    url = lab["base"] + "/api/none"
    out = run(env, url)
    assert out["candidates"] >= 1
    hit = [f for f in out["findings"] if "alg 'none'" in f["title"]]
    assert hit and hit[0]["cwe"] == "CWE-347"
    token = list(proof_spec(env, findings(env)[0])["proof_request"]["headers"].values())[0]
    assert token.endswith(".")  # empty signature
    quote_hits_evidence(env)


def test_hmac_rsa_confusion_is_proven(env, lab):
    url = lab["base"] + "/api/rs256"
    out = run(env, url, login="/login-rs")
    hit = [f for f in out["findings"] if "confusion" in f["title"]]
    assert hit and hit[0]["cwe"] == "CWE-347"
    # the key really came over the wire, from the lab's own jwks -> x5u chain
    assert exchanges(env, "/jwks.json") and exchanges(env, "/public.pem")
    quote_hits_evidence(env)


def test_hardened_endpoint_yields_zero_candidates(env, lab):
    out = run(env, lab["base"] + "/api/hard", login="/login-hard")
    assert out["candidates"] == 0
    assert findings(env) == []
    # the endpoint is live and does accept its own token: only the forgeries failed
    statuses = [r["status"] for r in exchanges(env, "/api/hard")]
    assert 200 in statuses and statuses.count(200) == 1


def test_out_of_scope_jku_is_refused_and_never_fetched(env, lab):
    foreign = "http://127.0.0.1:1/jwks.json"
    out = run(env, lab["base"] + "/api/rs256", login="/login-rs", jku=foreign)
    assert out["candidates"] == 0
    assert any("refused" in lim or "out of scope" in lim for lim in out["limitations"])
    assert not [r for r in env.db.query("SELECT * FROM exchanges WHERE engagement_id=?", (env.eid,))
                if foreign in r["url"] or ":1/" in r["url"]]
    assert findings(env) == []


def test_every_request_stayed_inside_scope(env, lab):
    run(env, lab["base"] + "/api/profile")
    urls = [r["url"] for r in env.db.query(
        "SELECT url FROM exchanges WHERE engagement_id=?", (env.eid,))]
    assert urls and all(u.startswith(lab["base"] + "/") for u in urls)
