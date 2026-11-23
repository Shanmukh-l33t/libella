"""Web-protocol audit against the in-process lab: each seeded flaw proves, /hard/* does not.

Every assertion reads captured exchanges and evidence blobs, never the audit's
return value alone, and every raw socket is checked against the egress decision.
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

import libella.web_protocol_audit as wpa  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.egress import EgressDecision  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402
from libella.web_protocol_audit import audit_web_protocol  # noqa: E402

HOST = "libella-lab.invalid"


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("protolab_app", str(ROOT / "labs/protolab/app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    srv = make_server("127.0.0.1", 0, mod.application, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"base": f"http://127.0.0.1:{srv.server_port}", "mod": mod,
           "port": srv.server_port}
    srv.shutdown()


@pytest.fixture
def env(tmp_path, lab):
    db = DB(tmp_path / "db.sqlite")
    evidence = EvidenceStore(db, tmp_path / "ev")
    eid = "eng_protocol"
    spec = {"targets": [{"kind": "url", "value": lab["base"]}], "categories": ["web"]}
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, "protocol", "safe_active", "draft", json.dumps(spec), "{}", "{}", time.time()))
    scope = Scope({**spec, "rate_limit_rps": 1000, "max_concurrency": 2})
    return SimpleNamespace(db=db, evidence=evidence, probe=HttpProbe(db, evidence),
                           pipeline=FindingPipeline(db, evidence), scope=scope, eid=eid)


def run(env, url, **hint):
    auth = {"test_hints": {"web_protocol": {"url": url, **hint}}}
    return audit_web_protocol(env.db, env.evidence, env.probe, env.scope, env.eid, auth,
                              env.pipeline)


def findings(env):
    return env.db.query("SELECT * FROM findings WHERE engagement_id=?", (env.eid,))


def exchanges(env, path):
    return env.db.query("SELECT * FROM exchanges WHERE engagement_id=? AND url LIKE ?",
                        (env.eid, "%" + path + "%"))


def check_quotes(env) -> None:
    """Every finding's quote must occur in the evidence it is bound to."""
    rows = findings(env)
    assert rows
    for f in rows:
        blobs = {e: json.loads(env.evidence.read(e))
                 for e in json.loads(f["evidence_ids_json"])}
        kinds = {e: env.db.one("SELECT kind FROM evidence WHERE id=?", (e,))["kind"] for e in blobs}
        spec = next(b for e, b in blobs.items() if kinds[e] == "proof_spec")
        quote, where = spec["quote"], spec.get("quote_in", "body")
        assert quote, f["title"]
        if where == "header_fact":
            name, _, value = quote.partition(":")
            headers = {}
            for e, b in blobs.items():
                if kinds[e] == "http_exchange":
                    headers |= {k.lower(): v for k, v in blobs[e]["response"]["headers"].items()}
            assert value.strip() in headers.get(name.strip().lower(), ""), f["title"]
        else:
            texts = []
            for e, b in blobs.items():
                if kinds[e] not in ("http_exchange", "http_raw"):
                    continue
                resp = b.get("response") or {}
                texts.append(resp["body"] if isinstance(resp.get("body"), str) else json.dumps(resp))
            assert any(quote in t for t in texts), f["title"]


def test_host_header_injection_is_proven(env, lab):
    out = run(env, lab["base"] + "/portal", host_header=HOST, reset_path="/reset")
    assert out["status"] == "assessed"
    assert len(out["candidates"]) == 2
    quotes = {c["quote_in"]: c["quote"] for c in out["candidates"]}
    assert quotes["header_fact"] == f"Location: http://{HOST}/login"
    assert any(HOST in q for q in [quotes["body"]])
    assert all(c["cwe"] == "CWE-601" for c in out["candidates"])
    # the direct Host override was the vector on the declared reset link
    reset = [json.loads(env.evidence.read(r["evidence_id"])) for r in exchanges(env, "/reset")]
    assert any(b["request"]["headers"].get("Host") == HOST for b in reset)
    check_quotes(env)


def test_bare_reflection_is_only_an_observation(env, lab):
    out = run(env, lab["base"] + "/echo", host_header=HOST)
    assert out["candidates"] == []
    assert findings(env) == []
    assert any("reflection alone" in o["summary"] for o in out["observations"])


def test_cache_poisoning_is_proven(env, lab):
    out = run(env, lab["base"] + "/cache", cache_probe="X-Cache-Canary")
    assert len(out["candidates"]) == 1 and out["candidates"][0]["cwe"] == "CWE-349"
    assert "canary=" in out["candidates"][0]["quote"]
    hits = exchanges(env, "/cache")
    assert len(hits) == 2
    blobs = [json.loads(env.evidence.read(r["evidence_id"])) for r in hits]
    canary = blobs[0]["request"]["headers"]["X-Cache-Canary"]
    assert canary not in json.dumps(blobs[1]["request"]["headers"])
    assert canary in blobs[1]["response"]["body"]
    check_quotes(env)


def test_hpp_validation_bypass_is_proven(env, lab):
    out = run(env, lab["base"] + "/pay",
              param={"name": "amount", "valid": "100", "invalid": "5000"})
    assert len(out["candidates"]) == 1 and out["candidates"][0]["cwe"] == "CWE-235"
    hit = out["candidates"][0]
    assert "amount=5000" in hit["quote"]  # the executed copy, verbatim
    control = json.loads(env.evidence.read(hit["evidence_ids"][1]))
    assert control["response"]["status"] == 400
    assert {r["status"] for r in exchanges(env, "/pay")} == {200, 400}
    check_quotes(env)


def test_method_tampering_put_is_proven(env, lab):
    out = run(env, lab["base"] + "/", methods="/export")
    assert len(out["candidates"]) == 1 and out["candidates"][0]["cwe"] == "CWE-650"
    hit = out["candidates"][0]
    assert hit["proof_request"]["method"] == "PUT"
    assert "protected export" in hit["quote"]
    rows = exchanges(env, "/export")
    assert 403 in {r["status"] for r in rows} and 200 in {r["status"] for r in rows}
    # the override header was tried and not honoured: no second claim
    tried = [json.loads(env.evidence.read(r["evidence_id"])) for r in rows]
    assert any("X-HTTP-Method-Override" in b["request"]["headers"] for b in tried)
    check_quotes(env)


def test_hardened_mirror_yields_no_candidates(env, lab):
    base = lab["base"]
    out = run(env, base + "/hard/pay", host_header=HOST, reset_path="/hard/reset",
              cache_probe="X-Cache-Canary",
              param={"name": "amount", "valid": "100", "invalid": "5000"},
              methods="/hard/export")
    assert out["candidates"] == [] and findings(env) == []
    out2 = run(env, base + "/hard/cache", cache_probe="X-Cache-Canary")
    assert out2["candidates"] == [] and findings(env) == []
    # the hardened routes answered; absence of a finding is not a dead target
    assert exchanges(env, "/hard/export") and exchanges(env, "/hard/cache")


def test_absent_hint_makes_zero_requests(env):
    out = audit_web_protocol(env.db, env.evidence, env.probe, env.scope, env.eid, {}, env.pipeline)
    assert out["status"] == "not_configured"
    assert out["limitations"]
    assert env.db.query("SELECT * FROM exchanges WHERE engagement_id=?", (env.eid,)) == []


def test_out_of_scope_url_is_blocked_before_any_request(env, lab):
    env.scope = Scope({"targets": [{"kind": "url", "value": "http://127.0.0.1:9/"}],
                       "categories": ["web"], "rate_limit_rps": 1000})
    out = run(env, lab["base"] + "/portal", host_header=HOST)
    assert out["status"] == "blocked" and out["candidates"] == []
    assert env.db.query("SELECT * FROM exchanges WHERE engagement_id=?", (env.eid,)) == []


class _Sock:
    def settimeout(self, _t):
        pass

    def sendall(self, data):
        self.sent = data

    def recv(self, _n):
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"

    def close(self):
        pass


def test_smuggling_is_opt_in_consults_egress_and_claims_nothing(env, lab, monkeypatch):
    calls, dials = [], []
    real_decide = wpa.Egress.decide

    def record(self, host, port=None, scheme="http", **kw):
        calls.append((host, port, scheme))
        return real_decide(self, host, port, scheme, **kw)

    real_connect = wpa._connect

    def connect(addr, timeout=5):
        dials.append(addr)
        return real_connect(addr, timeout=timeout)

    monkeypatch.setattr(wpa.Egress, "decide", record)
    monkeypatch.setattr(wpa, "_connect", connect)
    out = run(env, lab["base"] + "/", smuggling=True)
    assert calls[0] == ("127.0.0.1", lab["port"], "http")
    assert dials and all(addr == ("127.0.0.1", lab["port"]) for addr in dials)
    assert out["candidates"] == [] and findings(env) == []
    obs = [o for o in out["observations"] if o["kind"] == "web_protocol_smuggling"]
    assert obs and "timings" in obs[0]["summary"] and "no desync is claimed" in obs[0]["summary"]


def test_smuggling_denied_by_egress_opens_no_socket(env, lab, monkeypatch):
    seen = []

    def deny(self, host, port=None, scheme="http", **kw):
        seen.append((host, port, scheme))
        return EgressDecision(False, "denied by test")

    def boom(*a, **k):
        raise AssertionError("raw socket opened despite an egress denial")

    monkeypatch.setattr(wpa.Egress, "decide", deny)
    monkeypatch.setattr(wpa, "_connect", boom)
    out = run(env, lab["base"] + "/", smuggling=True)
    assert seen == [("127.0.0.1", lab["port"], "http")]
    assert out["candidates"] == []
    assert any("refused by egress" in lim for lim in out["limitations"])


def test_smuggling_zero_requests_without_the_opt_in(env, lab):
    out = run(env, lab["base"] + "/")
    assert out["candidates"] == []
    assert any("opt-in" in lim for lim in out["limitations"])
    assert env.db.query("SELECT * FROM exchanges WHERE engagement_id=?", (env.eid,)) == []


def test_desync_canary_on_another_connection_is_a_finding(env, lab, monkeypatch):
    monkeypatch.setattr(wpa, "_connect", lambda addr, timeout=5: _Sock())

    def fake_raw(decision, payload, timeout=5.0):
        canary = payload.split(b"/probe-")[1].split(b" ")[0]
        return b"HTTP/1.1 200 OK\r\n\r\nleaked /" + canary, {"duration_ms": 1.0, "bytes": 40}

    monkeypatch.setattr(wpa, "_raw", fake_raw)
    out = run(env, lab["base"] + "/", smuggling=True)
    assert len(out["candidates"]) == 1 and out["candidates"][0]["cwe"] == "CWE-444"
    assert out["candidates"][0]["proof_request"]["method"] == "RAW"
    check_quotes(env)
