"""Impact proof against the in-process ImpactLab: real impact, gated, hardened twins.

Every demonstration is judged from the evidence row it binds, never from the
module's return value alone. The gate is asserted by counting exchanges: an
unauthorized or refused proof must send nothing at all.
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

import libella.impact_proof as impact  # noqa: E402
from libella.checks import _candidate  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402
from libella.impact_proof import prove_impact  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location(
        "impactlab_app", str(ROOT / "labs/impactlab/app.py"))
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
    eid = "eng_impact"
    targets = [{"kind": "url", "value": lab["base"]}]
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, "impact", "safe_active", "draft",
         json.dumps({"targets": targets, "categories": ["web"]}), "{}", "{}", time.time()))
    scope = Scope({"targets": targets, "categories": ["web"], "rate_limit_rps": 1000,
                   "max_concurrency": 2})
    return SimpleNamespace(db=db, evidence=evidence, probe=HttpProbe(db, evidence),
                           pipeline=FindingPipeline(db, evidence), scope=scope, eid=eid,
                           base=lab["base"], marker=lab["mod"].IMPACT_MARKER)


def auth(**over):
    hint = {"lab": True,
            "markers": [{"table": "secrets", "column": "token", "value": "PLACEHOLDER"}],
            "sensitive_fields": ["email"], "command": "id", "object_id": "2"}
    hint.update(over)
    return {"test_hints": {"impact_proof": hint}}


def exchanges(env):
    return env.db.query("SELECT * FROM exchanges WHERE engagement_id=?", (env.eid,))


def finding(env, cwe, proof_url, quote_from, headers=None, capture_url=None):
    """Create a real finding whose proof_request is the given URL."""
    capture = env.probe.request(env.eid, env.scope, capture_url or proof_url, headers=headers,
                                tool="test_capture")
    assert capture.get("ok"), capture
    assert quote_from in capture["body"], capture["body"]
    pr = {"method": "GET", "url": proof_url}
    if headers:
        pr["headers"] = headers
    cand = _candidate("test finding", cwe, "A03:2021 Injection", "high", "high", proof_url,
                      "description", "predicted impact", "remediation",
                      capture["evidence_id"], quote_from, pr,
                      f"impact:{cwe}:{proof_url}")
    res = env.pipeline.submit_candidate(env.eid, cand)
    return env.db.one("SELECT * FROM findings WHERE id=?", (res["id"],))


def assert_demonstrated(env, row, result, cls):
    assert result["status"] == "demonstrated", result
    assert len(result["impact"]) == 1, result
    imp = result["impact"][0]
    assert imp["class"] == cls
    assert imp["finding_id"] == row["id"]
    assert imp["quote"]
    assert imp["quote"] in env.evidence.read(imp["evidence_id"]).decode(errors="replace")
    obs = env.db.query(
        "SELECT * FROM observations WHERE engagement_id=? AND kind='impact_demonstrated'",
        (env.eid,))
    assert any(o["quote"] == imp["quote"] and o["evidence_id"] == imp["evidence_id"]
               for o in obs), obs


def test_sql_injection_data_access_demonstrated(env):
    row = finding(env, "CWE-89", f"{env.base}/product?id=1", "Impact Widget")
    result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row,
                          auth(markers=[{"table": "secrets", "column": "token",
                                         "value": env.marker}]), env.pipeline)
    assert_demonstrated(env, row, result, "sql_injection")
    assert result["impact"][0]["quote"] == env.marker


def test_cross_identity_data_demonstrated(env):
    headers = {"X-User": "attacker"}
    row = finding(env, "CWE-639", f"{env.base}/orders/2", "attacker@example.com", headers,
                  capture_url=f"{env.base}/orders/1")
    result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row,
                          auth(), env.pipeline)
    assert_demonstrated(env, row, result, "cross_identity")
    quote = result["impact"][0]["quote"]
    assert "victim@example.com" in quote and "2" in quote


def test_command_execution_demonstrated(env):
    row = finding(env, "CWE-78", f"{env.base}/ping?host=127.0.0.1", "pinging")
    result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row,
                          auth(), env.pipeline)
    assert_demonstrated(env, row, result, "command_execution")
    assert "uid=" in result["impact"][0]["quote"]


def test_hardened_endpoints_demonstrate_nothing(env):
    cases = [
        ("CWE-89", f"{env.base}/hard/product?id=1", "Impact Widget", None,
         auth(markers=[{"table": "secrets", "column": "token", "value": env.marker}])),
        ("CWE-639", f"{env.base}/hard/orders/2", "attacker@example.com",
         {"X-User": "attacker"}, auth()),
        ("CWE-78", f"{env.base}/hard/ping?host=127.0.0.1", "pinging", None, auth()),
    ]
    for cwe, url, quote, headers, hint in cases:
        capture = f"{env.base}/hard/orders/1" if cwe == "CWE-639" else None
        row = finding(env, cwe, url, quote, headers, capture_url=capture)
        result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row,
                              hint, env.pipeline)
        assert result["status"] == "failed", (url, result)
        assert result["impact"] == [], (url, result)
    assert env.db.query(
        "SELECT * FROM observations WHERE engagement_id=? AND kind='impact_demonstrated'",
        (env.eid,)) == []


def test_absent_hint_sends_no_request(env):
    row = finding(env, "CWE-89", f"{env.base}/product?id=1", "Impact Widget")
    before = len(exchanges(env))
    result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row, {},
                          env.pipeline)
    assert result["status"] == "not_attempted" and result["limitations"]
    assert len(exchanges(env)) == before


def test_hint_without_lab_sends_no_request(env):
    row = finding(env, "CWE-78", f"{env.base}/ping?host=127.0.0.1", "pinging")
    before = len(exchanges(env))
    hint = {"test_hints": {"impact_proof": {"command": "id"}}}
    result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row, hint,
                          env.pipeline)
    assert result["status"] == "not_attempted" and result["limitations"]
    assert len(exchanges(env)) == before


def test_write_looking_command_refused_by_allowlist(env):
    assert impact.READ_ONLY_COMMANDS == ("id", "whoami", "uname -a")
    row = finding(env, "CWE-78", f"{env.base}/ping?host=127.0.0.1", "pinging")
    before = len(exchanges(env))
    for command in ("rm -rf /", "curl http://127.0.0.1:1/x", "bash -i"):
        result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row,
                              auth(command=command), env.pipeline)
        assert result["status"] == "refused", (command, result)
        assert result["impact"] == []
        assert len(exchanges(env)) == before, command
    urls = " ".join(e["url"] for e in exchanges(env))
    assert "rm -rf" not in urls and "curl" not in urls and "bash" not in urls
    assert "cmd=" not in urls  # the dangerous lab parameter is never called


def test_unsupported_class_and_out_of_scope_send_no_request(env):
    row = finding(env, "CWE-79", f"{env.base}/product?id=1", "Impact Widget")
    before = len(exchanges(env))
    result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row,
                          auth(), env.pipeline)
    assert result["status"] == "not_attempted"
    assert "no impact proof defined" in result["limitations"][0]
    assert len(exchanges(env)) == before

    outside = finding(env, "CWE-639", "http://127.0.0.1:1/orders/2", "attacker@example.com",
                      {"X-User": "attacker"}, capture_url=f"{env.base}/orders/1")
    before = len(exchanges(env))
    result = prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, outside,
                          auth(), env.pipeline)
    assert result["status"] == "refused"
    assert len(exchanges(env)) == before


def test_every_exchange_is_inside_scope(env):
    for cwe, url, quote, hint in (
            ("CWE-89", f"{env.base}/product?id=1", "Impact Widget",
             auth(markers=[{"table": "secrets", "column": "token", "value": env.marker}])),
            ("CWE-639", f"{env.base}/orders/2", "attacker@example.com", auth()),
            ("CWE-78", f"{env.base}/ping?host=127.0.0.1", "pinging", auth())):
        headers = {"X-User": "attacker"} if cwe == "CWE-639" else None
        capture = f"{env.base}/orders/1" if cwe == "CWE-639" else None
        row = finding(env, cwe, url, quote, headers, capture_url=capture)
        assert prove_impact(env.db, env.evidence, env.probe, env.scope, env.eid, row,
                            hint, env.pipeline)["status"] == "demonstrated"
    rows = exchanges(env)
    assert rows and all(r["url"].startswith(env.base) for r in rows), \
        [r["url"] for r in rows]
