"""Injection audit against the in-process lab: every class proves, /hard proves nothing.

Candidates are judged from the captured exchange and evidence rows, never from the
audit's own return value alone. The command-injection test drives the threshold logic
with a deterministic fake clock instead of waiting 5s; a separate check proves the lab
endpoint really does block on an injected sleep.
"""
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import libella.injection_audit as inj  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402
from libella.injection_audit import audit_injection  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("injlab_app", str(ROOT / "labs/injlab/app.py"))
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
    eid = "eng_inj"
    targets = [{"kind": "url", "value": lab["base"]}]
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, "inj", "safe_active", "draft",
         json.dumps({"targets": targets, "categories": ["web"]}), "{}", "{}", time.time()))
    scope = Scope({"targets": targets, "categories": ["web"], "rate_limit_rps": 1000,
                   "max_concurrency": 2})
    return SimpleNamespace(db=db, evidence=evidence, probe=HttpProbe(db, evidence),
                           pipeline=FindingPipeline(db, evidence), scope=scope, eid=eid,
                           base=lab["base"])


def run(env, targets, auth=None):
    auth = auth if auth is not None else {"test_hints": {"injection": {"targets": targets}}}
    return audit_injection(env.db, env.evidence, env.probe, env.scope, env.eid, auth,
                           env.pipeline)


def findings(env):
    return env.db.query("SELECT * FROM findings WHERE engagement_id=?", (env.eid,))


def proof_spec(env, finding) -> dict:
    for e in json.loads(finding["evidence_ids_json"]):
        if env.db.one("SELECT kind FROM evidence WHERE id=?", (e,))["kind"] == "proof_spec":
            return json.loads(env.evidence.read(e))
    raise AssertionError("finding carries no proof spec")


def quotes_are_in_evidence(env) -> None:
    """Every finding's quote must be a fact recorded in the blobs it is bound to."""
    rows = findings(env)
    assert rows
    for f in rows:
        assert f["state"] == "observed"  # bound to captured evidence, not a guess
        kinds = {e: env.db.one("SELECT kind FROM evidence WHERE id=?", (e,))["kind"]
                 for e in json.loads(f["evidence_ids_json"])}
        spec = next(json.loads(env.evidence.read(e)) for e, k in kinds.items() if k == "proof_spec")
        captured = {e: env.evidence.read(e).decode(errors="replace") for e, k in kinds.items()
                    if k in ("http_exchange", "oob_hit")}
        quote = spec["quote"]
        if spec.get("quote_in") == "header_fact":
            shown = [f"{k}: {v}"
                     for captured_id in captured
                     for k, v in json.loads(captured[captured_id])["response"]["headers"].items()]
            assert any(quote.lower() == line.lower() for line in shown), f["title"]
        else:
            assert any(quote in blob for blob in captured.values()), f["title"]
        assert spec["proof_request"]["url"].startswith(env.base + "/")
        assert len(json.loads(f["evidence_ids_json"])) >= 3  # attack + control + proof spec


def test_xxe_file_read_and_oob_callback_are_proven(env):
    out = run(env, [{"url": env.base + "/xml", "method": "POST", "param": "xml",
                     "kind": "xxe"}])
    assert out["status"] == "completed" and out["errors"] == []
    assert len(out["candidates"]) == 2, out
    cwes = {f["cwe"] for f in findings(env)}
    assert cwes == {"CWE-611"}
    assert any(inj.PASSWD_LINE.fullmatch(proof_spec(env, f)["quote"]) for f in findings(env))
    assert sum("out-of-band" in f["title"] for f in findings(env)) == 1
    quotes_are_in_evidence(env)


def test_command_injection_timing_is_proven_with_a_fake_clock(env, monkeypatch):
    steps = iter([0.0, 0.18, 1.0, 1.18, 2.0, 7.12, 8.0, 13.05])
    monkeypatch.setattr(inj, "_clock", lambda: next(steps))
    monkeypatch.setattr(inj, "SLEEP_SECONDS", 0)  # the delay is measured, not slept, in CI
    out = run(env, [{"url": env.base + "/ping", "param": "host", "kind": "command"}])
    assert out["errors"] == [] and len(out["candidates"]) == 1, out
    f = findings(env)[0]
    assert f["cwe"] == "CWE-78"
    assert any(o.startswith("command injection timing") and "delay 5.12s" in o
               for o in out["observations"])
    obs = env.db.one("SELECT * FROM observations WHERE kind='injection_observation' "
                     "AND quote LIKE 'delay%'")
    assert obs["quote"].startswith("delay 5.12s vs baseline 0.18s")
    assert obs["source_derived"] == "captured_exchange"
    quotes_are_in_evidence(env)


def test_timing_threshold_needs_repeatable_absolute_and_relative_delay():
    assert inj._timing_proven(0.18, 5.12, 5.05)
    assert not inj._timing_proven(0.18, 3.90, 3.90)   # under the 4s floor
    assert not inj._timing_proven(2.00, 7.90, 7.90)   # under 4x a 2s baseline
    assert inj._timing_proven(2.00, 8.10, 8.00)
    assert not inj._timing_proven(1.50, 5.20, 1.60)   # not repeatable


def test_lfi_traversal_returns_file_content(env):
    out = run(env, [{"url": env.base + "/download", "param": "file", "kind": "lfi"}])
    assert len(out["candidates"]) == 1, out
    f = findings(env)[0]
    assert f["cwe"] == "CWE-22"
    assert inj.PASSWD_LINE.fullmatch(proof_spec(env, f)["quote"])
    quotes_are_in_evidence(env)
    # the benign control asked for the same path without traversal and got nothing
    control = [r for r in env.db.query(
        "SELECT url FROM exchanges WHERE engagement_id=? AND url LIKE '%file=etc/passwd'",
        (env.eid,))]
    assert control


def test_php_filter_payload_only_for_php_targets():
    assert any("php://filter" in p for p, _ in inj._lfi_payloads(True))
    assert not any("php://filter" in p for p, _ in inj._lfi_payloads(False))


def test_crlf_header_injection_is_proven(env):
    out = run(env, [{"url": env.base + "/setcookie", "param": "name", "kind": "crlf"}])
    assert len(out["candidates"]) == 1, out
    f = findings(env)[0]
    assert f["cwe"] == "CWE-113"
    spec = proof_spec(env, f)
    assert spec["quote_in"] == "header_fact" and spec["quote"] == "libella-canary: 1"
    quotes_are_in_evidence(env)


def test_hardened_endpoints_yield_zero_candidates(env):
    out = run(env, [
        {"url": env.base + "/hard/xml", "method": "POST", "param": "xml", "kind": "xxe"},
        {"url": env.base + "/hard/ping", "param": "host", "kind": "command"},
        {"url": env.base + "/hard/download", "param": "file", "kind": "lfi"},
        {"url": env.base + "/hard/setcookie", "param": "name", "kind": "crlf"},
    ])
    assert out["status"] == "completed" and out["errors"] == []
    assert out["candidates"] == []
    assert findings(env) == []
    # the endpoints were really exercised: the probes are captured exchanges
    assert len(env.db.query("SELECT id FROM exchanges WHERE engagement_id=?", (env.eid,))) >= 8


def test_missing_hint_is_a_limitation_and_sends_nothing(env):
    out = run(env, [])
    assert out["status"] == "limited" and out["candidates"] == []
    assert any("no injectable parameter declared" in lim for lim in out["limitations"])
    assert env.db.query("SELECT id FROM exchanges WHERE engagement_id=?", (env.eid,)) == []
    assert findings(env) == []


def test_every_exchange_stays_inside_scope(env, monkeypatch):
    monkeypatch.setattr(inj, "SLEEP_SECONDS", 0)  # no real sleep: this test is about scope
    run(env, [
        {"url": env.base + "/xml", "method": "POST", "param": "xml", "kind": "xxe"},
        {"url": env.base + "/ping", "param": "host", "kind": "command"},
        {"url": env.base + "/download", "param": "file", "kind": "lfi"},
        {"url": env.base + "/setcookie", "param": "name", "kind": "crlf"},
    ])
    urls = [r["url"] for r in env.db.query(
        "SELECT url FROM exchanges WHERE engagement_id=?", (env.eid,))]
    assert urls and all(u.startswith(env.base + "/") for u in urls)


def test_target_without_a_kind_runs_every_class(env, monkeypatch):
    monkeypatch.setattr(inj, "SLEEP_SECONDS", 0)
    run(env, [{"url": env.base + "/download", "param": "file"}])
    tools = {r["tool"] for r in env.db.query(
        "SELECT tool FROM exchanges WHERE engagement_id=?", (env.eid,))}
    assert {"injection_xxe", "injection_cmd_probe", "injection_lfi", "injection_crlf"} <= tools


def test_out_of_scope_target_is_refused_without_a_request(env):
    out = run(env, [{"url": "http://127.0.0.1:1/x", "param": "q", "kind": "lfi"}])
    assert out["candidates"] == []
    assert any("out of scope" in lim for lim in out["limitations"])
    assert env.db.query("SELECT id FROM exchanges WHERE engagement_id=?", (env.eid,)) == []


def test_lab_ping_endpoint_really_blocks_on_an_injected_sleep(lab):
    started = time.monotonic()
    httpx.get(lab["base"] + "/ping", params={"host": "127.0.0.1;sleep 0.3"}, timeout=15)
    assert time.monotonic() - started >= 0.25
