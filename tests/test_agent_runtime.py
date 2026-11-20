"""Agent runtime regression: scripted LLM proves the investigation loop, evidence
gating, lifecycle termination, scope enforcement, and budgets (no live model)."""
import json
import threading
import time

import pytest
from flask import Flask, request
from werkzeug.serving import make_server

from libella.agent_runtime import AgentRunner
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.scope import Scope
from libella.tools import Registry
from libella.tools.adapters import ALL_ADAPTERS
from libella.tools.http_probe import HttpProbe
from libella.tools.runner import ToolRunner
from libella.verifier import Verifier


class ScriptedLLM:
    """Returns a scripted sequence of actions; can read DB to bind real evidence."""
    def __init__(self, db, steps):
        self.db = db
        self.steps = list(steps)
        self.calls = 0

    def model_for(self, role):
        return "mock-model"

    def complete(self, role, system, user, engagement_id=None, json_schema=None, temperature=0.1):
        self.calls += 1
        if not self.steps:
            action = {"thought": "done", "action": "finish", "args": {"summary": "no more steps", "evidence_ids": []}}
        else:
            step = self.steps.pop(0)
            action = step(self.db, user) if callable(step) else step
        return {"content": json.dumps(action), "parsed": action,
                "usage": {"input_tokens": 10, "output_tokens": 10, "cost_usd": 0.0001, "model": "mock-model"}}


@pytest.fixture
def lab():
    app = Flask(__name__)

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        return f"<html><body>Results for: {q}</body></html>"  # reflected XSS

    srv = make_server("127.0.0.1", 0, app)
    port = srv.port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


@pytest.fixture
def platform(tmp_path, lab):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    probe = HttpProbe(db, ev)
    pipe = FindingPipeline(db, ev)
    reg = Registry()
    for s in ALL_ADAPTERS:
        reg.register(s)
    runner = ToolRunner(db, ev, tmp_path / "runs")
    scope = Scope({"targets": [{"kind": "url", "value": lab}], "categories": ["recon", "web"]})
    ver = Verifier(db, ev, probe, pipe)
    return db, ev, pipe, probe, reg, runner, scope, ver


def _latest_ev(db, eng):
    row = db.one("SELECT id FROM evidence WHERE engagement_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1", (eng,))
    return row["id"] if row else None


def test_agent_investigates_and_proposes_evidence_backed_finding(platform, lab):
    db, ev, pipe, probe, reg, runner, scope, ver = platform
    eng = "eng"
    payload = "<script>alert(1)</script>"
    url = f"{lab}/search?q={payload}"

    def propose(db, user):
        eid = _latest_ev(db, eng)
        return {"thought": "payload reflected unescaped", "action": "propose_finding",
                "args": {"title": "Reflected XSS in q", "cwe": "CWE-79", "severity": "high",
                         "endpoint": f"{lab}/search", "description": "reflected", "impact": "xss",
                         "remediation": "encode", "evidence_ids": [eid], "quote": payload,
                         "proof_request": {"method": "GET", "url": url}}}

    steps = [
        {"thought": "probe the search endpoint", "action": "http_request", "args": {"url": url}},
        propose,
        {"thought": "concluded", "action": "finish", "args": {"summary": "XSS confirmed", "evidence_ids": []}},
    ]
    llm = ScriptedLLM(db, steps)
    ar = AgentRunner(db, ev, pipe, probe, reg, runner, llm, scope, eng)
    intent = {"id": "i1", "objective": f"investigate {lab}/search", "role": "web"}
    res = ar.run(intent, "web")
    assert res["status"] == "completed", res
    assert res["exit_reason"] == "completed"
    assert len(res["findings"]) == 1
    # investigation trace recorded
    kinds = {r["action_kind"] for r in db.query("SELECT action_kind FROM investigation_steps WHERE engagement_id=?", (eng,))}
    assert {"reason", "tool_call", "conclusion"} <= kinds
    # agent run accounted
    run = db.one("SELECT * FROM agent_runs WHERE engagement_id=?", (eng,))
    assert run["iterations"] == 3 and run["tokens_in"] > 0
    # independent verification reproduces the agent's finding
    fid = res["findings"][0]
    v = ver.verify(eng, scope, fid)
    assert v["verdict"] == "reproduced", v
    assert db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"] == "validated"


def test_finish_without_evidence_rejected(platform, lab):
    db, ev, pipe, probe, reg, runner, scope, ver = platform
    steps = [{"thought": "done already", "action": "finish", "args": {"summary": "nothing", "evidence_ids": []}}]
    ar = AgentRunner(db, ev, pipe, probe, reg, runner, ScriptedLLM(db, steps), scope, "eng")
    res = ar.run({"id": "i", "objective": "x", "role": "web"}, "web")
    # finish rejected (no evidence) -> nudged -> exhausts iterations, not completed
    assert res["exit_reason"] in ("max_iterations", "no_action")
    assert res["status"] != "completed"


def test_out_of_scope_request_refused(platform, lab):
    db, ev, pipe, probe, reg, runner, scope, ver = platform
    steps = [
        {"thought": "try external", "action": "http_request", "args": {"url": "http://evil.invalid/"}},
        {"thought": "stop", "action": "finish", "args": {"summary": "s", "evidence_ids": []}},
    ]
    ar = AgentRunner(db, ev, pipe, probe, reg, runner, ScriptedLLM(db, steps), scope, "eng")
    ar.run({"id": "i", "objective": "x", "role": "web"}, "web")
    refusals = db.query("SELECT * FROM events WHERE engagement_id='eng' AND kind='scope_refusal'")
    assert refusals, "out-of-scope agent request must be refused and audited"


def test_propose_finding_requires_real_evidence(platform, lab):
    db, ev, pipe, probe, reg, runner, scope, ver = platform
    steps = [
        {"thought": "fake claim", "action": "propose_finding",
         "args": {"title": "fake", "cwe": "CWE-79", "severity": "high", "endpoint": lab,
                  "description": "d", "impact": "i", "remediation": "r",
                  "evidence_ids": ["ev_nonexistent"], "quote": "x",
                  "proof_request": {"method": "GET", "url": lab}}},
        {"thought": "stop", "action": "finish", "args": {"summary": "s", "evidence_ids": []}},
    ]
    ar = AgentRunner(db, ev, pipe, probe, reg, runner, ScriptedLLM(db, steps), scope, "eng")
    ar.run({"id": "i", "objective": "x", "role": "web"}, "web")
    assert db.one("SELECT COUNT(*) n FROM findings WHERE engagement_id='eng'")["n"] == 0


def test_delegation_creates_gated_intent(platform, lab):
    db, ev, pipe, probe, reg, runner, scope, ver = platform
    steps = [
        {"thought": "hand off", "action": "delegate", "args": {"role": "api", "objective": "check api", "target": lab}},
        {"thought": "note", "action": "record_observation", "args": {"kind": "note", "summary": "delegating api work"}},
        {"thought": "done", "action": "finish", "args": {"summary": "delegated", "evidence_ids": []}},
    ]
    ar = AgentRunner(db, ev, pipe, probe, reg, runner, ScriptedLLM(db, steps), scope, "eng")
    ar.run({"id": "i", "objective": "x", "role": "web"}, "web")
    delegated = db.query("SELECT * FROM intents WHERE engagement_id='eng' AND parent_id='i'")
    assert delegated and delegated[0]["role"] == "api"
