"""Autonomy: runtime specialist charters, capability discovery, bounded memory.

Every test drives the real AgentRunner against a scripted model and a local lab,
so what is asserted is the runtime's behaviour, not a mock of it. The security
claims (an agent cannot widen its own surface or budget) are asserted on the
deterministic side effect: scope refusals, policy degradations, tool_calls,
findings.
"""
import json
import threading
import time

import pytest
from flask import Flask, request
from werkzeug.serving import make_server

import libella.agent_runtime as ar_mod
from libella import specialists
from libella.agent_runtime import AgentRunner
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.scope import Scope
from libella.specialists import ALLOWED_ACTIONS, MAX_ITERATIONS, validate_spec
from libella.tools import Registry
from libella.tools.adapters import ALL_ADAPTERS
from libella.tools.http_probe import HttpProbe
from libella.tools.runner import ToolRunner

PROMPT_BUDGET = 8000  # working memory + previous result, per turn


class ScriptedLLM:
    """Scripted actions; keeps every prompt it saw so tests can inspect them."""

    def __init__(self, db, steps):
        self.db = db
        self.steps = list(steps)
        self.users = []

    def model_for(self, role):
        return "mock-model"

    def complete(self, role, system, user, engagement_id=None, json_schema=None, temperature=0.1):
        self.users.append(user)
        step = self.steps.pop(0) if self.steps else {
            "thought": "done", "action": "finish", "args": {"summary": "no more steps"}}
        action = step(self.db, user) if callable(step) else step
        return {"content": json.dumps(action), "parsed": action,
                "usage": {"input_tokens": 10, "output_tokens": 10, "cost_usd": 0.0001,
                          "model": "mock-model"}}


@pytest.fixture
def lab():
    app = Flask("libella-autonomy")

    @app.get("/search")
    def search():
        return f"<html><body>Results for: {request.args.get('q', '')}</body></html>"

    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{srv.server_port}"
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
    scope = Scope({"targets": [{"kind": "url", "value": lab}],
                   "categories": ["recon", "web"], "rate_limit_rps": 1000})
    return db, ev, pipe, probe, reg, runner, scope


def _agent(platform, steps, profile="safe_active", budgets=None):
    db, ev, pipe, probe, reg, runner, scope = platform
    db.execute(
        "INSERT OR REPLACE INTO engagements(id, name, profile, status, scope_json, budgets_json, created_at) "
        "VALUES('eng','autonomy',?,'draft','{}',?,0)", (profile, json.dumps(budgets or {})))
    llm = ScriptedLLM(db, steps)
    return AgentRunner(db, ev, pipe, probe, reg, runner, llm, scope, "eng"), llm


def _mint(slug, actions, tools=None, **budget):
    return {"thought": f"mint {slug}", "action": "create_specialist",
            "args": {"slug": slug,
                     "expertise": "ColdFusion administrator API and J2EE stack configuration review",
                     "actions": actions, "tools": tools or [], "budget": budget}}


def _stored(db, slug):
    spec = specialists.get(db, "eng", slug)
    return spec["charter"] if spec else None


def test_generated_specialist_is_persisted_then_delegated_and_run(platform, lab):
    db, *_ = platform
    steps = [
        {"thought": "coldfusion in the header", "action": "http_request",
         "args": {"url": f"{lab}/search?q=cf"}},
        _mint("cf_config", ["read_context", "http_request", "run_check", "record_hypothesis",
                            "propose_finding"], max_usd=0.5, max_iterations=6),
        {"thought": "hand off", "action": "delegate",
         "args": {"role": "cf_config", "objective": "review the CF admin surface", "target": lab}},
        # the specialist's own turns
        {"thought": "cf admin login", "action": "http_request",
         "args": {"url": f"{lab}/search?q=admin"}},
        {"thought": "cf surface mapped", "action": "finish", "args": {"summary": "cf admin mapped"}},
        # back in the coordinator
        {"thought": "wrapped up", "action": "finish", "args": {"summary": "specialist covered CF"}},
    ]
    ar, llm = _agent(platform, steps)
    res = ar.run({"id": "i1", "objective": "investigate", "role": "web"}, "web")

    assert res["status"] == "completed", res
    charter = _stored(db, "cf_config")
    assert charter and charter["actions"] == [
        "read_context", "http_request", "run_check", "record_hypothesis", "propose_finding",
        "finish"], charter
    assert "delegate" not in charter["actions"] and "create_specialist" not in charter["actions"]
    # auditable creation
    created = db.query("SELECT payload_json FROM events WHERE engagement_id='eng' "
                       "AND kind='specialist_created'")
    assert created and json.loads(created[0]["payload_json"])["slug"] == "cf_config"
    # the delegate targeted the new role and the intent carries it
    intent = db.one("SELECT role, status FROM intents WHERE engagement_id='eng' AND parent_id='i1'")
    assert intent["role"] == "cf_config" and intent["status"] == "done"
    # the specialist really ran, under its own charter and iteration ceiling
    roles = {r["role"]: r for r in db.query("SELECT role, status, iterations FROM agent_runs "
                                            "WHERE engagement_id='eng'")}
    assert set(roles) == {"web", "cf_config"} and roles["cf_config"]["iterations"] == 2

    kinds = {r["action_kind"] for r in db.query(
        "SELECT action_kind FROM investigation_steps WHERE engagement_id='eng'")}
    assert {"specialist", "delegation"} <= kinds


def test_spec_cannot_widen_the_allowlist_or_the_budget(platform, lab):
    db, *_ = platform
    steps = [
        _mint("cf_config", ["http_request", "exec_shell"]),          # not an action at all
        _mint("cf_config", ["http_request", "delegate"]),            # coordinator meta action
        _mint("web", ["http_request"]),                              # built-in role name
        _mint("cf_config", ["http_request", "run_check", "finish"],
              max_usd=999, max_duration_s=99999, max_iterations=99),
        {"thought": "probe", "action": "http_request", "args": {"url": f"{lab}/search?q=1"}},
        {"thought": "done", "action": "finish", "args": {"summary": "s"}},
    ]
    ar, llm = _agent(platform, steps, budgets={"max_usd": 0.4, "max_duration_s": 120})
    res = ar.run({"id": "i1", "objective": "investigate", "role": "web"}, "web")

    # the three refused specs left nothing behind
    assert db.one("SELECT COUNT(*) n FROM events WHERE engagement_id='eng' "
                  "AND kind='specialist_created'")["n"] == 1
    refused = [u for u in llm.users if "specialist refused" in u]
    assert len(refused) >= 3, llm.users

    # the accepted one is clamped to the engagement ceiling, not what it asked for
    charter = _stored(db, "cf_config")
    assert charter["budget"]["max_usd"] == 0.4
    assert charter["budget"]["max_duration_s"] == 120
    assert charter["max_iterations"] == MAX_ITERATIONS
    assert charter["clamped"] is True
    assert set(charter["actions"]) <= set(ALLOWED_ACTIONS)
    assert res["status"] == "completed"

    # the validator itself is the boundary (no DB, no model)
    with pytest.raises(ValueError, match="not allowed"):
        validate_spec({"slug": "x_spec", "expertise": "a domain that is long enough to pass",
                       "actions": ["exec_shell"]}, {"max_usd": 1.0})
    with pytest.raises(ValueError, match="coordinator"):
        validate_spec({"slug": "x_spec", "expertise": "a domain that is long enough to pass",
                       "actions": ["create_specialist"]}, {"max_usd": 1.0})
    clamped = validate_spec({"slug": "x_spec", "expertise": "a domain that is long enough to pass",
                             "actions": ["http_request"], "budget": {"max_usd": 1e6}},
                            {"max_usd": 0.25})
    assert clamped["budget"]["max_usd"] == 0.25 and clamped["clamped"] is True


def test_list_capabilities_reports_only_profile_permitted_tools(platform, lab, monkeypatch):
    db, *_ = platform
    probed = []

    def fake_check(spec, force=False):
        probed.append(spec.name)
        return {"name": spec.name, "status": "missing", "level": "missing", "version": None,
                "minimum": None, "degraded": False, "limitations": ["not installed"],
                "detail": "not installed", "checked_at": 0.0}

    monkeypatch.setattr(ar_mod.readiness, "check", fake_check)
    steps = [
        {"thought": "probe", "action": "http_request", "args": {"url": f"{lab}/search?q=1"}},
        {"thought": "what can I run", "action": "list_capabilities", "args": {}},
        {"thought": "done", "action": "finish", "args": {"summary": "s"}},
    ]
    ar, llm = _agent(platform, steps, profile="passive")
    res = ar.run({"id": "i1", "objective": "investigate", "role": "web"}, "web")

    assert res["status"] == "completed", res
    # passive permits the passive scanners only: forbidden tools were not even probed
    assert set(probed) == {"httpx", "subfinder"}, probed
    result = llm.users[-1]
    assert '"tool": "httpx"' in result and '"installed": false' in result
    assert '"tool": "nmap"' not in result and '"tool": "nuclei"' not in result
    # a missing binary is reported, never fatal, and nothing was executed
    assert db.one("SELECT COUNT(*) n FROM tool_calls")["n"] == 0


def test_missing_binary_is_reported_as_missing_without_crashing(platform, lab, monkeypatch):
    def fake_check(spec, force=False):
        level = "missing" if spec.name == "nuclei" else "functional"
        return {"name": spec.name, "status": level, "level": level, "version": None,
                "minimum": None, "degraded": False, "limitations": [], "detail": "",
                "checked_at": 0.0}

    monkeypatch.setattr(ar_mod.readiness, "check", fake_check)
    steps = [
        {"thought": "probe", "action": "http_request", "args": {"url": f"{lab}/search?q=1"}},
        {"thought": "what can I run", "action": "list_capabilities", "args": {}},
        {"thought": "done", "action": "finish", "args": {"summary": "s"}},
    ]
    ar, llm = _agent(platform, steps)
    res = ar.run({"id": "i1", "objective": "investigate", "role": "web"}, "web")

    assert res["status"] == "completed", res
    result = llm.users[-1]
    assert '"tool": "nuclei"' in result and '"installed": false' in result
    assert '"tool": "nmap"' in result  # present tools are still listed beside it


def test_working_memory_is_bounded_and_keeps_older_observations_as_a_digest(platform, lab):
    db, *_ = platform
    now = time.time()
    for i in range(150):
        db.execute(
            "INSERT INTO observations(id, engagement_id, intent_id, kind, summary, source_derived, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (f"obs_{i}", "eng", None, "note" if i % 2 else "tool", "x" * 300 + f" observation {i}",
             "agent", now + i))
    db.execute(
        "INSERT INTO hypotheses(id, engagement_id, kind, statement, status, confidence, created_by, "
        "created_at, updated_at) VALUES('hyp_1','eng','auth','the CF admin API skips auth on /CFIDE',"
        "'supported',0.7,'run_prev',?,?)", (now, now))
    # enough assets/findings to blow any unbounded context: the trim must hold the line
    for i in range(40):
        db.execute("INSERT INTO assets(id, engagement_id, kind, key, value_json, first_seen, last_seen) "
                   "VALUES(?,?,?,?,?,?,?)", (f"a_{i}", "eng", "endpoint", f"/a/very/long/path/{i}",
                                             "{}", now, now + i))
    for i in range(12):
        db.execute("INSERT INTO findings(id, engagement_id, title, severity, state, endpoint, created_at) "
                   "VALUES(?,?,?,?,?,?,?)", (f"f_{i}", "eng", "y" * 180 + f" {i}", "high",
                                             "suspected", f"/p/{i}", now + i))
    steps = [
        {"thought": "probe", "action": "http_request", "args": {"url": f"{lab}/search?q=1"}},
        {"thought": "done", "action": "finish", "args": {"summary": "s"}},
    ]
    ar, llm = _agent(platform, steps)
    ar.run({"id": "i1", "objective": "investigate", "role": "web"}, "web")

    assert llm.users, "the loop must have prompted the model"
    assert max(len(u) for u in llm.users) <= PROMPT_BUDGET, max(len(u) for u in llm.users)
    memory = llm.users[-1]
    assert len(memory) <= ar_mod.CONTEXT_CHARS + ar_mod.PREV_CHARS + 250, len(memory)
    assert '"earlier_observations"' in memory and '"count": 144' in memory
    assert "recent_observations" in memory
    # a hypothesis another specialist established is carried forward, not re-derived
    assert "CFIDE" in memory


def test_specialist_cannot_leave_scope_or_run_a_forbidden_tool(platform, lab):
    db, *_ = platform
    steps = [
        _mint("cf_config", ["http_request", "run_tool"], tools=["httpx"]),
        {"thought": "hand off", "action": "delegate",
         "args": {"role": "cf_config", "objective": "scan the CF host", "target": lab}},
        # the specialist tries to break out of the controller
        {"thought": "elsewhere", "action": "http_request", "args": {"url": "http://evil.invalid/"}},
        {"thought": "scanner", "action": "run_tool", "args": {"tool": "nuclei", "params": {"target": lab}}},
        # blocked, so it does the permitted thing and concludes
        {"thought": "stay in scope", "action": "http_request", "args": {"url": f"{lab}/search?q=1"}},
        {"thought": "done", "action": "finish", "args": {"summary": "blocked"}},
        {"thought": "wrapped up", "action": "finish", "args": {"summary": "specialist done"}},
    ]
    ar, _ = _agent(platform, steps, profile="passive", budgets={"max_usd": 5})
    res = ar.run({"id": "i1", "objective": "investigate", "role": "web"}, "web")

    assert res["status"] == "completed", res
    assert db.one("SELECT COUNT(*) n FROM events WHERE engagement_id='eng' "
                  "AND kind='scope_refusal'")["n"] >= 1
    degradations = [json.loads(r["payload_json"]) for r in db.query(
        "SELECT payload_json FROM events WHERE engagement_id='eng' AND kind='degradation'")]
    assert any(d.get("code") == "policy_restriction" and d.get("unit") == "nuclei"
               for d in degradations), degradations
    assert db.one("SELECT COUNT(*) n FROM tool_calls")["n"] == 0, "a forbidden tool must never launch"


def test_specialist_evidence_gate_still_holds(platform, lab):
    db, *_ = platform
    steps = [
        _mint("cf_config", ["http_request", "propose_finding"]),
        {"thought": "hand off", "action": "delegate",
         "args": {"role": "cf_config", "objective": "confirm the claim", "target": lab}},
        {"thought": "forge it", "action": "propose_finding", "args": {
            "title": "CF admin auth bypass", "cwe": "CWE-306", "severity": "critical",
            "endpoint": f"{lab}/CFIDE", "description": "d", "impact": "i", "remediation": "r",
            "evidence_ids": ["ev_nonexistent"], "quote": "admin console",
            "proof_request": {"method": "GET", "url": f"{lab}/CFIDE"}}},
        {"thought": "capture something real", "action": "http_request",
         "args": {"url": f"{lab}/search?q=1"}},
        {"thought": "done", "action": "finish", "args": {"summary": "no finding"}},
        {"thought": "wrapped up", "action": "finish", "args": {"summary": "specialist done"}},
    ]
    ar, _ = _agent(platform, steps)
    res = ar.run({"id": "i1", "objective": "investigate", "role": "web"}, "web")

    assert res["status"] == "completed", res
    assert res["findings"] == []
    assert db.one("SELECT COUNT(*) n FROM findings WHERE engagement_id='eng'")["n"] == 0


def test_run_stops_when_the_shared_engagement_spend_passes_the_ceiling(platform, lab):
    # another intent (or an inline specialist) already spent the engagement's budget:
    # this run's own cost is tiny, but the shared ceiling must still stop it
    agent, llm = _agent(platform, [
        {"thought": "probe", "action": "http_request", "args": {"url": lab + "/search?q=a"}},
        {"thought": "probe", "action": "http_request", "args": {"url": lab + "/search?q=b"}},
    ], budgets={"max_usd": 1.0})
    agent.db.execute(
        "INSERT INTO llm_usage(id, engagement_id, role, model, input_tokens, output_tokens, "
        "cost_usd, created_at) VALUES('u1','eng','web','m',1,1,1.5,0)")
    res = agent.run({"id": "i_budget", "objective": "probe"}, "web")
    assert res["status"] == "budget_exhausted"
    assert "engagement spend passed" in res["summary"]
    assert len(llm.users) == 1  # stopped on the first turn, no target request issued
    assert agent.db.one("SELECT COUNT(*) n FROM exchanges")["n"] == 0
