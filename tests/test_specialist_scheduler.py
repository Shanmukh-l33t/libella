"""Registered specialists are scheduled roles the orchestrator really runs.

No mocks of the scheduler: each test starts the real run loop against a real DB,
a scripted model and a loopback lab, and asserts the side effects an operator
would see (agent_runs rows, investigation steps, registry state, degradations).
"""
import json
import threading

import pytest
from flask import Flask
from werkzeug.serving import make_server

from libella import specialists
from libella.agent_runtime import AgentRunner
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.orchestrator import Orchestrator
from libella.scope import Scope
from libella.tools import Registry
from libella.tools.adapters import ALL_ADAPTERS
from libella.tools.http_probe import HttpProbe
from libella.tools.runner import ToolRunner
from libella.verifier import Verifier

BUDGETS = {"max_usd": 5.0, "max_duration_s": 600}


class ScriptedLLM:
    """Scripted actions, queued as tests go; keeps every prompt it saw."""

    def __init__(self, db):
        self.db = db
        self.steps = []
        self.users = []

    def model_for(self, role):
        return "mock-model"

    def spend(self, engagement_id):
        return {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

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
    app = Flask("libella-scheduler")

    @app.get("/search")
    def search():
        return "<html><body>Results for: q</body></html>"

    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def env(tmp_path, lab):
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
    eng = {"db": db, "ev": ev, "probe": probe, "pipe": pipe, "reg": reg, "runner": runner,
           "scope": scope, "lab": lab, "llm": ScriptedLLM(db)}

    def create(profile="safe_active"):
        db.execute(
            "INSERT OR REPLACE INTO engagements(id, name, profile, status, scope_json, budgets_json, "
            "created_at) VALUES('eng','scheduler',?,'draft',?,?,0)",
            (profile, json.dumps({"targets": [{"kind": "url", "value": lab}]}),
             json.dumps(BUDGETS)))
        return Orchestrator(db, ev, probe, pipe, Verifier(db, ev, probe, pipe), reg, runner,
                            eng["llm"])

    eng["create"] = create
    return eng


def _register(env, slug, actions, tools=None, budgets=None):
    charter = specialists.validate_spec(
        {"slug": slug, "expertise": "ColdFusion administrator API and J2EE stack review",
         "actions": actions, "tools": tools or [], "budget": budgets or {}}, BUDGETS)
    return specialists.register(env["db"], "eng", charter, objective="review the CF surface")


def _intent(db, role, status="open", lease=0.0):
    db.execute(
        "INSERT INTO intents(id, engagement_id, role, objective, status, lease_expires, created_at) "
        "VALUES(?,?,?,?,?,?,0)", (f"i_{role}_{status}", "eng", role, f"investigate {role}",
                                  status, lease))
    return f"i_{role}_{status}"


def _degradations(db):
    return [json.loads(r["payload_json"]) for r in db.query(
        "SELECT payload_json FROM events WHERE engagement_id='eng' AND kind='degradation'")]


def test_registered_specialist_is_scheduled_and_executed(env):
    """create -> register -> scheduled -> running -> completed, with the real run."""
    db, lab = env["db"], env["lab"]
    orch = env["create"]()
    # the coordinator mints it (create -> register)
    agent_llm = ScriptedLLM(db)
    agent_llm.steps = [
        {"thought": "probe", "action": "http_request", "args": {"url": f"{lab}/search?q=cf"}},
        {"thought": "mint", "action": "create_specialist", "args": {
            "slug": "cf_config",
            "expertise": "ColdFusion administrator API and J2EE stack configuration review",
            "actions": ["http_request", "read_context"], "tools": []}},
        {"thought": "conclude", "action": "finish", "args": {"summary": "minted"}},
    ]
    ar = AgentRunner(db, env["ev"], env["pipe"], env["probe"], env["reg"], env["runner"],
                     agent_llm, env["scope"], "eng")
    ar.run({"id": "i_parent", "objective": "plan", "role": "web"}, "web")
    spec = specialists.get(db, "eng", "cf_config")
    assert spec["state"] == "registered", spec
    assert spec["charter"]["delegation_limit"] == 0
    assert "create_specialist" not in spec["charter"]["actions"]

    # the scheduler runs it because the INTENT names a registered specialist
    env["llm"].steps = [
        {"thought": "cf admin login", "action": "http_request", "args": {"url": f"{lab}/search?q=1"}},
        {"thought": "mapped", "action": "finish", "args": {"summary": "cf admin mapped"}},
    ]
    iid = _intent(db, "cf_config")
    orch.resume("eng", "agent")

    spec = specialists.get(db, "eng", "cf_config")
    assert spec["state"] == "completed", spec
    states = [h["to"] for h in spec["history"]]
    assert states == ["registered", "scheduled", "running", "completed"], spec["history"]
    assert all({"at", "from", "to", "reason"} <= set(h) for h in spec["history"])
    run = db.one("SELECT * FROM agent_runs WHERE engagement_id='eng' AND role='cf_config'")
    assert run and run["status"] == "completed"
    assert db.one("SELECT COUNT(*) n FROM investigation_steps WHERE agent_run_id=?",
                  (run["id"],))["n"] >= 2
    assert db.one("SELECT status FROM intents WHERE id=?", (iid,))["status"] == "done"


def test_unregistered_role_is_refused_not_run(env):
    db = env["db"]
    orch = env["create"]()
    _intent(db, "ghost_specialist")
    orch.resume("eng", "agent")

    assert db.one("SELECT COUNT(*) n FROM agent_runs WHERE role='ghost_specialist'")["n"] == 0
    degs = _degradations(db)
    assert any(d["code"] == "unknown_specialist" and d["role"] == "ghost_specialist"
               for d in degs), degs


def test_passive_profile_refuses_an_active_capability_specialist(env):
    db = env["db"]
    orch = env["create"]("passive")
    # a charter that can run the active check battery
    _register(env, "active_spec", ["http_request", "run_check"])
    _intent(db, "active_spec")
    orch.resume("eng", "agent")

    assert db.one("SELECT COUNT(*) n FROM agent_runs WHERE role='active_spec'")["n"] == 0
    degs = _degradations(db)
    refused = [d for d in degs if d["code"] == "policy_restriction"
               and d.get("specialist") == "active_spec"]
    assert refused and "run_baseline" in refused[0]["unit"], degs
    assert specialists.get(db, "eng", "active_spec")["state"] == "failed"


def test_cancel_marks_running_specialists_cancelled(env):
    db = env["db"]
    orch = env["create"]()
    _register(env, "cf_config", ["http_request"])
    specialists.transition(db, "eng", "cf_config", "running", "agent run started")

    orch.cancel("eng")

    spec = specialists.get(db, "eng", "cf_config")
    assert spec["state"] == "cancelled", spec
    assert spec["history"][-1]["reason"] == "engagement cancelled"


def test_unrun_specialist_expires_when_the_run_finishes(env):
    db = env["db"]
    orch = env["create"]()
    _register(env, "cf_config", ["http_request"])
    orch.resume("eng", "agent")  # nothing to claim: the run resolves and finishes

    assert specialists.get(db, "eng", "cf_config")["state"] == "expired"
    assert db.one("SELECT COUNT(*) n FROM agent_runs")["n"] == 0


def test_resume_reopens_a_specialist_left_running(env):
    db, lab = env["db"], env["lab"]
    orch = env["create"]()
    _register(env, "cf_config", ["http_request"])
    specialists.transition(db, "eng", "cf_config", "running", "the worker died mid-run")
    iid = _intent(db, "cf_config", status="running", lease=0.0)  # lease expired long ago

    env["llm"].steps = [
        {"thought": "probe", "action": "http_request", "args": {"url": f"{lab}/search?q=2"}},
        {"thought": "done", "action": "finish", "args": {"summary": "resumed and finished"}},
    ]
    orch.resume("eng", "agent")

    spec = specialists.get(db, "eng", "cf_config")
    assert spec["state"] == "completed", spec["history"]
    assert [h["to"] for h in spec["history"]] == [
        "registered", "running", "registered", "scheduled", "running", "completed"]
    assert db.one("SELECT status FROM intents WHERE id=?", (iid,))["status"] == "done"
    assert db.one("SELECT COUNT(*) n FROM agent_runs WHERE role='cf_config'")["n"] == 1


def test_legacy_settings_kv_charter_is_migrated_on_first_read(env):
    db = env["db"]
    env["create"]()  # an engagement row to own it
    charter = specialists.validate_spec(
        {"slug": "legacy_spec", "expertise": "ColdFusion administrator API and J2EE review",
         "actions": ["http_request"]}, BUDGETS)
    db.execute("INSERT INTO settings(key, value_json) VALUES(?,?)",
               ("agent_specialist:eng:legacy_spec", json.dumps(charter)))

    spec = specialists.get(db, "eng", "legacy_spec")

    assert spec and spec["state"] == "registered" and spec["history"][0]["to"] == "registered"
    assert db.one("SELECT COUNT(*) n FROM settings WHERE key=?",
                  ("agent_specialist:eng:legacy_spec",))["n"] == 0


def test_specialist_list_route_is_read_only(tmp_path):
    from fastapi.testclient import TestClient

    from libella.api import App, create_api
    app = App(tmp_path)
    app.db.execute("INSERT INTO engagements(id, name, scope_json, status) "
                   "VALUES('eng','Lab','{\"targets\": []}','draft')")
    app.db.execute("INSERT INTO engagements(id, name, scope_json, status) "
                   "VALUES('empty','Lab','{\"targets\": []}','draft')")
    charter = specialists.validate_spec(
        {"slug": "cf_config", "expertise": "ColdFusion administrator API and J2EE stack review",
         "actions": ["http_request"]}, BUDGETS)
    specialists.register(app.db, "eng", charter)
    client = TestClient(create_api(app), headers={"Authorization": f"Bearer {app.token}"})

    body = client.get("/api/engagements/eng/specialists")
    assert body.status_code == 200, body.text
    rows = body.json()
    assert [r["slug"] for r in rows] == ["cf_config"]
    assert rows[0]["state"] == "registered"
    assert rows[0]["history"][0]["to"] == "registered" and rows[0]["actions"] == [
        "http_request", "finish"]
    assert client.get("/api/engagements/empty/specialists").json() == []
    assert client.get("/api/engagements/nope/specialists").status_code == 404
    # read-only: there is no route that mints a charter
    assert client.post("/api/engagements/eng/specialists", json={"slug": "x"}).status_code == 405


def test_a_specialist_cannot_create_or_delegate_specialists(env):
    db, lab = env["db"], env["lab"]
    _register(env, "cf_config", ["http_request"])
    with pytest.raises(ValueError, match="coordinator"):
        specialists.validate_spec(
            {"slug": "sneaky", "expertise": "a domain long enough to pass the length check",
             "actions": ["http_request", "create_specialist"]}, BUDGETS)
    with pytest.raises(ValueError, match="coordinator"):
        specialists.validate_spec(
            {"slug": "sneaky", "expertise": "a domain long enough to pass the length check",
             "actions": ["http_request", "delegate"]}, BUDGETS)

    # and at runtime the action is not in the charter, so the loop refuses it
    llm = ScriptedLLM(db)
    llm.steps = [
        {"thought": "recruit", "action": "create_specialist", "args": {
            "slug": "child", "expertise": "a domain long enough to pass the length check",
            "actions": ["http_request"]}},
        {"thought": "probe", "action": "http_request", "args": {"url": f"{lab}/search?q=3"}},
        {"thought": "done", "action": "finish", "args": {"summary": "no recursion"}},
    ]
    ar = AgentRunner(db, env["ev"], env["pipe"], env["probe"], env["reg"], env["runner"],
                     llm, env["scope"], "eng")
    res = ar.run({"id": "i_child", "objective": "try to recurse", "role": "cf_config"},
                 "cf_config")
    assert res["status"] == "completed"
    assert specialists.get(db, "eng", "child") is None
    assert db.one("SELECT COUNT(*) n FROM specialists WHERE engagement_id='eng'")["n"] == 1
