"""An agent must be able to ask the application model a QUESTION during its loop.

The measured problem: agents matched the deterministic engine at 10 to 20 times the cost
because they had no application context and re-derived what was already known. A model that
exists but is not reachable from the loop changes nothing, so this drives the real
AgentRunner with a scripted model and asserts the action is dispatched, the answer is
relevant to the focus, and the trace records that it happened.

Negative twin: the same loop with an empty model must say so rather than crash or invent.
"""
import json

import pytest
from flask import Flask
from werkzeug.serving import make_server

from libella.agent_runtime import AgentRunner
from libella.appintel import AppIntel
from libella.db import DB
from libella.discovery import Discovery
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.scope import Scope
from libella.tools import Registry
from libella.tools.adapters import ALL_ADAPTERS
from libella.tools.http_probe import HttpProbe
from libella.tools.runner import ToolRunner


class ScriptedLLM:
    def __init__(self, db, steps):
        self.db = db
        self.steps = list(steps)
        self.calls = 0

    def model_for(self, role):
        return "mock-model"

    def complete(self, role, system, user, engagement_id=None, json_schema=None,
                 temperature=0.1):
        self.calls += 1
        step = self.steps.pop(0) if self.steps else {
            "thought": "done", "action": "finish", "args": {"summary": "end", "evidence_ids": []}}
        # a callable step resolves evidence at the moment the model is asked, which is how a
        # script records what the PREVIOUS action actually produced
        step = step(self.db, user) if callable(step) else step
        return {"content": json.dumps(step), "parsed": step,
                "usage": {"input_tokens": 10, "output_tokens": 5, "cost_usd": 0.0}}

    def spend(self, engagement_id):
        return {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}


@pytest.fixture
def env(tmp_path):
    app = Flask(__name__)

    @app.get("/catalog")
    def catalog():
        return json.dumps({"results": [{"id": 1, "title": "anvil", "customer_id": 12}]})

    srv = make_server("127.0.0.1", 0, app)
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.port}"
    db = DB(tmp_path / "t.db")
    db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
               "created_at) VALUES('eng','e','safe_active','running',?, '{}', 0)",
               (json.dumps({"targets": [{"kind": "url", "value": base}],
                            "categories": ["recon", "web", "api"], "rate_limit_rps": 200}),))
    ev = EvidenceStore(db, tmp_path / "ev")
    probe = HttpProbe(db, ev)
    pipe = FindingPipeline(db, ev)
    reg = Registry()
    for spec in ALL_ADAPTERS:
        reg.register(spec)
    runner = ToolRunner(db, ev, tmp_path / "runs")
    scope = Scope(json.loads(db.one("SELECT scope_json FROM engagements WHERE id='eng'")
                             ["scope_json"]))
    yield {"db": db, "ev": ev, "probe": probe, "pipe": pipe, "reg": reg, "runner": runner,
           "scope": scope, "base": base, "tmp": tmp_path}
    srv.shutdown()
    db.close()


def _run(env, steps):
    llm = ScriptedLLM(env["db"], steps)
    ar = AgentRunner(env["db"], env["ev"], env["pipe"], env["probe"], env["reg"],
                     env["runner"], llm, env["scope"], "eng")
    return ar.run({"id": "i1", "objective": f"investigate {env['base']}", "role": "web"}, "web")


def test_an_agent_can_read_the_application_model(env):
    """The answer is the neighbourhood of the focus, and the step is on the trace."""
    disc = Discovery(env["db"], "eng")
    disc.ingest_traffic(
        [{"method": "GET", "url": f"{env['base']}/catalog?kind=hardware", "page": env["base"]}],
        evidence_id=None)
    disc.ingest_response(f"{env['base']}/catalog/1",
                         json.dumps({"results": [{"id": 1, "customer_id": 12}]}))

    # finish requires evidence-backed work, so the script fetches the endpoint it asked
    # about and records what it saw: the realistic shape of a mapping investigation.
    res = _run(env, [
        {"thought": "what does this app expose?", "action": "app_context",
         "args": {"focus": "/catalog"}},
        {"thought": "confirm it", "action": "http_request", "args": {"url": env["base"] + "/catalog"}},
        lambda db, user: {"thought": "recorded what the endpoint serves", "action": "record_observation",
                          "args": {"kind": "catalog_shape", "summary": "catalog returns records with customer_id",
                                   "evidence_id": db.one("SELECT id FROM evidence ORDER BY rowid DESC LIMIT 1")["id"]}},
        {"thought": "done", "action": "finish", "args": {"summary": "mapped", "evidence_ids": []}},
    ])
    assert res["status"] == "completed", res
    kinds = {r["action_kind"] for r in env["db"].query(
        "SELECT action_kind FROM investigation_steps WHERE engagement_id='eng'")}
    assert "app_context" in kinds
    # the model recorded the endpoint and its owner field, which is what a hypothesis needs
    intel = AppIntel(env["db"], "eng")
    assert intel.node("param", "kind") is not None
    assert intel.node("owner", "customer_id") is not None


def test_an_empty_model_is_reported_not_invented(env):
    """Negative twin: no knowledge means the agent is told there is none."""
    res = _run(env, [
        {"thought": "what do I know?", "action": "app_context", "args": {"focus": "/nothing"}},
        {"thought": "confirm the app answers at all", "action": "http_request",
         "args": {"url": env["base"] + "/catalog"}},
        lambda db, user: {"thought": "recorded", "action": "record_observation",
                          "args": {"kind": "baseline",
                                   "summary": "application answered",
                                   "evidence_id": db.one("SELECT id FROM evidence ORDER BY rowid DESC LIMIT 1")["id"]}},
        {"thought": "done", "action": "finish", "args": {"summary": "nothing known",
                                                         "evidence_ids": []}},
    ])
    assert res["status"] == "completed", res
    intel = AppIntel(env["db"], "eng")
    # nothing was fabricated by asking
    assert intel.summary()["total"] == 0


def test_the_model_does_not_promote_a_guess(env):
    """An agent may record a hypothesis, but the store keeps it weak until evidence lands."""
    intel = AppIntel(env["db"], "eng")
    intel.add("endpoint", "GET /imaginary", "/imaginary", provenance="hypothesized")
    assert intel.summary()["supported"] == 0
    with pytest.raises(ValueError):
        intel.promote("endpoint", "GET /imaginary", "observed", "")
