"""Audit-2: the auth-aware baseline must use the platform's scoped HTTP path.

`run_baseline` used a private `httpx.Client` to log in and harvest cookies. That
request bypassed the rate limiter, the per-hop scope check, the post-connect
peer verification and the evidence capture every other request gets — while
posting credentials. A malformed test hint could also raise out of the action
and kill the run.
"""
import json
import threading
import time

import pytest
from flask import Flask, make_response, request

from libella.agent_runtime import AgentRunner
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.scope import Scope
from libella.tools import Registry
from libella.tools.adapters import ALL_ADAPTERS
from libella.tools.http_probe import HttpProbe
from libella.tools.runner import ToolRunner
from werkzeug.serving import make_server


class ScriptedLLM:
    def __init__(self, steps):
        self.steps = list(steps)

    def model_for(self, role):
        return "mock-model"

    def complete(self, role, system, user, engagement_id=None, json_schema=None, temperature=0.1):
        step = self.steps.pop(0) if self.steps else {"action": "finish", "args": {}}
        return {"content": json.dumps(step), "parsed": step,
                "usage": {"input_tokens": 1, "output_tokens": 1, "cost_usd": 0.0,
                          "model": "mock-model"}}


@pytest.fixture
def lab():
    app = Flask("audit2-baseline")

    @app.post("/login")
    def login():
        r = make_response('{"authenticated": false}')
        r.set_cookie("session", "abc123", httponly=True)
        return r

    @app.get("/")
    def home():
        return "home"

    @app.get("/<path:any>")
    def missing(any):
        return "missing", 404

    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _run(tmp_path, lab, auth_json, steps):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": lab}], "categories": ["web", "api"],
                   "rate_limit_rps": 1000})
    db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
               "created_at) VALUES('eng','baseline','safe_active','draft',?,?,0)",
               (json.dumps({"targets": [{"kind": "url", "value": lab}]}), json.dumps(auth_json)))
    ar = AgentRunner(db, ev, FindingPipeline(db, ev), HttpProbe(db, ev), _registry(),
                     ToolRunner(db, ev, tmp_path / "runs"), ScriptedLLM(steps), scope, "eng")
    return db, ar.run({"id": "i1", "objective": "baseline", "role": "web"}, "web")


def _registry():
    reg = Registry()
    for s in ALL_ADAPTERS:
        reg.register(s)
    return reg


IDENT = {"identities": [{"username": "alice", "password": "pw-alice-1", "login_url": ""}]}


def test_baseline_login_is_captured_as_evidence(tmp_path, lab):
    auth = json.loads(json.dumps(IDENT))
    auth["identities"][0]["login_url"] = lab + "/login"
    db, res = _run(tmp_path, lab, auth, [{"action": "run_baseline", "args": {"url": lab}},
                                         {"action": "finish", "args": {"summary": "done"}}])
    assert res["status"] in ("completed", "budget_exhausted"), res
    rows = db.query("SELECT tool, url FROM exchanges WHERE tool='baseline_login'")
    assert rows and rows[0]["url"] == lab + "/login", "the credentialed login left no evidence"
    ev_id = db.one("SELECT evidence_id FROM exchanges WHERE tool='baseline_login' LIMIT 1")
    assert ev_id["evidence_id"]


def test_malformed_test_hint_degrades_instead_of_killing_the_run(tmp_path, lab):
    auth = {"test_hints": {"ssrf": {"url": lab + "/go"}},  # missing param/internal_url
            "identities": [{"login_url": lab + "/login"}]}  # no username
    db, res = _run(tmp_path, lab, auth, [{"action": "run_baseline", "args": {"url": lab}},
                                         {"action": "finish", "args": {"summary": "done"}}])
    assert res["run_id"], res
    assert db.one("SELECT COUNT(*) n FROM investigation_steps WHERE action_kind='tool_call' ")[
        "n"] >= 1