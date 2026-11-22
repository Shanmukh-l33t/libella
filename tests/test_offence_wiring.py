"""The offensive audits are wired into a real run, not just importable.

A module that no intent reaches is not a capability. These tests drive the
deterministic planner and the executor of the real orchestrator: an engagement
that declares what an audit needs gets the intent, one that does not gets none,
and executing the intent reaches the audit (proven by a monkeypatched call that
records its arguments, so the assertion is about dispatch, while each audit's own
tests prove its behaviour).
"""
import json
import time

import pytest

from libella.api import App
from libella.scope import Scope

BASE = "http://127.0.0.1:1"


def _app(tmp_path, auth):
    app = App(tmp_path / "data")
    scope = {"targets": [{"kind": "url", "value": BASE}],
             "categories": ["recon", "web", "api"], "rate_limit_rps": 5}
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng", "offence", "safe_active", "draft", json.dumps(scope), json.dumps(auth), "{}",
         time.time()))
    return app


def _roles(app):
    return {r["role"] for r in app.db.query("SELECT role FROM intents WHERE engagement_id='eng'")}


IDENTITIES = [{"username": "alice", "password": "p", "login_url": BASE + "/login"},
              {"username": "bob", "password": "p", "login_url": BASE + "/login"}]


def test_planner_creates_each_audit_only_for_a_declared_target(tmp_path):
    app = _app(tmp_path, {"identities": IDENTITIES,
                          "test_hints": {"jwt": {"token": "x", "url": BASE + "/api/me"}},
                          "oauth": {"authorize_url": BASE + "/authorize", "client_id": "c"},
                          "session": {"login_url": BASE + "/login", "username_field": "u",
                                      "password_field": "p", "username": "alice",
                                      "password": "p"}})
    orch = app.orchestrator()
    eng = app.db.one("SELECT * FROM engagements WHERE id='eng'")
    orch._plan_deterministic("eng", Scope(json.loads(eng["scope_json"])), eng)
    roles = _roles(app)
    assert {"jwt_audit", "oauth_audit", "session_audit", "privesc_audit"} <= roles


def test_nothing_is_planned_without_the_configuration_it_needs(tmp_path):
    app = _app(tmp_path, {"identities": [IDENTITIES[0]]})  # one identity, no hints
    orch = app.orchestrator()
    eng = app.db.one("SELECT * FROM engagements WHERE id='eng'")
    orch._plan_deterministic("eng", Scope(json.loads(eng["scope_json"])), eng)
    assert not ({"jwt_audit", "oauth_audit", "session_audit", "privesc_audit"} & _roles(app))


@pytest.mark.parametrize("role,module,func", [
    ("jwt_audit", "jwt_audit", "audit_jwt"),
    ("oauth_audit", "oauth_audit", "audit_oauth"),
    ("session_audit", "session_audit", "audit_session"),
    ("privesc_audit", "privesc_audit", "audit_role_matrix"),
])
def test_executor_dispatches_each_audit_with_the_engagement_context(tmp_path, monkeypatch,
                                                                   role, module, func):
    app = _app(tmp_path, {"identities": IDENTITIES,
                          "session": {"login_url": BASE + "/login"},
                          "test_hints": {"jwt": {"token": "x", "url": BASE + "/api/me"}},
                          "oauth": {"authorize_url": BASE + "/authorize"}})
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return {"candidates": []}

    monkeypatch.setattr(f"libella.{module}.{func}", fake)
    orch = app.orchestrator()
    iid = orch._add_intent("eng", role, f"{role} run")
    eng = app.db.one("SELECT * FROM engagements WHERE id='eng'")
    status, _ = orch._execute("eng", Scope(json.loads(eng["scope_json"])), eng,
                              app.db.one("SELECT * FROM intents WHERE id=?", (iid,)))
    assert calls, f"{role} intent did not reach {module}.{func}"
    assert status != "exhausted", status
    assert "eng" in calls[0]  # the engagement id travels with the call


def test_an_audit_role_is_policy_gated(tmp_path):
    from libella.policy import permits
    for role in ("jwt_audit", "oauth_audit", "session_audit", "privesc_audit"):
        assert permits(role, "safe_active"), role
        assert not permits(role, "passive"), role
