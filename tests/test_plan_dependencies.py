"""Regression: verify/report must wait for ALL finding-producing intents.

Bug: verify depended only on web_checks, so with api/graphql/code/container
audits (or infra-only engagements) it ran before findings existed and nothing
was validated; report could render before verification. Found via container
GraphQL engagement (7 findings, 0 validated).
"""
import json
import time

from libella.api import App


def _plan(app, scope, auth):
    eid = "eng_plan"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (eid, "plan test", "safe_active", "draft", json.dumps(scope), json.dumps(auth),
         "{}", time.time()))
    from libella.scope import Scope
    app.orchestrator()._plan_deterministic(eid, Scope(scope),
                                           app.db.one("SELECT * FROM engagements WHERE id=?", (eid,)))
    return {r["role"]: r for r in app.db.query(
        "SELECT * FROM intents WHERE engagement_id=?", (eid,))}


def test_verify_waits_for_graphql_and_report_waits_for_verify(tmp_path):
    app = App(tmp_path)
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:9"}],
             "categories": ["recon", "api"]}
    roles = _plan(app, scope, {"graphql": "http://127.0.0.1:9/graphql"})
    verify_deps = set(json.loads(roles["verify"]["depends_on_json"]))
    assert roles["graphql_audit"]["id"] in verify_deps
    assert json.loads(roles["report"]["depends_on_json"]) == [roles["verify"]["id"]]


def test_verify_waits_for_code_and_container(tmp_path):
    app = App(tmp_path)
    scope = {"targets": [{"kind": "repo", "value": str(tmp_path)},
                         {"kind": "image", "value": "local:tag"}],
             "categories": ["code"]}
    roles = _plan(app, scope, {})
    verify_deps = set(json.loads(roles["verify"]["depends_on_json"]))
    assert roles["code_audit"]["id"] in verify_deps
    assert roles["container_scan"]["id"] in verify_deps
