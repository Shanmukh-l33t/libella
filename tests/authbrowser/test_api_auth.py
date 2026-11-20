"""Auth-context / workflow API routes end to end: real FastAPI app, real sessions."""
import json

import pytest
from fastapi.testclient import TestClient

from libella.api import App, create_api
from libella.browser_crawl import browser_available

pytestmark = pytest.mark.skipif(not browser_available(), reason="playwright/chromium not installed")


@pytest.fixture
def client(tmp_path):
    app = App(tmp_path)
    return app, TestClient(create_api(app), headers={"Authorization": f"Bearer {app.token}"})


def _engagement(client, base):
    r = client.post("/api/engagements", json={
        "name": "authlab", "scope": {"targets": [{"kind": "url", "value": base}],
                                     "categories": ["web", "api"]}})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _login_body(base, identities, login_kwargs):
    return {"name": "alice", "base_url": base, "login_url": base + "/login",
            "username": "alice", "password": identities[0]["password"],
            "selectors": login_kwargs["selectors"],
            "success_assertion": login_kwargs["success_assertion"]}


def test_api_requires_token(client):
    _, c = client
    assert c.get("/api/tools", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_auth_context_and_workflow_routes(client, labs, identities, login_kwargs):
    app, c = client
    base = labs["vuln"]
    eid = _engagement(c, base)

    r = c.post(f"/api/engagements/{eid}/auth-contexts", json=_login_body(
        base, identities, login_kwargs))
    assert r.status_code == 200, r.text
    created = r.json()
    assert created["status"] == "active" and created["cookie_count"] >= 1
    assert "cookies" not in json.dumps(created)  # cookie values never leave the server

    # a failed login is stored, not silently dropped
    r = c.post(f"/api/engagements/{eid}/auth-contexts",
               json={**_login_body(base, identities, login_kwargs),
                     "name": "alice-wrong-pw", "password": "SI_SECRET_PASSWORD_WRONG01"})
    assert r.status_code == 200 and r.json()["status"] == "failed"
    assert len(c.get(f"/api/engagements/{eid}/auth-contexts").json()) == 2

    assert c.post(f"/api/auth-contexts/{created['id']}/verify").json()["status"] == "active"

    steps = [{"action": "navigate", "value": base + "/dashboard"},
             {"action": "assert", "selector": "#dashboard"},
             {"action": "extract", "selector": "#dashboard"}]
    r = c.post(f"/api/engagements/{eid}/workflows",
               json={"name": "dashboard", "auth_context_id": created["id"], "steps": steps})
    assert r.status_code == 200, r.text
    wid = r.json()["id"]
    run = c.post(f"/api/workflows/{wid}/run").json()
    assert run["ok"] is True, run["steps"]
    assert run["workflow"]["status"] == "passed"
    assert run["network"] and run["evidence_id"].startswith("ev_")
    assert app.db.one("SELECT status FROM workflows WHERE id=?", (wid,))["status"] == "passed"
    assert app.db.one("SELECT kind FROM evidence WHERE id=?", (run["evidence_id"],))["kind"] == \
        "auth_workflow"


def test_workflow_validation(client, labs):
    _, c = client
    base = labs["vuln"]
    eid = _engagement(c, base)
    assert c.post(f"/api/engagements/{eid}/workflows",
                  json={"steps": []}).status_code == 400
    assert c.post(f"/api/engagements/{eid}/workflows",
                  json={"steps": [{"action": "rm -rf"}]}).status_code == 400
    assert c.post(f"/api/engagements/{eid}/workflows",
                  json={"auth_context_id": "ac_missing",
                        "steps": [{"action": "assert", "selector": "h1"}]}).status_code == 404
    assert c.post("/api/workflows/wf_missing/run").status_code == 404
