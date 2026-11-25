"""H1/M6: the engagement profile must gate work, not describe it.

A passive engagement has to run read-only observation only, and every skipped
unit must surface as a degradation the report shows. Default (safe_active) keeps
the exact pipeline benchmarks rely on. Budgets are validated at creation so a
string cannot crash the worker thread.
"""
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient
from flask import Flask, request
from werkzeug.serving import make_server

from libella.api import App, create_api
from libella.policy import permits
from libella.scope import Scope


@pytest.fixture
def lab():
    app = Flask("profile-lab")

    @app.get("/")
    def index():
        return "<html><body>home</body></html>"

    @app.get("/search")
    def search():
        return f"<html><body>Results: {request.args.get('q', '')}</body></html>"

    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def app(tmp_path):
    return App(tmp_path / "data")


@pytest.fixture
def client(app):
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    return c


def _scope(lab):
    return {"targets": [{"kind": "url", "value": lab}], "categories": ["recon", "web"],
            "rate_limit_rps": 1000}


def _eng(app, lab, profile="safe_active", extra=()):
    eid = f"eng_{time.time_ns()}"
    scope = _scope(lab)
    scope["targets"] += [{"kind": "url", "value": t} for t in extra]
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
        "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, "profile test", profile, "draft", json.dumps(scope), "{}", "{}", time.time()))
    return eid


def _row(app, eid):
    return app.db.one("SELECT * FROM engagements WHERE id=?", (eid,))


def _degradations(app, eid):
    return [json.loads(r["payload_json"]) for r in app.db.query(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind='degradation'", (eid,))]


def _plan(app, eid):
    eng = _row(app, eid)
    app.orchestrator()._plan_deterministic(eid, Scope(json.loads(eng["scope_json"])), eng)
    return {r["role"] for r in app.db.query(
        "SELECT role FROM intents WHERE engagement_id=?", (eid,))}


# ---- the table itself ----

def test_policy_table_is_fail_closed():
    assert permits("crawl", "passive")
    assert not permits("file_upload", "passive")
    assert permits("file_upload", "safe_active")
    assert permits("nuclei", "advanced_validation")
    # an unlisted unit is never permitted, and an unknown profile ranks strictest
    assert not permits("some_future_check", "advanced_validation")
    assert not permits("file_upload", "yolo")


# ---- planning ----

def test_passive_plan_skips_active_work_and_records_the_skips(app, lab):
    eid = _eng(app, lab, "passive", extra=("https://127.0.0.1:9",))
    roles = _plan(app, eid)
    assert {"recon", "crawl", "web_checks", "verify", "report"} <= roles
    assert "nuclei_scan" not in roles and "infra_scan" not in roles
    degs = _degradations(app, eid)
    assert degs and {d["code"] for d in degs} == {"policy_restriction"}
    assert {d["unit"] for d in degs} >= {"nuclei_scan", "infra_scan"}
    assert any("policy restriction" in d["detail"] for d in degs)


def test_safe_active_plan_keeps_the_existing_pipeline(app, lab):
    eid = _eng(app, lab, "safe_active", extra=("https://127.0.0.1:9",))
    roles = _plan(app, eid)
    assert {"recon", "crawl", "web_checks", "nuclei_scan", "infra_scan",
            "verify", "report"} <= roles
    assert _degradations(app, eid) == []


def test_advanced_validation_plan_is_not_narrower_than_default(app, lab):
    eid = _eng(app, lab, "advanced_validation", extra=("https://127.0.0.1:9",))
    roles = _plan(app, eid)
    assert {"web_checks", "nuclei_scan", "infra_scan"} <= roles
    assert _degradations(app, eid) == []


# ---- execution (defense in depth) ----

def test_passive_execution_refuses_an_active_intent(app, lab):
    eid = _eng(app, lab, "passive")
    app.db.execute(
        "INSERT INTO intents(id, engagement_id, role, objective, status, created_at) "
        "VALUES('i_forced', ?, 'nuclei_scan', ?, 'running', ?)",
        (eid, f"Template scan {lab}", time.time()))
    eng = _row(app, eid)
    intent = app.db.one("SELECT * FROM intents WHERE id='i_forced'")
    status, result = app.orchestrator()._execute(
        eid, Scope(json.loads(eng["scope_json"])), eng, intent)
    assert status == "exhausted" and result["skipped"] == "policy_restriction"
    assert app.db.one("SELECT COUNT(*) n FROM tool_calls WHERE engagement_id=?", (eid,))["n"] == 0
    assert any(d["code"] == "policy_restriction" for d in _degradations(app, eid))


def test_passive_web_checks_keep_read_only_checks_only(app, lab):
    eid = _eng(app, lab, "passive")
    eng = _row(app, eid)
    app.orchestrator()._do_web_checks(
        eid, Scope(json.loads(eng["scope_json"])), eng, f"Web security checks on {lab}",
        "i_checks")
    titles = [f["title"] for f in app.pipeline.list(eid)]
    assert any("Missing security headers" in t for t in titles), titles
    assert not any("Reflected XSS" in t for t in titles), titles
    skipped = json.dumps(_degradations(app, eid))
    assert "reflected_xss" in skipped and "policy restriction" in skipped


def test_safe_active_web_checks_still_detect_injection(app, lab):
    eid = _eng(app, lab, "safe_active")
    eng = _row(app, eid)
    app.orchestrator()._do_web_checks(
        eid, Scope(json.loads(eng["scope_json"])), eng, f"Web security checks on {lab}",
        "i_checks")
    titles = [f["title"] for f in app.pipeline.list(eid)]
    assert any("Reflected XSS" in t for t in titles), titles


# ---- API boundary ----

def test_unknown_profile_is_rejected_at_creation(client, lab):
    r = client.post("/api/engagements", json={"name": "x", "scope": _scope(lab),
                                              "profile": "yolo"})
    assert r.status_code == 400 and "profile" in r.json()["detail"]


def test_unknown_mode_and_providerless_agent_mode_are_rejected(client, lab):
    eid = client.post("/api/engagements",
                      json={"name": "x", "scope": _scope(lab)}).json()["id"]
    assert client.post(f"/api/engagements/{eid}/start",
                       json={"mode": "turbo"}).status_code == 400
    r = client.post(f"/api/engagements/{eid}/start", json={"mode": "agent"})
    assert r.status_code == 400 and "provider" in r.json()["detail"]
    r = client.post(f"/api/engagements/{eid}/start", json={"mode": "llm"})
    assert r.status_code == 400 and "provider" in r.json()["detail"]


def test_string_or_nonpositive_budget_is_rejected_at_creation(client, lab):
    for budgets in ({"max_duration_s": "60"}, {"max_usd": -1}, {"max_duration_s": 0}):
        r = client.post("/api/engagements",
                        json={"name": "x", "scope": _scope(lab), "budgets": budgets})
        assert r.status_code == 400, (budgets, r.text)
    ok = client.post("/api/engagements",
                     json={"name": "x", "scope": _scope(lab),
                           "budgets": {"max_duration_s": 60, "max_usd": 2.5}})
    assert ok.status_code == 200, ok.text
