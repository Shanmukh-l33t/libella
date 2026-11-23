"""Resuming an engagement continues its own plan instead of cloning it.

The real resume path (`App._run_guarded` -> `Orchestrator.start`) always re-planned, so
every restart inserted a second recon/crawl/sweep/report set. Two consequences, both
silent: the same target was tested twice at the operator's expense, and the
duplicate-work guard could not catch it because that guard only compares against intents
already marked `done`, so a clone of a still-open intent reads as new work.

A `Run again` on a COMPLETED engagement must still plan a fresh plan, which is the
negative control below.
"""
import json
import threading

import pytest
from flask import Flask
from werkzeug.serving import make_server

from libella.api import App
from libella.orchestrator import Orchestrator
from libella.scope import Scope


@pytest.fixture
def lab():
    app = Flask("libella-resume-plan")

    @app.get("/")
    def index():
        return "<html><body>resume fixture</body></html>"

    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _app(tmp_path, lab, status="draft"):
    data = App(tmp_path / "data")
    spec = {"targets": [{"kind": "url", "value": lab}],
            "categories": ["recon", "web"], "rate_limit_rps": 1000}
    data.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, budgets_json, created_at) "
        "VALUES('eng','resume','safe_active',?,?,?,0)",
        (status, json.dumps(spec), json.dumps({"max_duration_s": 60})))
    return data, Scope(spec)


def _orch(data):
    return Orchestrator(data.db, data.evidence, data.probe, data.pipeline,
                        data.verifier, data.registry, data.runner, None)


def _roles(data):
    return [r["role"] for r in data.db.query(
        "SELECT role FROM intents WHERE engagement_id='eng' ORDER BY created_at")]


def test_fresh_engagement_is_planned_once(tmp_path, lab):
    data, scope = _app(tmp_path, lab)
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    _orch(data)._plan_deterministic("eng", scope, eng)

    roles = _roles(data)
    assert roles.count("crawl") == 1 and roles.count("web_checks") == 1
    assert roles.count("recon") == 1


def test_resume_does_not_clone_the_plan(tmp_path, lab):
    data, scope = _app(tmp_path, lab)
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    orch = _orch(data)
    orch._plan_deterministic("eng", scope, eng)
    first = _roles(data)
    assert "recon" in first

    # the state a killed worker leaves: one intent done, the rest still open/running
    data.db.execute("UPDATE intents SET status='done' WHERE role='recon'")
    data.db.execute("UPDATE intents SET status='running', claim_token='deadworker' "
                    "WHERE role='crawl'")

    _orch(data)._reopen_unfinished("eng")  # start() returns True here: resume, no replan
    assert _roles(data) == first, "the resumed run planned a second set of intents"
    # the interrupted intent is re-opened so resume redoes it, not recorded as in flight
    crawl = data.db.one("SELECT status, claim_token FROM intents "
                        "WHERE engagement_id='eng' AND role='crawl'")
    assert crawl["status"] == "open" and crawl["claim_token"] is None
    assert data.db.query("SELECT seq FROM events WHERE engagement_id='eng' "
                         "AND kind='plan_resumed'")


def test_run_again_on_a_completed_engagement_plans_fresh_work(tmp_path, lab):
    """Negative control: a completed engagement has no open intents, so it replans."""
    data, scope = _app(tmp_path, lab, status="done")
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    _orch(data)._plan_deterministic("eng", scope, eng)
    first = _roles(data)
    assert first
    data.db.execute("UPDATE intents SET status='done'")  # everything finished

    # start()'s gate: nothing unfinished, so a Run again plans fresh work
    assert _orch(data)._reopen_unfinished("eng") is False
    _orch(data)._plan_deterministic("eng", scope, eng)

    assert len(_roles(data)) == 2 * len(first)
    assert not data.db.query("SELECT seq FROM events WHERE engagement_id='eng' "
                             "AND kind='plan_resumed'")


def _first(data, role):
    return data.db.one("SELECT * FROM intents WHERE engagement_id='eng' AND role=? "
                       "ORDER BY created_at", (role,))


@pytest.mark.parametrize("crash_role,crash_status", [
    ("recon", "running"),        # crashed during fingerprinting
    ("crawl", "running"),        # crashed during crawling
    ("web_checks", "running"),   # crashed mid-sweep
    ("verify", "open"),          # crashed before verification
    ("report", "open"),          # crashed while rendering: nothing left open but the report
])
def test_resume_at_every_stage_reuses_the_existing_plan(tmp_path, lab, crash_role, crash_status):
    """A crash at any stage must resume its own plan: the interrupted work is redone, the
    plan itself is never cloned, and completed work is not repeated."""
    data, scope = _app(tmp_path, lab)
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    _orch(data)._plan_deterministic("eng", scope, eng)
    planned = _roles(data)

    # everything before the crash point is finished, the crash point is in flight
    order = [r["role"] for r in data.db.query(
        "SELECT role FROM intents WHERE engagement_id='eng' ORDER BY created_at")]
    for role in order[:order.index(crash_role)]:
        data.db.execute("UPDATE intents SET status='done' WHERE role=?", (role,))
    data.db.execute("UPDATE intents SET status=? WHERE role=?", (crash_status, crash_role))
    if crash_status == "running":  # only an in-flight claim carries a token
        data.db.execute("UPDATE intents SET claim_token='dead' WHERE role=?", (crash_role,))

    assert _orch(data)._reopen_unfinished("eng") is True
    assert _roles(data) == planned, "the resumed run cloned the plan"
    assert _first(data, crash_role)["status"] == "open"
    assert _first(data, crash_role)["claim_token"] is None


def test_repeated_resumes_are_idempotent(tmp_path, lab):
    data, scope = _app(tmp_path, lab)
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    _orch(data)._plan_deterministic("eng", scope, eng)
    planned = _roles(data)
    data.db.execute("UPDATE intents SET status='running', claim_token='dead' WHERE role='crawl'")

    for _ in range(3):  # a worker that keeps dying and being restarted
        assert _orch(data)._reopen_unfinished("eng") is True
        assert _roles(data) == planned
        data.db.execute("UPDATE intents SET status='running', claim_token='dead' "
                        "WHERE role='crawl'")  # died again

    assert len(data.db.query("SELECT seq FROM events WHERE engagement_id='eng' "
                             "AND kind='plan_resumed'")) == 3  # one per resume, no clones


def test_completed_work_is_never_reopened(tmp_path, lab):
    """Work that must not be repeated stays done; only the interrupted intent is reopened."""
    data, scope = _app(tmp_path, lab)
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    _orch(data)._plan_deterministic("eng", scope, eng)
    data.db.execute("UPDATE intents SET status='done' WHERE role='crawl'")
    data.db.execute("UPDATE intents SET status='running', claim_token='dead' "
                    "WHERE role='web_checks'")

    _orch(data)._reopen_unfinished("eng")

    assert _first(data, "crawl")["status"] == "done"
    assert _first(data, "web_checks")["status"] == "open"
