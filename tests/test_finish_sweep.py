"""A terminal engagement carries no dead worker's bookkeeping.

Measured on a real agent-mode run that was SIGKILLed mid-investigation and then resumed:
the engagement reached 'done', yet one agent run was still 'running' and one budget
reservation was still 'reserved'. Both are lies about a finished assessment: the run reads
as in flight, and the leaked reservation keeps counting against max_usd.

`budget.py` releases stale reservations only when the NEXT reservation is taken, so an
engagement that never runs again keeps the leak forever. `_finish` now closes both.
"""
import json
import time

import pytest

from libella.api import App
from libella.scope import Scope


@pytest.fixture
def app(tmp_path):
    a = App(tmp_path / "data")
    spec = {"targets": [{"kind": "url", "value": "http://127.0.0.1:1"}],
            "categories": ["recon", "web"]}
    a.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, budgets_json, created_at) "
        "VALUES('eng','finish','safe_active','running',?,'{}',?)",
        (json.dumps(spec), time.time()))
    a.scope = Scope(spec)
    return a


def _leak(a):
    a.db.execute(
        "INSERT INTO agent_runs(id, engagement_id, role, status, started_at) "
        "VALUES('run_dead','eng','web','running',?)", (time.time(),))
    a.db.execute(
        "INSERT INTO budget_ledger(id, engagement_id, run_id, kind, amount_usd, state, "
        "created_at) VALUES('bud_dead','eng','run_dead','reservation',0.005, 'reserved', ?)",
        (time.time(),))


def _orch(a):
    return a.orchestrator()


def test_finish_releases_a_dead_workers_agent_run_and_reservation(app):
    _leak(app)
    _orch(app)._finish("eng", "done", "all intents resolved")

    run = app.db.one("SELECT status, finished_at FROM agent_runs WHERE id='run_dead'")
    assert run["status"] == "interrupted" and run["finished_at"] is not None
    led = app.db.one("SELECT state FROM budget_ledger WHERE id='bud_dead'")
    assert led["state"] == "released"


def test_the_release_is_reported_rather_than_silent(app):
    _leak(app)
    _orch(app)._finish("eng", "done", "all intents resolved")

    ev = app.db.query("SELECT payload_json FROM events WHERE engagement_id='eng' "
                      "AND kind='worker_state_released'")
    assert ev, "leaked worker state was cleaned without saying so"
    payload = json.loads(ev[0]["payload_json"])
    assert payload["reservations_released"] == 1
    assert payload["agent_runs_interrupted"] == 1


def test_a_clean_termination_emits_nothing(app):
    """Negative control: no leak, no event, no rewriting of healthy rows."""
    app.db.execute(
        "INSERT INTO agent_runs(id, engagement_id, role, status, started_at, finished_at) "
        "VALUES('run_ok','eng','web','completed',?,?)", (time.time(), time.time()))
    _orch(app)._finish("eng", "done", "all intents resolved")

    assert not app.db.query("SELECT seq FROM events WHERE engagement_id='eng' "
                            "AND kind='worker_state_released'")
    assert app.db.one("SELECT status FROM agent_runs WHERE id='run_ok'")["status"] == "completed"


def test_settled_spend_is_never_released_again(app):
    """Only 'reserved' rows are touched: settled spend must survive termination intact."""
    app.db.execute(
        "INSERT INTO budget_ledger(id, engagement_id, run_id, kind, amount_usd, state, "
        "created_at, settled_at) VALUES('bud_ok','eng','run_ok','reservation',0.25,'settled',?,?)",
        (time.time(), time.time()))
    _orch(app)._finish("eng", "done", "all intents resolved")

    row = app.db.one("SELECT state, amount_usd FROM budget_ledger WHERE id='bud_ok'")
    assert row["state"] == "settled" and row["amount_usd"] == 0.25


def test_a_failed_termination_also_sweeps(app):
    """Leaks must be closed whatever the terminal status, not only on the happy path."""
    _leak(app)
    _orch(app)._finish("eng", "failed", "provider outage")

    assert app.db.one("SELECT status FROM agent_runs WHERE id='run_dead'")["status"] == "interrupted"
    assert app.db.one("SELECT state FROM budget_ledger WHERE id='bud_dead'")["state"] == "released"
