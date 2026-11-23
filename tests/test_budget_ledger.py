"""Engagement spend is enforced by an atomic reservation ledger.

Every check runs against a real SQLite file, the way the engine runs: the point
is that concurrent reservations cannot both see the same headroom.
"""
import json
import threading
import time

import pytest
from flask import Flask

from libella.agent_runtime import AgentRunner
from libella.budget import RESERVATION_TTL_S, BudgetLedger
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.llm import BudgetExceeded, LLM, LLMError
from libella.scope import Scope
from libella.tools import Registry
from libella.tools.adapters import ALL_ADAPTERS
from libella.tools.http_probe import HttpProbe
from libella.tools.runner import ToolRunner
from werkzeug.serving import make_server


def _db(tmp_path) -> DB:
    db = DB(tmp_path / "b.db")
    db.execute(
        "INSERT OR REPLACE INTO engagements(id, name, profile, status, scope_json, budgets_json, "
        "created_at) VALUES('eng','budget','safe_active','draft',?,?,0)",
        (json.dumps({"targets": []}), json.dumps({"max_usd": 1.0})))
    return db


def test_concurrent_reservations_never_pass_the_ceiling(tmp_path):
    db = _db(tmp_path)
    ledger = BudgetLedger(db)
    results, barrier = [], threading.Barrier(8)

    def worker():
        barrier.wait()  # all eight see the same empty ledger, then race
        results.append(ledger.reserve("eng", "run_x", 0.3, 1.0))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    granted = [r for r in results if r]
    assert len(granted) == 3, granted  # 3 x 0.3 fits under 1.0; a fourth does not
    assert ledger.committed("eng") <= 1.0
    for rid in granted:
        ledger.settle(rid, 0.3)
    assert ledger.committed("eng") == pytest.approx(0.9)
    assert ledger.totals("eng")["by_state"]["settled"]["count"] == 3


def test_a_crashed_reservation_is_expired_and_released(tmp_path):
    db = _db(tmp_path)
    ledger = BudgetLedger(db)
    stale = ledger.reserve("eng", "run_dead", 0.9, 1.0)
    assert ledger.reserve("eng", "run_live", 0.9, 1.0) is None  # fully committed
    # the worker that took it died: age the row past the TTL
    db.execute("UPDATE budget_ledger SET created_at=? WHERE id=?",
               (time.time() - RESERVATION_TTL_S - 1, stale))

    rid = ledger.reserve("eng", "run_live", 0.9, 1.0)
    assert rid is not None, "an abandoned reservation must not hold budget hostage"
    assert db.one("SELECT state FROM budget_ledger WHERE id=?", (stale,))["state"] == "released"
    events = [json.loads(r["payload_json"]) for r in db.query(
        "SELECT payload_json FROM events WHERE engagement_id='eng' "
        "AND kind='budget_reservation_expired'")]
    assert events and events[0]["count"] == 1


def test_provider_error_releases_the_reservation(tmp_path):
    db = _db(tmp_path)
    server = make_server("127.0.0.1", 0, Flask("boom"), threaded=True)
    # a Flask app with no routes answers 404: a provider-side failure, not a usage bill
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        llm = LLM(db, {"base_url": f"http://127.0.0.1:{server.server_port}/v1",
                       "default_model": "gpt-4o-mini"})
        with pytest.raises(LLMError) as err:
            llm.complete("web", "system prompt", "user prompt", "eng")
        assert not isinstance(err.value, BudgetExceeded)
    finally:
        server.shutdown()
    rows = db.query("SELECT state, amount_usd FROM budget_ledger WHERE engagement_id='eng'")
    assert [(r["state"], r["amount_usd"]) for r in rows] == [("released", 0.0)]
    assert BudgetLedger(db).committed("eng") == 0.0


def test_agent_run_stopped_by_reservation_refusal_is_budget_exhausted(tmp_path):
    db = _db(tmp_path)
    db.execute("UPDATE engagements SET budgets_json=? WHERE id='eng'",
               (json.dumps({"max_usd": 1.0}),))
    # another agent already committed the engagement's whole ceiling
    db.execute("INSERT INTO budget_ledger(id, engagement_id, run_id, kind, amount_usd, state, "
               "created_at) VALUES('bud_seed','eng','run_other','reservation',1.0,'settled',?)",
               (time.time(),))
    lab = Flask("budget-lab")
    lab.add_url_rule("/", view_func=lambda: "<html>ok</html>")
    srv = make_server("127.0.0.1", 0, lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        ev = EvidenceStore(db, tmp_path / "ev")
        reg = Registry()
        for s in ALL_ADAPTERS:
            reg.register(s)
        # nothing listens on the provider port: any attempted call would be model_failed
        llm = LLM(db, {"base_url": "http://127.0.0.1:1/v1", "default_model": "gpt-4o-mini"})
        runner = ToolRunner(db, ev, tmp_path / "runs")
        scope = Scope({"targets": [{"kind": "url", "value": base}],
                       "categories": ["recon", "web"], "rate_limit_rps": 1000})
        ar = AgentRunner(db, ev, FindingPipeline(db, ev), HttpProbe(db, ev), reg, runner,
                         llm, scope, "eng")
        res = ar.run({"id": "i1", "objective": "investigate", "role": "web"}, "web")
    finally:
        srv.shutdown()

    assert res["status"] == "budget_exhausted", res
    assert res["exit_reason"] == "budget_exhausted"
    assert "budget" in res["summary"].lower()
    assert res["status"] != "completed" and res["findings"] == []
    assert res["iterations"] == 1  # the first turn was refused before any call was made
    assert db.one("SELECT COUNT(*) n FROM agent_runs WHERE status='completed'")["n"] == 0
    assert db.one("SELECT COALESCE(SUM(cost_usd),0) c FROM llm_usage")["c"] == 0
    assert db.one("SELECT COUNT(*) n FROM exchanges")["n"] == 0
