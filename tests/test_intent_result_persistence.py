"""Durable intent state: what must survive, and what must fail loudly instead of vanishing.

`result_json` is the only carrier between a producer intent and the consumers that read it
later: `web_checks` reads the crawl's endpoint inventory, and a resumed run re-reads it
after a worker restart. `_execute` returned a hardcoded `{}` for every handler, so each
producer's result was dropped at the dispatch boundary and `_complete` then persisted that
`{}` under the lease fence. Every engagement therefore swept zero endpoints and recorded a
completed-looking run whose parameter checks never ran.

Three properties are pinned here:
  * a producer's result survives completion and is unchanged by restoration
  * a restarted worker rebuilds it from SQLite alone
  * missing / corrupt / legacy-empty state is a reported gap, never an empty sweep

The last point is the reason these tests exist: an absent inventory that reads as `[]` is
indistinguishable from a clean one, which is the false-clean class this platform must not
produce.
"""
import json
import threading

import pytest
from flask import Flask, request
from werkzeug.serving import make_server

from libella import coverage
from libella.api import App
from libella.checks import WebChecks
from libella.orchestrator import Orchestrator
from libella.scope import Scope


@pytest.fixture
def lab():
    app = Flask("libella-durable-state")

    @app.get("/")
    def index():
        return '<html><body><a href="/catalog?sku=widget">catalog</a></body></html>'

    @app.get("/catalog")
    def catalog():
        return f"<html><body>Item {request.args.get('sku', '')}</body></html>"

    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _app(tmp_path, lab):
    data = App(tmp_path / "data")
    spec = {"targets": [{"kind": "url", "value": lab}],
            "categories": ["recon", "web"], "rate_limit_rps": 1000}
    data.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, budgets_json, created_at) "
        "VALUES('eng','durable','safe_active','draft',?,?,0)",
        (json.dumps(spec), json.dumps({"max_duration_s": 60})))
    return data, Scope(spec)


def _orch(data):
    return Orchestrator(data.db, data.evidence, data.probe, data.pipeline,
                        data.verifier, data.registry, data.runner, None)


def _intent(data, iid, role, objective, result=None):
    data.db.execute(
        "INSERT INTO intents(id, engagement_id, role, objective, status, claim_token, "
        "result_json, created_at) VALUES(?,?,?,?,?,?,?,0)",
        (iid, "eng", role, objective, "running", "tok", result))
    return data.db.one("SELECT * FROM intents WHERE id=?", (iid,))


def _codes(data):
    return [json.loads(r["payload_json"]).get("code")
            for r in data.db.query("SELECT payload_json FROM events "
                                   "WHERE engagement_id='eng' AND kind='degradation'")]


def _web_checks_state(data):
    """The ledger's own verdict for the unit that consumed the crawl state."""
    slots = coverage._unit_slots(data.db, "eng", coverage.standards.spec(coverage.DEFAULT))
    return coverage._unit_state(slots["web_checks"])


# ---- persistence and restoration -------------------------------------------

def test_producer_result_survives_completion(tmp_path, lab):
    data, scope = _app(tmp_path, lab)
    orch = _orch(data)
    intent = _intent(data, "c1", "crawl", f"Crawl {lab}")

    status, result = orch._execute("eng", scope, {"profile": "safe_active"}, intent)
    assert orch._complete(intent, status, result) is True  # what the run loop does

    stored = json.loads(data.db.one(
        "SELECT result_json FROM intents WHERE id='c1'")["result_json"])
    assert stored["endpoints"], "the crawl discovered nothing to persist"
    assert any("/catalog" in ep for ep in stored["endpoints"]), stored["endpoints"]
    assert result["endpoints"] == stored["endpoints"]


def test_both_producers_persist_their_own_result(tmp_path, lab):
    """Negative control for a fix that only ever covers the crawl path."""
    data, scope = _app(tmp_path, lab)
    orch = _orch(data)
    data.db.execute(
        "INSERT INTO intents(id, engagement_id, role, objective, status, result_json, created_at) "
        "VALUES('c1','eng','crawl','crawl','done',?,0)",
        (json.dumps({"endpoints": [lab + "/catalog?sku=x"], "forms": [], "pages": []}),))
    intent = _intent(data, "w1", "web_checks", f"Web security checks on {lab}")
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")

    _, result = orch._execute("eng", scope, eng, intent)

    assert set(result) == {"candidates", "mitigated", "skipped"}, result


def test_state_is_readable_by_a_new_worker_after_restart(tmp_path, lab, monkeypatch):
    """A killed worker holds no memory: restoration must come from SQLite alone."""
    data, scope = _app(tmp_path, lab)
    first = _orch(data)
    intent = _intent(data, "c1", "crawl", f"Crawl {lab}")
    status, result = first._execute("eng", scope, {"profile": "safe_active"}, intent)
    first._complete(intent, status, result)

    seen = []
    real = WebChecks.reflected_xss

    def spy(self, url, param):
        seen.append((url, param))
        return real(self, url, param)

    monkeypatch.setattr(WebChecks, "reflected_xss", spy)
    restarted = _orch(data)  # the resumed engagement's worker
    checks = _intent(data, "w1", "web_checks", f"Web security checks on {lab}")
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    restarted._execute("eng", scope, eng, checks)

    assert (lab + "/catalog", "sku") in seen, f"restored inventory was not consumed: {seen}"
    assert "crawl_result_missing" not in _codes(data), _codes(data)


# ---- explicit failure instead of silent loss -------------------------------

@pytest.mark.parametrize("payload", ["{}", "not json at all", '{"pages": []}', ""],
                         ids=["legacy-empty-object", "corrupt", "no-endpoints-key", "blank"])
def test_unusable_crawl_state_is_a_reported_gap_not_an_empty_sweep(tmp_path, lab, payload):
    data, scope = _app(tmp_path, lab)
    _intent(data, "c1", "crawl", f"Crawl {lab}", payload)
    orch = _orch(data)
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    intent = _intent(data, "w1", "web_checks", f"Web security checks on {lab}")

    _, result = orch._execute("eng", scope, eng, intent)

    assert "crawl_result_missing" in _codes(data), _codes(data)
    # the fixed checks and the constant parameter list still run (they never needed the
    # crawl); what must not happen is a probe of a discovered endpoint that does not exist
    crawled = [r["url"] for r in data.db.query(
        "SELECT url FROM exchanges WHERE engagement_id='eng' AND url LIKE '%/catalog%'")]
    assert crawled == [], f"a nonexistent inventory was probed: {crawled}"
    # and the ledger must not read the sweep as assessed
    assert _web_checks_state(data) == "blocked_target"


def test_a_real_inventory_does_not_raise_the_gap(tmp_path, lab):
    """Negative control: the same path stays quiet when the state is intact."""
    data, scope = _app(tmp_path, lab)
    _intent(data, "c1", "crawl", f"Crawl {lab}",
            json.dumps({"endpoints": [lab + "/catalog?sku=x"], "forms": [], "pages": []}))
    orch = _orch(data)
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    intent = _intent(data, "w1", "web_checks", f"Web security checks on {lab}")

    orch._execute("eng", scope, eng, intent)

    assert "crawl_result_missing" not in _codes(data), _codes(data)
    assert _web_checks_state(data) != "blocked_target"


def test_no_crawl_intent_at_all_is_not_reported_as_a_missing_one(tmp_path, lab):
    """An engagement that never planned a crawl is unassessed by absence, not by damage."""
    data, scope = _app(tmp_path, lab)
    orch = _orch(data)
    eng = data.db.one("SELECT * FROM engagements WHERE id='eng'")
    intent = _intent(data, "w1", "web_checks", f"Web security checks on {lab}")

    orch._execute("eng", scope, eng, intent)

    assert "crawl_result_missing" not in _codes(data), _codes(data)
