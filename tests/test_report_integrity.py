"""Reporting must survive real engagements: coverage derivation, terminal status, kinds.

Two defects found by the first real-site run:
  - coverage derivation raised KeyError('blocked') once a target_mitigated
    degradation existed, which blocked the report intent of a finished run;
  - the report intent's error then marked a FINISHED engagement as failed, so a
    completed assessment read as a crash and produced no report.
"""
import json
import time

import pytest

from libella import coverage
from libella.api import App
from libella.db import new_id

SCOPE = {"targets": [{"kind": "url", "value": "https://example.test/"}],
         "categories": ["recon", "web"], "rate_limit_rps": 5}


@pytest.fixture
def app(tmp_path):
    return App(tmp_path / "data")


def _engagement(db, eid="eng_t", status="done"):
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at, started_at, finished_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (eid, "target", "safe_active", status, json.dumps(SCOPE), "{}", "{}",
         time.time(), time.time(), time.time()))
    return eid


def _intent(db, eid, role="web_checks", status="done"):
    iid = new_id("i")
    db.execute("INSERT INTO intents(id, engagement_id, role, objective, status, depends_on_json, "
               "informed_by_json, asset_ids_json, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
               (iid, eid, role, "checks", status, "[]", "[]", "[]", time.time()))
    return iid


def test_mitigated_target_marks_the_unit_blocked_and_does_not_crash(app):
    eid = _engagement(app.db)
    iid = _intent(app.db, eid)
    app.db.emit(eid, "degradation", {"code": "target_mitigated", "intent_id": iid,
                                     "units": ["headers_check", "path_probe"],
                                     "detail": "403 challenge"})
    work = coverage.workspace(app.db, eid)  # must not raise KeyError('blocked')
    statuses = {t["automatic"]["status"] for c in work["categories"] for t in c["tests"]}
    assert "inconclusive" in statuses
    reasons = [t["automatic"]["reason"] for c in work["categories"] for t in c["tests"]
               if t["automatic"]["status"] == "inconclusive"]
    assert any("challenge" in r or "not assessed" in r for r in reasons), reasons


def test_partial_scan_is_inconclusive_not_completed(app):
    eid = _engagement(app.db)
    iid = _intent(app.db, eid, role="nuclei_scan")
    app.db.emit(eid, "degradation", {"code": "scan_partial", "intent_id": iid, "units": ["nuclei"],
                                     "detail": "nuclei covered 26% of its templates"})
    work = coverage.workspace(app.db, eid)
    scan = [t for c in work["categories"] for t in c["tests"]
            if "nuclei" in t["automatic"].get("units", [])]
    assert scan and all(t["automatic"]["status"] != "completed_no_issue" for t in scan)


def test_post_run_error_keeps_a_finished_run_done(app):
    from libella.api import create_api  # noqa: F401  (ensures the app builds)

    eid = _engagement(app.db, status="done")

    class Boom:
        def start(self, engagement_id, mode):
            raise RuntimeError("report hook exploded")

    app._run_guarded(Boom(), eid, "deterministic")
    row = app.db.one("SELECT status, status_detail FROM engagements WHERE id=?", (eid,))
    assert row["status"] == "done", row
    kinds = [json.loads(r["payload_json"])["code"] for r in
             app.db.query("SELECT payload_json FROM events WHERE engagement_id=? "
                          "AND kind='degradation'", (eid,))]
    assert "post_run_error" in kinds, kinds
    assert not app.db.query("SELECT seq FROM events WHERE engagement_id=? AND kind='engagement_failed'",
                            (eid,))


def test_post_run_error_on_a_running_run_still_fails_it(app):
    eid = _engagement(app.db, status="running")

    class Boom:
        def start(self, engagement_id, mode):
            raise RuntimeError("planner exploded")

    app._run_guarded(Boom(), eid, "deterministic")
    row = app.db.one("SELECT status, status_detail FROM engagements WHERE id=?", (eid,))
    assert row["status"] == "failed" and "planner exploded" in row["status_detail"]
