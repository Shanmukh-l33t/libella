"""A unit that ran a subset of its checks is partial, not unassessed and not clean.

Three outcomes must stay distinct, because collapsing any two of them is the class of
error this ledger exists to prevent:

  ran everything          -> completed            (completed_no_issue if no finding)
  ran, policy cut a part  -> partial              (partial_evidence: the cut subset was
                                                   never tested, so it cannot be a pass)
  could not run at all    -> blocked_target       (inconclusive)

`oast_unsupported` is the first case: nuclei's in-band HTTP templates executed for real,
and only the out-of-band subset (interactsh callbacks to public OAST servers the
engagement does not authorize) was excluded by policy.
"""
import json
import time

from libella import coverage
from libella.db import DB


def _db(tmp_path, profile="safe_active"):
    db = DB(tmp_path / "coverage.db")
    spec = {"targets": [{"kind": "url", "value": "http://127.0.0.1:1"}],
            "categories": ["recon", "web", "api"]}
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, budgets_json, created_at) "
        "VALUES('eng','cov',?,'done',?,'{}',?)",
        (profile, json.dumps(spec), time.time()))
    return db


def _state(db, unit="nuclei"):
    """Unit name as the ledger keys it: a tool name for tool_calls, a role for intents."""
    slots = coverage._unit_slots(db, "eng", coverage.standards.spec(coverage.DEFAULT))
    return coverage._unit_state(slots.get(unit, coverage._slot({}, unit)))


def _degrade(db, code, **payload):
    db.emit("eng", "degradation", {"code": code, **payload})


def _executed(db, tool="nuclei"):
    db.execute(
        "INSERT INTO tool_calls(id, engagement_id, tool, scope_decision, created_at) "
        "VALUES('c1','eng',?,'executed: ok',?)", (tool, time.time()))


def test_executed_without_restriction_is_completed(tmp_path):
    db = _db(tmp_path)
    _executed(db)
    assert _state(db) == "completed"


def test_oast_exclusion_is_partial_not_blocked(tmp_path):
    """In-band templates ran: the unit is partial, never 'not assessed' and never clean."""
    db = _db(tmp_path)
    _executed(db)
    _degrade(db, "oast_unsupported", unit="nuclei")
    assert _state(db) == "partial"


def test_partial_never_reads_as_a_clean_pass(tmp_path):
    """The ledger must show partial_evidence, not completed_no_issue, for any requirement."""
    db = _db(tmp_path)
    _executed(db)
    _degrade(db, "oast_unsupported", unit="nuclei")
    ws = coverage.workspace(db, "eng", coverage.DEFAULT)
    rows = [t for c in ws["categories"] for t in c["tests"] if "nuclei" in t["automatic"]["units"]]
    assert rows, "no requirement is mapped to nuclei: the fixture proves nothing"
    for row in rows:
        assert row["status"] in ("partial_evidence", "finding_verified", "finding_unverified"), \
            (row["id"], row["status"], row["automatic"]["reason"])


def test_a_target_block_is_still_inconclusive(tmp_path):
    """Negative control: a real block is a different outcome from a policy subset."""
    db = _db(tmp_path)
    _executed(db)
    _degrade(db, "target_mitigated", units=["nuclei"])
    assert _state(db) == "blocked_target"


def test_missing_crawl_state_is_blocked_not_partial(tmp_path):
    """The inventory gap is 'not assessed', not 'partially assessed'."""
    db = _db(tmp_path)
    _executed(db, tool="web_checks")
    _degrade(db, "crawl_result_missing", unit="web_checks")
    assert _state(db, "web_checks") == "blocked_target"


def test_blocked_and_partial_together_stay_conservative(tmp_path):
    """If a unit was both blocked and partially run, blocked wins: nothing was tested."""
    db = _db(tmp_path)
    _executed(db)
    _degrade(db, "oast_unsupported", unit="nuclei")
    _degrade(db, "target_mitigated", units=["nuclei"])
    assert _state(db) == "blocked_target"
