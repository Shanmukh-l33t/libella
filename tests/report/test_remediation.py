"""Remediation tracking: field updates persist, board groups, historical diff."""
import time

import pytest

from libella.remediation import (board_status, compare_engagements, remediation_board,
                                 set_remediation)


def test_set_remediation_persists_and_stamps_remediated_at(pair):
    fid = "f_eng_a_0"
    out = set_remediation(pair.db, fid, notes="Patched in v2", owner="alice",
                          fix_commit="abc1234")
    assert (out["owner"], out["fix_commit"], out["remediation_notes"]) == \
        ("alice", "abc1234", "Patched in v2")
    row = pair.db.one("SELECT * FROM findings WHERE id=?", (fid,))
    assert row["owner"] == "alice" and row["remediated_at"] is None

    before = time.time()
    out = set_remediation(pair.db, fid, state="remediated")
    assert out["state"] == "remediated" and out["remediated_at"] >= before
    stored = pair.db.one("SELECT remediated_at FROM findings WHERE id=?", (fid,))
    assert stored["remediated_at"] == out["remediated_at"]  # survived the round trip


def test_set_remediation_rejects_bad_input(pair):
    with pytest.raises(KeyError):
        set_remediation(pair.db, "f_missing", owner="alice")
    with pytest.raises(ValueError):
        set_remediation(pair.db, "f_eng_a_0", state="not_a_state")


def test_board_groups_by_remediation_status(pair):
    set_remediation(pair.db, "f_eng_a_0", owner="alice")  # -> in_progress
    set_remediation(pair.db, "f_eng_a_1", state="remediated")  # -> remediated
    pair.db.execute("UPDATE findings SET state='retested_fixed' WHERE id='f_eng_a_2'")

    board = remediation_board(pair.db, "eng_a")
    assert board["total"] == 3
    assert board["counts"] == {"open": 0, "in_progress": 1, "remediated": 1, "fixed": 1,
                               "regressed": 0, "closed": 0}
    by_status = {c["status"]: c["findings"] for c in board["columns"]}
    assert [f["id"] for f in by_status["in_progress"]] == ["f_eng_a_0"]
    assert [f["id"] for f in by_status["fixed"]] == ["f_eng_a_2"]


def test_board_status_variants():
    assert board_status({"state": "retested_persists"}) == "regressed"
    assert board_status({"state": "ruled_out"}) == "closed"
    assert board_status({"state": "validated"}) == "open"
    assert board_status({"state": "validated", "fix_commit": "deadbeef"}) == "in_progress"


def test_compare_detects_new_fixed_persisting_and_severity_change(pair):
    pair.db.execute(
        "INSERT INTO retests(id, finding_id, exchange_id, verdict, detail, created_at) "
        "VALUES(?,?,?,?,?,?)", ("rt_1", "f_eng_b_0", None, "persists", "still injectable",
                                time.time()))
    diff = compare_engagements(pair.db, "eng_a", "eng_b")
    assert diff["counts"] == {"new": 1, "fixed": 0, "not_observed": 1, "persisting": 1, "severity_changed": 1}
    assert [f["dedup_key"] for f in diff["new"]] == ["open-redirect"]
    assert [f["dedup_key"] for f in diff["not_observed"]] == ["missing-hsts"]
    assert diff["not_observed"][0]["reason"] == "absent_in_b"
    assert [f["dedup_key"] for f in diff["persisting"]] == ["sqli-products"]
    assert diff["persisting"][0]["retests"][0]["verdict"] == "persists"
    assert diff["severity_changed"][0]["previous_severity"] == "high"
    assert diff["severity_changed"][0]["direction"] == "better"


def test_compare_rejects_unknown_engagement(pair):
    with pytest.raises(KeyError):
        compare_engagements(pair.db, "eng_a", "eng_nope")
