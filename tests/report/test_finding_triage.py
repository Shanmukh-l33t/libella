"""Finding triage: persisted owner/due date, remediation workflow state independent
of verification, audit activity, and the auth/validation around both routes."""
import pytest
from fastapi.testclient import TestClient

from libella.api import create_api
from libella.remediation import (board_status, finding_activity, remediation_board,
                                 set_remediation)


def test_owner_due_and_remediation_state_persist(pair):
    out = set_remediation(pair.db, "f_eng_a_0", owner="alice", due_at="2026-12-31",
                          remediation_state="in_progress", notes="WAF rule staged")
    assert (out["owner"], out["due_at"], out["remediation_state"]) == \
        ("alice", "2026-12-31", "in_progress")
    row = pair.db.one("SELECT * FROM findings WHERE id='f_eng_a_0'")
    assert (row["owner"], row["due_at"], row["remediation_state"]) == \
        ("alice", "2026-12-31", "in_progress")
    assert row["state"] == "validated"  # verification lifecycle untouched


def test_resolved_needs_no_verification_and_board_reflects_it(pair):
    out = set_remediation(pair.db, "f_eng_a_0", remediation_state="resolved")
    assert out["state"] == "validated" and out["remediation_state"] == "resolved"
    assert out["remediated_at"]
    assert pair.db.one("SELECT COUNT(*) n FROM verifications")["n"] == 0

    board = remediation_board(pair.db, "eng_a")
    assert board["counts"]["remediated"] == 1 and board["total"] == 3
    assert board["columns"][2]["findings"][0]["id"] == "f_eng_a_0"


def test_retest_verdict_wins_over_owner_claim(pair):
    set_remediation(pair.db, "f_eng_a_0", remediation_state="resolved")
    pair.db.execute("UPDATE findings SET state='retested_persists' WHERE id='f_eng_a_0'")
    assert board_status(pair.db.one("SELECT * FROM findings WHERE id='f_eng_a_0'")) == "regressed"


def test_invalid_states_dates_and_lengths_are_rejected(pair):
    with pytest.raises(ValueError):
        set_remediation(pair.db, "f_eng_a_0", remediation_state="done")
    for bad in ("31/12/2026", "2026-02-30", "tomorrow"):
        with pytest.raises(ValueError):
            set_remediation(pair.db, "f_eng_a_0", due_at=bad)
    with pytest.raises(ValueError):
        set_remediation(pair.db, "f_eng_a_0", owner="x" * 121)
    with pytest.raises(ValueError):
        set_remediation(pair.db, "f_eng_a_0", notes="x" * 4001)
    assert pair.db.one("SELECT due_at FROM findings WHERE id='f_eng_a_0'")["due_at"] is None


def test_empty_due_date_clears(pair):
    set_remediation(pair.db, "f_eng_a_0", due_at="2026-12-31")
    assert set_remediation(pair.db, "f_eng_a_0", due_at="")["due_at"] is None


def test_activity_history_is_newest_first_and_limited(pair):
    set_remediation(pair.db, "f_eng_a_0", owner="alice")
    set_remediation(pair.db, "f_eng_a_0", remediation_state="in_progress",
                    due_at="2026-12-01")
    events = finding_activity(pair.db, "f_eng_a_0")
    assert [e["kind"] for e in events] == ["finding_remediation", "finding_remediation"]
    assert events[0]["payload"]["changes"]["remediation_state"] == \
        {"from": "open", "to": "in_progress"}
    assert events[0]["payload"]["changes"]["due_at"] == {"from": None, "to": "2026-12-01"}
    assert events[1]["payload"]["changes"]["owner"] == {"from": None, "to": "alice"}
    assert len(finding_activity(pair.db, "f_eng_a_0", limit=1)) == 1
    with pytest.raises(KeyError):
        finding_activity(pair.db, "f_missing")


def test_api_persists_fields_and_serves_activity(client, pair):
    r = client.post("/api/findings/f_eng_a_0/remediation",
                    json={"owner": "alice", "due_at": "2026-12-31",
                          "remediation_state": "in_progress"})
    assert r.status_code == 200 and r.json()["due_at"] == "2026-12-31"

    detail = client.get("/api/findings/f_eng_a_0").json()
    assert (detail["owner"], detail["due_at"], detail["remediation_state"]) == \
        ("alice", "2026-12-31", "in_progress")

    activity = client.get("/api/findings/f_eng_a_0/activity", params={"limit": 10}).json()
    assert activity[0]["payload"]["changes"]["owner"] == {"from": None, "to": "alice"}
    assert client.get("/api/findings/f_missing/activity").status_code == 404


def test_api_rejects_bad_state_date_and_oversized_owner(client, pair):
    assert client.post("/api/findings/f_eng_a_0/remediation",
                       json={"remediation_state": "nope"}).status_code == 400
    assert client.post("/api/findings/f_eng_a_0/remediation",
                       json={"due_at": "2026-02-30"}).status_code == 400
    assert client.post("/api/findings/f_eng_a_0/remediation",
                       json={"owner": "x" * 121}).status_code == 400


def test_new_routes_require_token(app, pair):
    anon = TestClient(create_api(app))
    assert anon.get("/api/findings/f_eng_a_0/activity").status_code == 401
    assert anon.post("/api/findings/f_eng_a_0/remediation",
                     json={"owner": "alice"}).status_code == 401
