"""Audit-2: remediation must not be a side door around the finding state machine.

POST /api/findings/{id}/remediation carries an optional `state`. Writing it
straight into the row promoted a `suspected` finding to `validated` with zero
verifications, which is exactly the gate the platform sells.
"""
import pytest

from libella.db import DB
from libella.remediation import set_remediation


@pytest.fixture
def db(tmp_path):
    d = DB(tmp_path / "t.db")
    d.execute("INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
              "VALUES('eng','e','safe_active','draft','{}',0)")
    d.execute(
        "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
        "evidence_ids_json, dedup_key, created_at, updated_at) "
        "VALUES('f1','eng','t','CWE-79','high','low','suspected','[]','k',0,0)")
    return d


def test_cannot_promote_suspected_to_validated(db):
    with pytest.raises(ValueError):
        set_remediation(db, "f1", state="validated")
    assert db.one("SELECT state FROM findings WHERE id='f1'")["state"] == "suspected"
    assert db.one("SELECT COUNT(*) n FROM verifications")["n"] == 0


def test_lifecycle_legal_state_change_still_works(db):
    out = set_remediation(db, "f1", state="observed")
    assert out["state"] == "observed"


def test_remediation_metadata_updates_without_state(db):
    out = set_remediation(db, "f1", notes="patched upstream", owner="alice", fix_commit="abc123")
    assert out["state"] == "suspected"
    assert out["owner"] == "alice" and out["fix_commit"] == "abc123"
    assert out["remediation_notes"] == "patched upstream"


def test_remediated_state_stamps_timestamp(db):
    db.execute("UPDATE findings SET state='reported' WHERE id='f1'")
    out = set_remediation(db, "f1", state="remediated")
    assert out["state"] == "remediated"
    assert db.one("SELECT remediated_at FROM findings WHERE id='f1'")["remediated_at"]
