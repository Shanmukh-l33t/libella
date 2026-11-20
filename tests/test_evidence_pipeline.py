"""Evidence ledger + finding pipeline gate tests."""
import pytest
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline


@pytest.fixture
def store(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    return db, ev


def test_content_addressed_and_chain(store):
    db, ev = store
    a = ev.put("eng1", b"hello", "test")
    b = ev.put("eng1", b"world", "test")
    assert a["sha256"] != b["sha256"]
    assert ev.read(a["id"]) == b"hello"
    chain = ev.verify_chain("eng1")
    assert chain["ok"] and chain["checked"] == 2


def test_tamper_detected(store):
    db, ev = store
    a = ev.put("eng1", b"secret evidence", "test")
    path = ev.root / a["path"]
    path.write_bytes(b"tampered")
    with pytest.raises(ValueError):
        ev.read(a["id"])
    assert ev.verify_chain("eng1")["ok"] is False


def test_chain_break_detected(store):
    db, ev = store
    ev.put("eng1", b"a", "test")
    ev.put("eng1", b"b", "test")
    db.execute("UPDATE evidence SET prev_hash='0'*64 WHERE rowid=2")
    assert ev.verify_chain("eng1")["ok"] is False


def test_dedup_and_provenance(store):
    db, ev = store
    pipe = FindingPipeline(db, ev)
    ex = ev.put_json("eng1", {"request": {}, "response": {}}, "http_exchange")
    cand = {"title": "XSS", "severity": "high", "endpoint": "/search",
            "evidence_ids": [ex["id"]], "quote": "<script>", "dedup_key": "xss:/search:q",
            "proof_request": {"method": "GET", "url": "http://x/search?q=<script>"}}
    r1 = pipe.submit_candidate("eng1", cand)
    r2 = pipe.submit_candidate("eng1", cand)
    assert r1["deduped"] is False
    assert r2["deduped"] is True
    assert r1["state"] == "observed"  # derived from real evidence binding
    f = db.one("SELECT * FROM findings WHERE id=?", (r1["id"],))
    assert f["state"] == "observed"


def test_unbound_evidence_stays_suspected(store):
    db, ev = store
    pipe = FindingPipeline(db, ev)
    cand = {"title": "Fake", "severity": "high", "endpoint": "/x",
            "evidence_ids": ["ev_doesnotexist"], "quote": "q", "dedup_key": "fake"}
    r = pipe.submit_candidate("eng1", cand)
    assert r["state"] == "suspected"


def test_validation_gate_requires_reproduced_verification(store):
    db, ev = store
    pipe = FindingPipeline(db, ev)
    ex = ev.put_json("eng1", {}, "http_exchange")
    cand = {"title": "T", "severity": "low", "endpoint": "/t",
            "evidence_ids": [ex["id"]], "quote": "q", "dedup_key": "t"}
    r = pipe.submit_candidate("eng1", cand)
    with pytest.raises(ValueError):
        pipe.transition(r["id"], "validated")
    db.execute("INSERT INTO verifications(id, finding_id, attempt, method, verdict, detail, created_at) "
               "VALUES('v1', ?, 1, 'replay', 'reproduced', 'ok', 0)", (r["id"],))
    pipe.transition(r["id"], "validated")
    assert db.one("SELECT state FROM findings WHERE id=?", (r["id"],))["state"] == "validated"
