"""Evidence ledger: concurrency, forgery, isolation, path safety."""
import hashlib
import json
import threading

import pytest

from libella.db import DB
from libella.evidence import EvidenceStore


@pytest.fixture
def store(tmp_path):
    db = DB(tmp_path / "t.db")
    return db, EvidenceStore(db, tmp_path / "ev")


def test_concurrent_puts_keep_the_chain_valid(store):
    db, ev = store
    barrier = threading.Barrier(16)
    errs = []

    def work(i):
        try:
            barrier.wait()
            for j in range(3):
                ev.put("eng", f"blob-{i}-{j}".encode(), "test")
        except Exception as e:  # pragma: no cover
            errs.append(e)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errs
    chain = ev.verify_chain("eng")
    assert chain["ok"], chain
    assert chain["checked"] == 48


def test_blob_and_single_row_forgery_detected(store):
    db, ev = store
    a = ev.put("eng", b"one", "test")
    b = ev.put("eng", b"two", "test")
    # attacker rewrites blob a and repairs its ledger row consistently
    (ev.root / a["path"]).write_bytes(b"rewritten")
    digest = hashlib.sha256(b"rewritten").hexdigest()
    row = db.one("SELECT * FROM evidence WHERE id=?", (a["id"],))
    chain = hashlib.sha256(f"{row['prev_hash']}|{digest}|{row['kind']}|{row['created_at']}".encode()).hexdigest()
    db.execute("UPDATE evidence SET sha256=?, chain_hash=? WHERE id=?", (digest, chain, a["id"]))
    # the following entry still points at the old head -> detected
    assert ev.verify_chain("eng")["ok"] is False


def test_chain_head_is_per_engagement(store):
    db, ev = store
    ev.put("engA", b"a", "test")
    ev.put("engB", b"b", "test")
    assert ev.verify_chain("engB")["checked"] == 1
    assert ev.verify_chain("engA")["head"] != ev.verify_chain("engB")["head"]


def test_engagement_id_cannot_traverse_the_store(store):
    db, ev = store
    with pytest.raises(ValueError):
        ev.put("../../etc", b"x", "test")
    with pytest.raises(ValueError):
        ev.put("a/b", b"x", "test")


def test_evidence_reads_are_content_addressed(store):
    db, ev = store
    a = ev.put("eng", b"same", "k1")
    b = ev.put("eng", b"same", "k2")
    assert a["path"] == b["path"]
    assert ev.verify_chain("eng")["checked"] == 2