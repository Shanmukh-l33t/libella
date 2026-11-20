"""Concurrency: leases, fencing, parallel writes."""
import threading
import time

from libella.scope import Scope


def test_stale_worker_cannot_complete_a_reclaimed_intent(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    orch = app.orchestrator()
    iid = orch._add_intent(eid, "recon", f"probe {lab.base}")
    a = orch._claim_next(eid)
    assert a and a["id"] == iid

    # lease expires; another worker legitimately re-claims the same intent
    app.db.execute("UPDATE intents SET lease_expires=? WHERE id=?", (time.time() - 1, iid))
    orch._sweep_leases(eid)
    b = orch._claim_next(eid)
    assert b and b["claim_token"] != a["claim_token"]

    assert orch._complete(a, "done") is False
    row = app.db.one("SELECT status, claim_token FROM intents WHERE id=?", (iid,))
    assert row["status"] == "running" and row["claim_token"] == b["claim_token"]
    assert orch._complete(b, "done") is True
    lost = app.db.query("SELECT * FROM events WHERE engagement_id=? AND kind='lease_lost'", (eid,))
    assert len(lost) == 1


def test_concurrent_claims_are_exclusive(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    orch = app.orchestrator()
    iid = orch._add_intent(eid, "recon", f"probe {lab.base}")
    claimed = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        it = orch._claim_next(eid)
        if it:
            claimed.append(it["claim_token"])

    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(claimed) == 1
    assert app.db.one("SELECT attempts FROM intents WHERE id=?", (iid,))["attempts"] == 1


def test_parallel_verifications_do_not_break_the_chain(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    ev = app.evidence.put_json(eid, {"request": {"url": lab.base + "/ok"}}, "http_exchange")
    fid = app.pipeline.submit_candidate(eid, {
        "title": "t", "severity": "low", "endpoint": lab.base + "/ok",
        "evidence_ids": [ev["id"]], "quote": "hello libella",
        "proof_request": {"method": "GET", "url": lab.base + "/ok"}, "dedup_key": "d"})["id"]
    scope = Scope({"targets": [{"kind": "url", "value": lab.base}],
                   "categories": ["web"], "rate_limit_rps": 1000})
    ts = [threading.Thread(target=app.verifier.verify, args=(eid, scope, fid)) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert app.evidence.verify_chain(eid)["ok"] is True
    assert app.pipeline.list(eid)[0]["state"] == "validated"
