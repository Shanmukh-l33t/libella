"""Investigation graph lineage + cross-run memory/drift tests."""
import json
import time

from libella.db import DB, new_id
from libella.evidence import EvidenceStore
from libella.graph import build_graph
from libella import memory as mem


def _seed(db, ev, eng):
    now = time.time()
    aid = new_id("a")
    db.execute("INSERT INTO assets(id, engagement_id, kind, key, value_json, first_seen, last_seen) "
               "VALUES(?,?,?,?,?,?,?)", (aid, eng, "endpoint", "http://lab/search", "{}", now, now))
    eid = ev.put_json(eng, {"request": {}, "response": {}}, "http_exchange")["id"]
    oid = new_id("obs")
    db.execute("INSERT INTO observations(id, engagement_id, kind, summary, evidence_id, source_derived, asset_id, created_at) "
               "VALUES(?,?,?,?,?,?,?,?)", (oid, eng, "fingerprint", "search endpoint", eid, "captured_exchange", aid, now))
    hid = new_id("hyp")
    db.execute("INSERT INTO hypotheses(id, engagement_id, statement, status, asset_id, created_at, updated_at) "
               "VALUES(?,?,?,?,?,?,?)", (hid, eng, "possible XSS", "supported", aid, now, now))
    fid = new_id("f")
    db.execute("INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, endpoint, "
               "dedup_key, evidence_ids_json, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
               (fid, eng, "XSS", "CWE-79", "high", "high", "validated", "http://lab/search", "xss", json.dumps([eid]), now, now))
    db.execute("INSERT INTO verifications(id, finding_id, attempt, method, verdict, detail, created_at) "
               "VALUES(?,?,?,?,?,?,?)", (new_id("v"), fid, 1, "replay", "reproduced", "ok", now))
    rid = new_id("run")
    db.execute("INSERT INTO agent_runs(id, engagement_id, role, model, status, iterations, started_at) "
               "VALUES(?,?,?,?,?,?,?)", (rid, eng, "web", "m", "completed", 3, now))
    db.execute("INSERT INTO investigation_steps(id, engagement_id, agent_run_id, seq, action_kind, summary, created_at) "
               "VALUES(?,?,?,?,?,?,?)", (new_id("step"), eng, rid, 1, "reason", "thinking", now))
    return aid, fid


def test_graph_full_lineage(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    _seed(db, ev, "eng")
    g = build_graph(db, "eng")
    types = {n["type"] for n in g["nodes"]}
    assert {"asset", "observation", "evidence", "hypothesis", "finding", "verification",
            "agent_run"} <= types
    kinds = {e["kind"] for e in g["edges"]}
    assert {"supported_by", "affects", "verified_by", "observed_on"} <= kinds
    assert g["timeline"] and g["coverage"]["validated"] == 1
    # verified affects edge flagged
    aff = [e for e in g["edges"] if e["kind"] == "affects"]
    assert aff and aff[0]["verified"] is True
    # filter
    gf = build_graph(db, "eng", include={"finding", "verification"})
    assert {n["type"] for n in gf["nodes"]} == {"finding", "verification"}


def test_memory_recall_and_drift(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    _seed(db, ev, "eng1")
    mem.record_facts(db, "eng1")
    recalled = mem.recall(db, "http://lab/search")
    assert recalled, "facts recorded for target"
    assert any(r["kind"].startswith("finding:") for r in recalled)
    # second engagement on same origin but different asset set -> drift
    now = time.time()
    db.execute("INSERT INTO assets(id, engagement_id, kind, key, value_json, first_seen, last_seen) "
               "VALUES(?,?,?,?,?,?,?)", (new_id("a"), "eng2", "endpoint", "http://lab/new", "{}", now, now))
    changes = mem.detect_drift(db, "eng2")
    kinds = {c["change_kind"] for c in changes}
    assert "added" in kinds or "removed" in kinds
