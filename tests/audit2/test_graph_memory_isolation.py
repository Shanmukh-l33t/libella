"""Audit-2: the graph and cross-run memory must not mix engagements.

Cross-engagement *memory* is a feature (keyed by target origin); cross-engagement
*leakage* inside one engagement's graph is not. The check below fails if any node
from another engagement appears in a graph, and confirms recall is keyed to the
target the caller asked for and nothing else.
"""
import json

import pytest

from libella.db import DB
from libella.graph import build_graph
from libella.memory import recall, record_facts


@pytest.fixture
def db(tmp_path):
    d = DB(tmp_path / "t.db")
    for eid in ("eng_a", "eng_b"):
        d.execute("INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
                  "VALUES(?, ?, 'safe_active', 'done', ?, 0)",
                  (eid, eid, json.dumps({"targets": [{"kind": "url",
                                                      "value": f"http://{eid}.test"}]})))
        d.execute("INSERT INTO assets(id, engagement_id, kind, key, value_json, first_seen, "
                  "last_seen) VALUES(?,?,?,?,?,0,0)",
                  (f"a_{eid}", eid, "host", f"{eid}.test", "{}"))
        d.execute(
            "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
            "endpoint, evidence_ids_json, dedup_key, created_at, updated_at) "
            "VALUES(?,?,'t','CWE-79','low','low','observed',?, '[]',?,0,0)",
            (f"f_{eid}", eid, f"http://{eid}.test/x", f"key-{eid}"))
        record_facts(d, eid)
    return d


def test_graph_is_engagement_scoped(db):
    g = build_graph(db, "eng_a")
    labels = " ".join(str(n["label"]) for n in g["nodes"])
    assert "eng_b" not in labels
    assert g["coverage"]["findings"] == 1
    ids = {n["id"] for n in g["nodes"]}
    assert "f_eng_b" not in ids and "a_eng_b" not in ids


def test_memory_recall_is_keyed_to_the_asked_target(db):
    facts = recall(db, "http://eng_a.test")
    assert facts and all(f["target_key"] == "http://eng_a.test:80" for f in facts)
    assert recall(db, "http://eng_b.test") and not recall(db, "http://nothing.test")
