"""OWASP WSTG 4.2 coverage workspace: manual review ledger over the auto ledger.

Every catalog test always carries an automatic status derived from execution;
an operator may record a review on top. The manual record needs evidence or a
reason, and neither side may overwrite the other. These tests also assert the
workspace never queues intents or tool calls.
"""
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from libella import standards  # noqa: E402
from libella.api import App, create_api  # noqa: E402

SCOPE = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
         "categories": ["web"], "rate_limit_rps": 20}
CATEGORIES = ["INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS", "INPV", "ERRH",
              "CRYP", "BUSL", "CLNT"]


@pytest.fixture
def app(tmp_path):
    app = App(tmp_path / "data")
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng_cov", "wstg", "safe_active", "draft", json.dumps(SCOPE), "{}", "{}", time.time()))
    return app


@pytest.fixture
def client(app):
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    return c


def _item(workspace, test_id):
    return next(t for c in workspace["categories"] for t in c["tests"] if t["id"] == test_id)


def _put(client, test_id, **body):
    return client.put(f"/api/engagements/eng_cov/coverage/wstg/{test_id}", json=body)


def test_catalog_is_the_wstg_4_2_test_list():
    catalog = [(rid, standards.requirement("wstg", rid)["title"])
               for rid in standards.requirements("wstg")]
    ids = [t[0] for t in catalog]
    assert len(ids) == 96 and len(set(ids)) == 96
    assert standards.framework("wstg")["version"] == "4.2"
    assert {i.split("-")[1] for i in ids} == set(CATEGORIES)
    assert all(t[1] and t[1] == t[1].strip() for t in catalog)
    by_id = dict(catalog)
    assert by_id["WSTG-INFO-01"] == "Conduct Search Engine Discovery Reconnaissance for Information Leakage"
    assert by_id["WSTG-INPV-19"] == "Testing for Server-Side Request Forgery"
    assert by_id["WSTG-CLNT-13"] == "Testing for Cross Site Script Inclusion"


def test_workspace_starts_with_no_review_and_an_honest_automatic_status(client):
    w = client.get("/api/engagements/eng_cov/coverage/wstg").json()
    assert w["framework"]["version"] == "4.2"
    assert w["engagement_id"] == "eng_cov"
    s = w["summary"]
    assert s["total"] == 96 and sum(s["statuses"].values()) == 96
    assert s["manual"] == {"covered": 0, "manual": 0, "unsupported": 0}
    assert [c["id"] for c in w["categories"]] == [f"WSTG-{c}" for c in CATEGORIES]
    # a run that has not executed anything claims no test as completed
    assert s["completed"] == 0 and s["not_tested"] == s["applicable"]
    assert {t["status"] for c in w["categories"] for t in c["tests"]} <= {
        "requires_manual", "not_supported", "inconclusive"}
    assert s["statuses"]["inconclusive"] == s["supported"]
    assert w["categories"][0]["name"] == "Information Gathering"


def test_manual_review_requires_a_note(client):
    r = _put(client, "WSTG-INFO-01", status="manual")
    assert r.status_code == 400 and "note" in r.json()["detail"]
    r = _put(client, "WSTG-INFO-01", status="manual",
             note="Read cached headers by hand; no cache-control on authenticated pages.")
    assert r.status_code == 200
    w = r.json()
    assert w["summary"]["manual"]["manual"] == 1
    item = _item(w, "WSTG-INFO-01")
    assert item["status"] == "manual" and item["manual"]["note"].startswith("Read cached headers")
    assert item["manual"]["updated_at"]
    # the automatic derivation stays visible next to the review
    assert item["automatic"]["status"] == "requires_manual"


def test_unsupported_must_state_why(client):
    assert _put(client, "WSTG-INPV-10", status="unsupported").status_code == 400
    r = _put(client, "WSTG-INPV-10", status="unsupported",
             note="No mail submission surface in scope.")
    assert r.status_code == 200
    assert _item(r.json(), "WSTG-INPV-10")["status"] == "unsupported"
    assert r.json()["summary"]["manual"]["unsupported"] == 1


def test_covered_requires_evidence_from_this_engagement(app, client):
    r = _put(client, "WSTG-ATHN-01", status="covered")
    assert r.status_code == 400
    r = _put(client, "WSTG-ATHN-01", status="covered", evidence_id="ev_missing")
    assert r.status_code == 400
    foreign = app.evidence.put("eng_other", b"{}", "note")
    r = _put(client, "WSTG-ATHN-01", status="covered", evidence_id=foreign["id"])
    assert r.status_code == 400 and "engagement" in r.json()["detail"]

    own = app.evidence.put("eng_cov", b'{"login":"https"}', "note")
    r = _put(client, "WSTG-ATHN-01", status="covered", evidence_id=own["id"])
    assert r.status_code == 200
    item = _item(r.json(), "WSTG-ATHN-01")
    assert item["status"] == "covered" and item["manual"]["evidence_id"] == own["id"]
    assert r.json()["summary"]["manual"]["covered"] == 1
    # a manual "covered" counts as a completed test in the denominators
    assert r.json()["summary"]["completed"] >= 1


def test_unknown_status_clears_the_review_only(client):
    _put(client, "WSTG-CONF-06", status="manual", note="Checked OPTIONS by hand.")
    r = _put(client, "WSTG-CONF-06", status="unknown")
    assert r.status_code == 200
    item = _item(r.json(), "WSTG-CONF-06")
    assert item["manual"] is None
    assert not item["status"] == "manual"
    assert item["automatic"]["status"] == "requires_manual"
    assert r.json()["summary"]["manual"]["manual"] == 0


def test_unknown_test_or_engagement_is_rejected(client):
    assert _put(client, "WSTG-ZZZZ-99", status="manual", note="x").status_code == 404
    assert _put(client, "WSTG-INFO-01", status="invented").status_code == 400
    assert client.get("/api/engagements/nope/coverage/wstg").status_code == 404


def test_coverage_never_executes_anything(client, app):
    _put(client, "WSTG-INFO-01", status="manual", note="Walked the metafiles by hand.")
    _put(client, "WSTG-CONF-07", status="unsupported", note="No TLS terminator in this scope.")
    client.get("/api/engagements/eng_cov/coverage/wstg")
    assert app.db.query("SELECT id FROM tool_calls") == []
    assert app.db.query("SELECT id FROM intents") == []
    assert app.db.query("SELECT id FROM observations") == []
