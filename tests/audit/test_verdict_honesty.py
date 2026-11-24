"""Retest/report honesty: 'fixed' must be earned, never inferred from a block page.

An independent audit found the retest path declaring a finding fixed on any HTTP
response that merely lacked the quote — including 401/403/5xx and login
redirects — and letting that verdict bypass the finding lifecycle.
"""
import json
import threading
import time
from pathlib import Path

import pytest
from flask import Flask, Response
from werkzeug.serving import make_server

from libella.api import App
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.report import render_report
from libella.scope import Scope
from libella.tools.http_probe import HttpProbe
from libella.verifier import Verifier

MARK = "proof-marker-42"


class Box:
    """Local lab whose /vuln response can be swapped between remediation states."""

    def __init__(self, tmp_path):
        self.mode = "vulnerable"
        box = self
        lab = Flask(__name__)

        @lab.get("/vuln")
        def vuln():
            if box.mode == "vulnerable":
                return Response(f"<p>{MARK}</p>", status=200)
            if box.mode == "fixed":
                return Response("all clean now", status=200)
            if box.mode == "login":
                return Response("", status=302, headers={"Location": "/login?next=/vuln"})
            code = int(box.mode)
            return Response("denied" if code in (401, 403) else "boom", status=code)

        self.srv = make_server("127.0.0.1", 0, lab)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        self.base = f"http://127.0.0.1:{self.srv.port}"
        self.url = self.base + "/vuln"
        self.db = DB(tmp_path / "t.db")
        self.ev = EvidenceStore(self.db, tmp_path / "ev")
        self.probe = HttpProbe(self.db, self.ev)
        self.pipe = FindingPipeline(self.db, self.ev)
        self.ver = Verifier(self.db, self.ev, self.probe, self.pipe)
        self.scope = Scope({"targets": [{"kind": "url", "value": self.base}],
                            "categories": ["recon", "web", "api", "infra"],
                            "rate_limit_rps": 1000})

    def close(self):
        self.srv.shutdown()

    def finding(self, verify=True) -> str:
        r = self.probe.request("eng", self.scope, self.url, tool="check")
        assert r["ok"]
        fid = self.pipe.submit_candidate("eng", {
            "title": "marker reflected", "cwe": "CWE-79", "severity": "medium",
            "endpoint": self.url, "evidence_ids": [r["evidence_id"]], "quote": MARK,
            "proof_request": {"method": "GET", "url": self.url}, "dedup_key": "k",
        })["id"]
        if verify:
            assert self.ver.verify("eng", self.scope, fid)["verdict"] == "reproduced"
        return fid

    def state(self, fid) -> str:
        return self.db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"]

    def retests(self, fid) -> list[dict]:
        return self.db.query("SELECT * FROM retests WHERE finding_id=?", (fid,))


@pytest.fixture
def box(tmp_path):
    b = Box(tmp_path)
    yield b
    b.close()


def test_fixed_when_status_class_matches_and_quote_is_gone(box):
    fid = box.finding()
    box.mode = "fixed"
    res = box.ver.retest("eng", box.scope, fid)
    assert res["verdict"] == "fixed", res
    assert box.state(fid) == "retested_fixed"
    assert box.retests(fid)[0]["verdict"] == "fixed"


def test_persists_while_quote_still_reproduces(box):
    fid = box.finding()
    res = box.ver.retest("eng", box.scope, fid)
    assert res["verdict"] == "persists", res
    assert box.state(fid) == "retested_persists"


@pytest.mark.parametrize("mode", ["401", "403", "500", "503"])
def test_auth_and_error_responses_are_inconclusive_not_fixed(box, mode):
    fid = box.finding()
    box.mode = mode
    res = box.ver.retest("eng", box.scope, fid)
    assert res["verdict"] == "inconclusive", res
    assert mode in res["detail"], res
    assert box.state(fid) == "validated"  # no verdict earned, no state change


def test_status_class_change_is_inconclusive(box):
    fid = box.finding()
    box.mode = "404"
    res = box.ver.retest("eng", box.scope, fid)
    assert res["verdict"] == "inconclusive", res
    assert "200" in res["detail"] and "404" in res["detail"], res


def test_redirect_to_login_is_inconclusive(box):
    fid = box.finding()
    box.mode = "login"
    res = box.ver.retest("eng", box.scope, fid)
    assert res["verdict"] == "inconclusive", res
    assert "auth" in res["detail"].lower(), res


def test_unvalidated_finding_has_no_retest_verdict(box):
    fid = box.finding(verify=False)  # stays 'observed'
    assert box.state(fid) == "observed"
    res = box.ver.retest("eng", box.scope, fid)
    assert res["verdict"] == "inconclusive", res
    assert box.state(fid) == "observed"
    assert box.retests(fid) == []  # nothing recorded for something never reproduced


def test_retest_states_cannot_bypass_the_lifecycle(box):
    fid = box.finding(verify=False)  # 'observed'
    box.db.execute("INSERT INTO retests(id, finding_id, exchange_id, verdict, detail, created_at) "
                   "VALUES('rt_fake', ?, NULL, 'fixed', 'ok', 0)", (fid,))
    with pytest.raises(ValueError):
        box.pipe.transition(fid, "retested_fixed")
    assert box.state(fid) == "observed"


def test_report_declares_only_the_findings_it_flags_verified(tmp_path):
    """Declared 'confirmed' must equal the per-finding flags the gate recomputes."""
    app = App(tmp_path / "data")
    eid = "eng_count"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (eid, "count", "safe_active", "done",
         json.dumps({"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
                     "categories": ["web"]}), "{}", "{}", time.time()))

    def add(fid, state):
        app.db.execute(
            "INSERT INTO findings(id, engagement_id, title, severity, confidence, endpoint, state, "
            "dedup_key, evidence_ids_json, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (fid, eid, f"finding {fid}", "high", "high", "http://127.0.0.1:8801/x", state,
             fid, "[]", time.time(), time.time()))

    add("f_ok", "validated")
    add("f_persists", "retested_persists")
    add("f_fixed", "retested_fixed")
    add("f_suspected", "suspected")
    res = render_report(app.db, app.evidence, eid)
    doc = json.loads((Path(res["outdir"]) / "report.json").read_text())
    flagged = [f["id"] for f in doc["findings"] if f["verified"]]
    assert doc["summary"]["confirmed"] == len(flagged) == 2, doc["summary"]
    assert set(flagged) == {"f_ok", "f_persists"}
