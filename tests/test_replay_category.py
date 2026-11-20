"""Regression: verifier replay must use a category the engagement permits.

Bug: replay defaulted to category 'web'; api-only engagements refused it
(out_of_scope) and every finding stayed inconclusive. Found via container
GraphQL engagement (7 findings, 0 validated, verifications detail showed
"category 'web' not permitted").
"""
import threading
import time

from werkzeug.serving import make_server
from flask import Flask, jsonify

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.scope import Scope
from libella.tools.http_probe import HttpProbe
from libella.verifier import Verifier


def test_api_only_engagement_verifies(tmp_path):
    lab = Flask(__name__)

    @lab.get("/api/thing")
    def thing():
        return jsonify(marker="stable-proof-marker")

    srv = make_server("127.0.0.1", 0, lab)
    port = srv.port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        db = DB(tmp_path / "t.db")
        ev = EvidenceStore(db, tmp_path / "ev")
        probe = HttpProbe(db, ev)
        pipe = FindingPipeline(db, ev)
        ver = Verifier(db, ev, probe, pipe)
        scope = Scope({"targets": [{"kind": "url", "value": f"http://127.0.0.1:{port}"}],
                       "categories": ["recon", "api"]})
        url = f"http://127.0.0.1:{port}/api/thing"
        r = probe.request("eng", scope, url, category="api", tool="check")
        assert r["ok"]
        cand = {"title": "test", "cwe": "CWE-200", "severity": "low", "confidence": "high",
                "endpoint": url, "description": "d", "impact": "i", "remediation": "r",
                "evidence_ids": [r["evidence_id"]], "quote": "stable-proof-marker",
                "quote_in": "body", "proof_request": {"method": "GET", "url": url},
                "dedup_key": "k"}
        f = pipe.submit_candidate("eng", cand)
        res = ver.verify("eng", scope, f["id"])
        assert res["verdict"] == "reproduced", res
        assert db.one("SELECT state FROM findings WHERE id=?", (f["id"],))["state"] == "validated"
    finally:
        srv.shutdown()
