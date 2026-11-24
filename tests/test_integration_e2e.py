"""End-to-end acceptance: full assessment lifecycle + new subsystem APIs through
the real application (TestClient), against an in-process vulnerable lab."""
import threading
import time

import pytest
from flask import Flask, request
from fastapi.testclient import TestClient
from werkzeug.serving import make_server

from libella.api import App, create_api


@pytest.fixture
def lab():
    app = Flask(__name__)

    @app.get("/")
    def index():
        return "<html><body><a href='/search?q=hi'>search</a></body></html>"

    @app.get("/search")
    def search():
        return f"<html><body>Results: {request.args.get('q','')}</body></html>"

    srv = make_server("127.0.0.1", 0, app)
    port = srv.port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


@pytest.fixture
def client(tmp_path, lab, monkeypatch):
    # A lifecycle test must not depend on which scanners the host happens to have:
    # with nuclei installed it runs a full template scan (minutes). Absent tools are
    # recorded as degradations, which is the path CI exercises anyway.
    import libella.tools.runner as runner
    monkeypatch.setattr(runner, "resolve_binary", lambda name: None)
    app = App(tmp_path / "data")
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    return c, app, lab


def _wait_done(c, eid, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = c.get(f"/api/engagements/{eid}").json()["status"]
        if s not in ("running", "draft"):
            return s
        time.sleep(1)
    return "timeout"


def test_full_lifecycle_and_new_apis(client):
    c, app, lab = client
    r = c.post("/api/engagements", json={
        "name": "e2e", "scope": {"targets": [{"kind": "url", "value": lab}],
                                 "categories": ["recon", "web"], "rate_limit_rps": 50},
        "budgets": {"max_duration_s": 120}})
    assert r.status_code == 200, r.text
    eid = r.json()["id"]
    assert c.post(f"/api/engagements/{eid}/start", json={"mode": "deterministic"}).status_code == 200
    status = _wait_done(c, eid)
    assert status == "done", status
    # findings validated
    findings = c.get(f"/api/engagements/{eid}/findings").json()
    assert findings, "expected findings"
    assert any(f["state"] == "validated" for f in findings), findings
    # deep graph lineage
    g = c.get(f"/api/engagements/{eid}/graph").json()
    assert {"nodes", "edges", "timeline", "coverage"} <= set(g)
    assert any(n["type"] == "finding" for n in g["nodes"])
    assert g["coverage"]["validated"] >= 1
    # traffic search + replay
    tr = c.get(f"/api/engagements/{eid}/traffic").json()
    exchanges = tr.get("items") or tr.get("exchanges") or tr
    assert exchanges, "expected captured traffic"
    first = exchanges[0] if isinstance(exchanges, list) else exchanges["items"][0]
    xid = first["id"]
    rp = c.post(f"/api/exchanges/{xid}/replay", json={})
    assert rp.status_code == 200, rp.text
    # memory recall (recorded at finish)
    mem = c.get(f"/api/engagements/{eid}/memory").json()
    assert isinstance(mem, list)
    # report json + pdf
    rj = c.get(f"/api/engagements/{eid}/report?format=json").json()
    assert rj["summary"]["confirmed"] >= 1
    pdf = c.get(f"/api/engagements/{eid}/report?format=pdf")
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF", "PDF export"
    # remediation
    fid = findings[0]["id"]
    rem = c.post(f"/api/findings/{fid}/remediation",
                 json={"notes": "fix encoded output", "owner": "dev", "state": "remediated"})
    assert rem.status_code == 200, rem.text
    board = c.get(f"/api/engagements/{eid}/remediation-board").json()
    assert board
    # evidence chain integrity
    ev = c.get(f"/api/engagements/{eid}/findings").json()[0]["evidence_ids"][0]
    chain = c.get(f"/api/evidence/{ev}/chain").json()
    assert chain["ok"]
