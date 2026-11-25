"""An expired or invalid authorization window must prevent network dispatch."""
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from libella.api import App, create_api
from libella.gate import evaluate, normalize
from libella.scope import Scope


@pytest.mark.parametrize("end", ["1", "not-a-timestamp"])
def test_closed_window_refuses_manual_target_actions(tmp_path, monkeypatch, end):
    app = App(tmp_path)
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:9/"}], "categories": ["web"]}
    app.db.execute("INSERT INTO engagements(id,name,status,scope_json,window_end) VALUES(?,?,?,?,?)",
                   ("eng", "Test", "window_closed", json.dumps(scope), end))
    evidence = app.evidence.put_json("eng", {"proof_request": {"url": "http://127.0.0.1:9/"}}, "proof_spec")
    app.db.execute("INSERT INTO findings(id,engagement_id,title,state,evidence_ids_json,created_at) VALUES(?,?,?,?,?,?)",
                   ("f", "eng", "Test finding", "validated", json.dumps([evidence["id"]]), time.time()))
    app.db.execute("INSERT INTO exchanges(id,engagement_id,url,method) VALUES(?,?,?,?)",
                   ("ex", "eng", "http://127.0.0.1:9/", "GET"))
    calls = []

    def intercept(*args, **kwargs):
        calls.append(1)
        return {"ok": False, "error": "fixture would have dispatched"}

    monkeypatch.setattr(app.probe, "request", intercept)
    with TestClient(create_api(app), headers={"Authorization": f"Bearer {app.token}"}) as client:
        for action in ("verify", "retest"):
            response = client.post(f"/api/findings/f/{action}")
            assert response.json()["verdict"] == "inconclusive"
        replay = client.post("/api/exchanges/ex/replay")
        assert replay.status_code == 409
        assert calls == []
        assert "window" in replay.json()["detail"]
        for action in ("start", "resume"):
            result = client.post(f"/api/engagements/eng/{action}")
            assert result.status_code == 409
            assert "new engagement" in result.json()["detail"]
    finding = app.db.one("SELECT state FROM findings WHERE id='f'")
    assert finding and finding["state"] == "validated"


def test_http_probe_rechecks_window_after_redirect(tmp_path):
    app = App(tmp_path)
    scope = Scope({"targets": [{"kind": "url", "value": "http://127.0.0.1:9/"}], "categories": ["web"]})
    app.db.execute("INSERT INTO engagements(id,name,scope_json) VALUES(?,?,?)", ("eng", "Test", "{}"))
    calls = []

    def reply(request):
        calls.append(request.url.path)
        app.db.execute("UPDATE engagements SET window_end='1' WHERE id='eng'")
        return httpx.Response(302, headers={"Location": "/next"})

    with httpx.Client(transport=httpx.MockTransport(reply)) as client:
        result = app.probe.request("eng", scope, "http://127.0.0.1:9/", client=client)
    assert calls == ["/"]
    assert not result["ok"] and "window_end" in result["error"]


def test_window_closed_is_explicitly_failed_by_offline_gate():
    report = normalize({"engagement": {"status": "window_closed"}, "degradations": [], "findings": [],
                        "summary": {"intents": 1, "intents_done": 1, "intents_blocked": 0,
                                    "findings_total": 0, "confirmed": 0}})
    result = evaluate(None, report)
    assert not result["passed"]
    assert any(c["name"] == "engagement-status" and c["status"] == "failed" for c in result["coverage"])
