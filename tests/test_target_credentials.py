"""Target API credential diagnostic: scoped, bounded, honest, redacted."""
import threading
import time

import pytest
from flask import Flask, request
from werkzeug.serving import make_server

from libella.scope import Scope
from libella.target_credentials import check_target_credentials


@pytest.fixture
def lab():
    app = Flask("cred-lab")

    @app.get("/api/me")
    def me():
        if request.headers.get("Authorization") == "Bearer good-token":
            return {"user": "alice", "id": 1}, 200
        return {"error": "unauthorized"}, 401

    @app.get("/boom")
    def boom():
        return {"error": "server"}, 500

    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _scope(base):
    return Scope({"targets": [{"kind": "url", "value": base}], "categories": ["api", "web"]})


def test_accepted_credential_reports_success_and_identity(lab):
    res = check_target_credentials(_scope(lab), lab + "/api/me",
                                  {"type": "bearer", "token": "good-token"},
                                  expect_substring="alice")
    assert res["reachable"] is True
    assert res["status"] == 200
    assert res["auth"] == "accepted"
    assert res["identity_confirmed"] is True
    assert "good-token" not in str(res)


def test_wrong_credential_is_rejected_not_success(lab):
    res = check_target_credentials(_scope(lab), lab + "/api/me", {"type": "bearer", "token": "bad"})
    assert res["status"] == 401
    assert res["auth"] == "rejected"
    assert res["identity_confirmed"] is False


def test_200_without_identity_marker_is_not_overclaimed(lab):
    res = check_target_credentials(_scope(lab), lab + "/api/me", {"type": "bearer", "token": "good-token"})
    assert res["status"] == 200
    assert res["auth"] == "responded_success"
    assert res["identity_confirmed"] is False


def test_server_error_is_not_auth_success(lab):
    res = check_target_credentials(_scope(lab), lab + "/boom", {"type": "bearer", "token": "good-token"})
    assert res["status"] == 500
    assert res["auth"] == "server_error"


def test_out_of_scope_target_is_refused_without_request(lab):
    res = check_target_credentials(_scope(lab), "http://169.254.169.254/latest/meta-data",
                                  {"type": "bearer", "token": "x"})
    assert res["reachable"] is False
    assert res["auth"] == "refused"
    assert "scope" in res["detail"].lower()


def test_credential_value_never_leaks(lab):
    secret = "super-secret-value-123"
    res = check_target_credentials(_scope(lab), lab + "/api/me",
                                  {"type": "header", "name": "X-API-Key", "value": secret})
    assert secret not in str(res)


def test_invalid_credential_type_is_a_clear_error(lab):
    res = check_target_credentials(_scope(lab), lab + "/api/me", {"type": "bogus"})
    assert res["auth"] == "error"
    assert res["reachable"] is False


def test_api_route_requires_auth_and_redacts(lab, tmp_path):
    from fastapi.testclient import TestClient
    from libella.api import App, create_api
    app = App(tmp_path / "data")
    with TestClient(create_api(app)) as client:
        body = {"url": lab + "/api/me", "credential": {"type": "bearer", "token": "good-token"},
                "expect_substring": "alice"}
        assert client.post("/api/target-credentials/test", json=body).status_code == 401
        resp = client.post("/api/target-credentials/test", json=body,
                           headers={"Authorization": f"Bearer {app.token}"})
        assert resp.status_code == 200
        assert resp.json()["auth"] == "accepted"
        assert "good-token" not in resp.text
        # metadata target is refused by scope even when named directly
        meta = client.post("/api/target-credentials/test",
                           json={"url": "http://169.254.169.254/", "credential": {"type": "none"}},
                           headers={"Authorization": f"Bearer {app.token}"})
        assert meta.json()["auth"] == "refused"
