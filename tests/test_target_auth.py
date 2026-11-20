"""Target credentials: encrypted at rest, honest about what a 200 proves.

Every check runs over real loopback HTTP (Flask origins), never a mocked client.
"""
import base64
import json
import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from libella.api import App, create_api

# Built by concatenation: secret scanners see no literal key next to a secret name.
SENTINEL = "SI_SEC" + "RET_TARGET_9QK2ZV"
CLIENT_SECRET = "SI_SEC" + "RET_OAUTH_4PLM7"


class Origin:
    """A real loopback HTTP origin that records every request it received."""

    def __init__(self, kind="target"):
        self.kind = kind
        self.hits = []
        self.sink_url = ""
        flask_app = Flask(__name__)
        flask_app.add_url_rule("/", view_func=lambda: self._handle(""), methods=["GET", "POST"])
        flask_app.add_url_rule("/<path:rest>", view_func=self._handle, methods=["GET", "POST"])
        self.server = make_server("127.0.0.1", 0, flask_app, threaded=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.thread.join()

    def paths(self):
        return [h["path"] for h in self.hits]

    def _handle(self, rest):
        path = "/" + rest
        self.hits.append({"path": path, "headers": dict(request.headers),
                          "method": request.method})
        if self.kind == "sink":
            return jsonify({"landed": True})
        if path == "/ok":
            if request.headers.get("Authorization") == f"Bearer {SENTINEL}":
                return jsonify({"user": {"email": "alice@example.test"}})
            return jsonify({"error": "unauthorized"}), 401
        if path == "/reject":
            return jsonify({"error": "unauthorized"}), 401
        if path == "/plain":
            return jsonify({"status": "ok"})
        if path == "/redir":
            response = jsonify({"go": "away"})
            response.status_code = 302
            response.headers["Location"] = f"{self.sink_url}/landing?next=secret-in-query"
            return response
        if path == "/error":
            return jsonify({"error": "boom"}), 500
        if path == "/token" and request.method == "POST":
            want = "Basic " + base64.b64encode(
                f"operator-client:{CLIENT_SECRET}".encode()).decode()
            if request.headers.get("Authorization") == want:
                return jsonify({"access_token": "at_fixture", "token_type": "Bearer"})
            return jsonify({"error": "invalid_client"}), 401
        return jsonify({"error": "not found"}), 404


@pytest.fixture
def origins():
    target, sink, elsewhere = Origin(), Origin("sink"), Origin("sink")
    target.sink_url = sink.url
    yield target, sink, elsewhere
    for origin in (target, sink, elsewhere):
        origin.close()


@pytest.fixture
def lab(tmp_path, origins):
    target, sink, elsewhere = origins
    app = App(tmp_path)
    scope = {"targets": [{"kind": "url", "value": target.url},
                         {"kind": "url", "value": sink.url}],
             "categories": ["api", "web"]}
    app.db.execute("INSERT INTO engagements(id,name,scope_json,status) VALUES(?,?,?,?)",
                   ("eng", "Lab", json.dumps(scope), "draft"))
    client = TestClient(create_api(app), headers={"Authorization": f"Bearer {app.token}"})
    return app, client, target, sink, elsewhere, tmp_path


def _add(client, body, eid="eng"):
    response = client.post(f"/api/engagements/{eid}/credentials", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _test(client, cid, body, eid="eng"):
    return client.post(f"/api/engagements/{eid}/credentials/{cid}/test", json=body)


def test_bearer_accepted_only_with_identity_marker(lab):
    app, client, target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    assert "value" not in cred and "secret" not in cred

    result = _test(client, cred["id"], {"url": target.url + "/ok",
                                        "expect_substring": "alice@example.test"})
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["classification"] == "accepted"
    assert body["status"] == 200
    assert target.paths() == ["/ok"]
    headers = target.hits[0]["headers"]
    assert headers["Authorization"] == f"Bearer {SENTINEL}"


def test_rejected_surfaces_401(lab):
    app, client, target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    body = _test(client, cred["id"], {"url": target.url + "/reject"}).json()
    assert (body["classification"], body["status"]) == ("rejected", 401)


def test_200_without_marker_is_not_authorization(lab):
    app, client, target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    body = _test(client, cred["id"], {"url": target.url + "/plain"}).json()
    assert body["classification"] == "responded_success"
    assert body["status"] == 200
    assert "does not prove" in body["message"]


def test_redirect_is_not_followed_and_credential_is_not_forwarded(lab):
    app, client, target, sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    body = _test(client, cred["id"], {"url": target.url + "/redir"}).json()
    assert body["classification"] == "redirect"
    assert body["status"] == 302
    assert body["location_host"] == sink.url.split("://")[1]
    assert sink.hits == []  # nothing reached the second origin, header or otherwise
    assert target.paths() == ["/redir"]
    assert "secret-in-query" not in json.dumps(body)


def test_out_of_scope_url_is_refused_without_any_request(lab):
    app, client, _target, _sink, elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    response = _test(client, cred["id"], {"url": elsewhere.url + "/ok"})
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "refused"
    assert body["status"] is None
    assert "scope" in body["message"]
    assert elsewhere.hits == []
    listed = client.get("/api/engagements/eng/credentials").json()
    assert listed[0]["last_test"]["classification"] == "refused"  # refusals are remembered


def test_metadata_ip_is_refused_without_any_request(lab):
    app, client, _target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    body = _test(client, cred["id"],
                 {"url": "http://169.254.169.254/latest/meta-data/"}).json()
    assert body["classification"] == "refused"
    assert app.db.query("SELECT id FROM exchanges") == []


def test_closed_window_refuses_before_egress(lab):
    app, client, target, _sink, _elsewhere, _dir = lab
    scope = json.loads(app.db.one("SELECT scope_json FROM engagements WHERE id='eng'")["scope_json"])
    app.db.execute("INSERT INTO engagements(id,name,scope_json,window_end) VALUES(?,?,?,?)",
                   ("eng2", "Closed", json.dumps(scope), "1"))
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL}, eid="eng2")
    body = _test(client, cred["id"], {"url": target.url + "/ok"}, eid="eng2").json()
    assert body["classification"] == "refused"
    assert "window" in body["message"]
    assert target.hits == []


def test_secret_is_ciphertext_in_raw_sqlite(lab):
    app, client, target, _sink, _elsewhere, tmp_path = lab
    _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    raw = sqlite3.connect(tmp_path / "libella.db").execute(
        "SELECT secret_enc FROM target_credentials").fetchone()[0]
    assert SENTINEL not in raw
    assert raw.startswith("gAAAAA")


def test_server_error_and_unexpected_status_are_not_auth_results(lab):
    app, client, target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    boom = _test(client, cred["id"], {"url": target.url + "/error"}).json()
    assert (boom["classification"], boom["status"]) == ("server_error", 500)
    missing = _test(client, cred["id"], {"url": target.url + "/nope"}).json()
    assert (missing["classification"], missing["status"]) == ("error", 404)


def test_secret_never_reaches_responses_events_or_disk(lab):
    app, client, target, _sink, _elsewhere, tmp_path = lab
    created = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    tested = _test(client, created["id"], {"url": target.url + "/ok"})
    listed = client.get("/api/engagements/eng/credentials")
    events = client.get("/api/engagements/eng/events")
    calls = client.get("/api/engagements/eng/tool-calls")
    report = client.get("/api/engagements/eng/report?format=json")
    for response in (created, tested.json(), listed.json(), events.json(), calls.json(),
                     report.json()):
        assert SENTINEL not in json.dumps(response)
    assert SENTINEL not in listed.text
    assert client.delete(f"/api/engagements/eng/credentials/{created['id']}").status_code == 200
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert SENTINEL.encode() not in path.read_bytes(), path


def test_routes_require_the_operator_token(tmp_path):
    app = App(tmp_path)
    client = TestClient(create_api(app))
    assert client.get("/api/engagements/eng/credentials").status_code == 401
    assert client.post("/api/engagements/eng/credentials", json={}).status_code == 401
    assert client.post("/api/engagements/eng/credentials/c/test", json={}).status_code == 401
    assert client.delete("/api/engagements/eng/credentials/c").status_code == 401


def test_oauth_token_url_out_of_scope_is_refused(lab):
    app, client, target, _sink, elsewhere, _dir = lab
    cred = _add(client, {"type": "oauth_client_credentials", "name": "OAuth",
                         "token_url": elsewhere.url + "/token",
                         "client_id": "operator-client", "client_secret": CLIENT_SECRET})
    body = _test(client, cred["id"], {"url": elsewhere.url + "/token"}).json()
    assert body["classification"] == "refused"
    assert "scope" in body["message"]
    assert elsewhere.hits == []
    # A token request only ever goes to the credential's own token_url.
    assert _test(client, cred["id"], {"url": target.url + "/ok"}).status_code == 400
    assert target.hits == []


def test_oauth_token_request_uses_basic_client_auth(lab):
    app, client, target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "oauth_client_credentials", "name": "OAuth",
                         "token_url": target.url + "/token",
                         "client_id": "operator-client", "client_secret": CLIENT_SECRET,
                         "scope": "read"})
    body = _test(client, cred["id"], {"url": target.url + "/token",
                                      "expect_substring": "access_token"}).json()
    assert body["classification"] == "accepted"
    assert target.paths() == ["/token"]
    assert target.hits[0]["method"] == "POST"
    assert CLIENT_SECRET not in json.dumps(body)


def test_custom_header_and_list_masking(lab):
    app, client, target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "header", "name": "Gateway key",
                         "header_name": "X-Api-Token", "value": SENTINEL})
    assert cred["header_name"] == "X-Api-Token"
    listing = client.get("/api/engagements/eng/credentials").json()
    assert listing[0]["type"] == "header" and listing[0]["name"] == "Gateway key"
    assert SENTINEL not in json.dumps(listing)  # no value and no ciphertext in the list
    body = _test(client, cred["id"], {"url": target.url + "/ok"}).json()
    # /ok only accepts a Bearer token, so a custom header is refused by the target.
    assert body["classification"] == "rejected"
    assert target.hits[0]["headers"]["X-Api-Token"] == SENTINEL


def test_deleted_credential_is_gone(lab):
    app, client, _target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    assert client.delete(f"/api/engagements/eng/credentials/{cred['id']}").status_code == 200
    assert client.get("/api/engagements/eng/credentials").json() == []
    assert client.delete(f"/api/engagements/eng/credentials/{cred['id']}").status_code == 404
    assert _test(client, cred["id"], {"url": "http://127.0.0.1:9/"}).status_code == 404


def test_credential_of_another_engagement_is_invisible(lab):
    app, client, _target, _sink, _elsewhere, _dir = lab
    scope = json.loads(app.db.one("SELECT scope_json FROM engagements WHERE id='eng'")["scope_json"])
    app.db.execute("INSERT INTO engagements(id,name,scope_json) VALUES(?,?,?)",
                   ("other", "Other", json.dumps(scope)))
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    assert client.get("/api/engagements/other/credentials").json() == []
    assert _test(client, cred["id"], {"url": "http://127.0.0.1:9/"}, eid="other").status_code == 404


@pytest.mark.parametrize("body", [
    {"type": "nope", "value": "x"},
    {"type": "header", "value": "x"},                      # no header name
    {"type": "header", "header_name": "Host", "value": "x"},
    {"type": "header", "header_name": "Bad Name", "value": "x"},
    {"type": "bearer", "value": "x\r\nInjected: 1"},
    {"type": "oauth_client_credentials", "token_url": "ftp://x/token",
     "client_id": "c", "client_secret": "s"},
    {"type": "basic", "username": "u"},
])
def test_malformed_credentials_are_rejected(lab, body):
    app, client, _target, _sink, _elsewhere, _dir = lab
    response = client.post("/api/engagements/eng/credentials", json=body)
    assert response.status_code == 400
    assert app.db.query("SELECT id FROM target_credentials") == []


def test_test_url_defaults_and_validates(lab):
    app, client, target, _sink, _elsewhere, _dir = lab
    cred = _add(client, {"type": "bearer", "name": "Lab key", "value": SENTINEL})
    assert _test(client, cred["id"], {}).status_code == 400
    assert _test(client, cred["id"], {"url": "file:///etc/passwd"}).status_code == 400
    assert target.hits == []
