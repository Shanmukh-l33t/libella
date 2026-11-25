"""Provider checks go through HTTP to an inert local completion endpoint."""
import json
import threading
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from libella.api import App, create_api


@pytest.fixture
def diagnostic(tmp_path, monkeypatch):
    app = App(tmp_path)
    calls = []
    # the probe now demands a JSON object: agents parse one on every turn, so a plain
    # "OK" reply is reported as text_only rather than fully working
    reply = [200, {"choices": [{"message": {"content": '{"ok": true}'}}]}]
    encoding = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append((self.path, self.headers.get("Authorization"), request))
            body = json.dumps(reply[1]).encode()
            self.send_response(reply[0])
            self.send_header("Content-Type", "application/json")
            if encoding:
                body = gzip.compress(body)
                self.send_header("Content-Encoding", "gzip")
            if reply[0] == 307:
                self.send_header("Location", "/unexpected")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}/v1"
        monkeypatch.setenv("LIBELLA_PROVIDER_TEST_URLS", base)
        with TestClient(create_api(app)) as client:
            yield app, client, {"Authorization": f"Bearer {app.token}"}, base, calls, reply, encoding
        server.shutdown()
        thread.join()


def test_draft_calls_provider_once_without_saving(diagnostic):
    app, client, headers, base, calls, *_ = diagnostic
    draft = {"base_url": base, "default_model": "fixture-model", "api_key": "fixture-only"}
    path = "/api/settings/provider-test"
    assert client.post(path, json=draft).status_code == 401
    response = client.post(path, headers=headers, json=draft)
    assert response.status_code == 200
    assert response.json()["status"] == "connected"
    assert response.json()["latency_ms"] >= 0
    assert len(calls) == 1
    endpoint, auth, body = calls[0]
    assert (endpoint, auth, body["model"]) == ("/v1/chat/completions", "Bearer fixture-only", "fixture-model")
    assert body["max_tokens"] == 64
    assert app.db.one("SELECT 1 FROM settings WHERE key='llm_config'") is None
    assert app.db.one("SELECT 1 FROM llm_usage") is None


@pytest.mark.parametrize("code, payload, expected", [
    (401, {"error": {"message": "fixture-only"}}, "invalid_credentials"),
    (403, {}, "access_denied"),
    (404, {"error": {"code": "model_not_found"}}, "model_unavailable"),
    (429, {"error": {"code": "insufficient_quota"}}, "insufficient_quota"),
    (429, {}, "rate_limited"),
    (503, {}, "provider_unavailable"),
    (307, {}, "redirect_refused"),
    (200, {"choices": []}, "protocol_mismatch"),
    (200, {"choices": [{"message": {"content": "x" * 70_000}}]}, "response_too_large"),
])
def test_safe_provider_feedback(diagnostic, code, payload, expected):
    _, client, headers, base, calls, reply, _ = diagnostic
    reply[:] = [code, payload]
    response = client.post("/api/settings/provider-test", headers=headers,
                           json={"base_url": base, "api_key": "fixture-only"})
    assert response.status_code == 200
    assert response.json()["status"] == expected
    assert "fixture-only" not in response.text
    assert len(calls) == 1


def test_only_configured_endpoint_can_use_saved_key(diagnostic, monkeypatch):
    _, client, headers, base, calls, *_ = diagnostic
    path = "/api/settings/provider-test"
    assert client.put("/api/settings", headers=headers,
                      json={"llm": {"base_url": base, "api_key": "fixture-only"}}).status_code == 200
    assert client.post(path, headers=headers, json={"base_url": base + "/other"}).json()["status"] == "endpoint_not_allowed"
    assert not calls
    monkeypatch.setenv("LIBELLA_PROVIDER_TEST_URLS", base + "," + base + "/other")
    assert client.post(path, headers=headers, json={"base_url": base + "/other"}).json()["status"] == "connected"
    assert calls[-1][1] is None
    assert client.post(path, headers=headers, json={}).json()["status"] == "connected"
    assert calls[-1][1] == "Bearer fixture-only"
    assert client.put("/api/settings", headers=headers,
                      json={"llm": {"base_url": base + "/other"}}).status_code == 200
    assert "api_key" not in client.get("/api/settings", headers=headers).json()["llm"]
    assert client.post(path, headers=headers, json={}).json()["status"] == "connected"
    assert calls[-1][1] is None


def test_invalid_url_and_input_do_not_echo_secrets(diagnostic):
    _, client, headers, base, calls, *_ = diagnostic
    path = "/api/settings/provider-test"
    response = client.post(path, headers=headers, json={"base_url": base + "?key=fixture-only"})
    assert response.json()["status"] == "invalid_url"
    assert "fixture-only" not in response.text
    response = client.post(path, headers=headers, json={"api_key": {"value": "fixture-only"}})
    assert response.status_code == 400
    assert "fixture-only" not in response.text
    for bad in ([], {"model": "x"}, {"base_url": "x" * 2049}):
        assert client.post(path, headers=headers, json=bad).status_code == 400
    assert client.post(path, headers=headers, content=b"{" + b" " * 9000 + b"}").status_code == 413
    response = client.post(path, headers=headers, json={"base_url": "http://10.0.0.5/v1", "api_key": "fixture-only"})
    assert response.json()["status"] == "invalid_url"
    assert not calls


def test_compressed_reply_is_read(diagnostic):
    _, client, headers, base, _, _, encoding = diagnostic
    encoding.append("gzip")
    response = client.post("/api/settings/provider-test", headers=headers, json={"base_url": base})
    assert response.json()["status"] == "connected"


def test_save_rejects_unsafe_endpoint_and_normalizes_key(diagnostic):
    app, client, headers, base, calls, *_ = diagnostic
    put = lambda llm: client.put("/api/settings", headers=headers, json={"llm": llm})  # noqa: E731
    assert put({"base_url": "http://10.0.0.5/v1", "api_key": "fixture-only"}).status_code == 400
    assert put({"base_url": "https://u:p@example.test/v1"}).status_code == 400
    assert app.llm_settings() == {}
    assert put({"base_url": base, "api_key": "   "}).status_code == 200
    assert "api_key" not in app.llm_settings()
    assert put({"base_url": "https://api.openai.com/v1", "api_key": " fixture-only "}).status_code == 200
    assert app.llm_settings()["api_key"] == "fixture-only"
    assert put({"base_url": "https://API.openai.com/v1/"}).status_code == 200
    assert app.llm_settings()["api_key"] == "fixture-only"  # same endpoint, different spelling
    assert put({"base_url": ""}).status_code == 200
    assert app.llm_settings()["api_key"] == "fixture-only"  # blank means the OpenAI default
    assert not calls
