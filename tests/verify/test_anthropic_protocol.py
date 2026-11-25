"""Libella must speak BOTH provider protocols, and discover models instead of guessing.

An operator may point Libella at an OpenAI-compatible endpoint or an Anthropic one. The two
differ in every part an agent depends on: auth header, the system prompt being a top-level
field, `max_tokens` being required, and the usage field names. Getting any of them wrong
fails every agent turn with a provider 400, so both paths are asserted against a local
server that enforces the real shape, plus model discovery so an ID need not be typed.

Negative twins: the OpenAI shape is rejected by the Anthropic server (proving the test is
not passing vacuously), a wrong key is refused, and discovery refuses an unallowlisted host.
"""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from libella.db import DB
from libella.llm import LLM, LLMError
# imported under a non-test name: pytest collects any imported top-level `test_*` symbol
# as a test and then errors on its missing fixtures
from libella.provider_diagnostic import ANTHROPIC_URL, list_models
from libella.provider_diagnostic import test_connection as probe_provider

GOOD = "sk-ant-test"


class Provider(BaseHTTPRequestHandler):
    """Anthropic Messages on /v1/messages, OpenAI on /v1/chat/completions, models on /v1/models."""

    def _json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - stdlib signature
        if self.path != "/v1/models":
            return self._json(404, {"error": "no"})
        if self.headers.get("x-api-key") != GOOD:
            return self._json(401, {"error": {"type": "authentication_error"}})
        return self._json(200, {"data": [{"id": "claude-sonnet-4", "display_name": "Claude Sonnet 4"},
                                         {"id": "claude-haiku-3-5"}]})

    def do_POST(self):  # noqa: N802 - stdlib signature
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/v1/messages":
            if self.headers.get("x-api-key") != GOOD:
                return self._json(401, {"error": {"type": "authentication_error"}})
            # The Anthropic shape requires max_tokens and a messages list; `system` is
            # OPTIONAL (a diagnostic probe may omit it). The OpenAI shape has no max_tokens
            # requirement, so this discriminates the two without rejecting a valid probe.
            if "max_tokens" not in body or not isinstance(body.get("messages"), list):
                return self._json(400, {"error": {"type": "invalid_request_error"}})
            return self._json(200, {"content": [{"type": "text", "text": '{"ok": true}'}],
                                    "stop_reason": "end_turn",
                                    "usage": {"input_tokens": 21, "output_tokens": 7}})
        if self.path == "/v1/chat/completions":
            return self._json(200, {"choices": [{"message": {"content": '{"ok": true}'},
                                                 "finish_reason": "stop"}],
                                    "usage": {"prompt_tokens": 11, "completion_tokens": 4}})
        return self._json(404, {"error": "no"})

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass


@pytest.fixture
def provider(monkeypatch):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}/v1"
    monkeypatch.setenv("LIBELLA_PROVIDER_TEST_URLS", base)
    yield base
    srv.shutdown()


@pytest.fixture
def db(tmp_path):
    handle = DB(tmp_path / "t.sqlite")
    handle.execute("INSERT INTO engagements(id,name,profile,status,scope_json,created_at) "
                   "VALUES('e','e','safe_active','running','{}',0)")
    yield handle
    handle.close()


def test_the_anthropic_shape_is_translated(db, provider):
    """Positive twin: system as a field, max_tokens present, x-api-key auth."""
    llm = LLM(db, {"base_url": provider, "api_key": GOOD, "api_style": "anthropic",
                   "models": {"planner": "claude-sonnet-4"}})
    out = llm.complete("planner", "be terse", "reply", engagement_id="e",
                       json_schema={"type": "object"})
    assert out["parsed"] == {"ok": True}
    assert (out["usage"]["input_tokens"], out["usage"]["output_tokens"]) == (21, 7)


def test_the_openai_shape_is_still_used_for_an_openai_endpoint(db, provider):
    """The other protocol must not regress: same call, OpenAI path, its own usage fields."""
    llm = LLM(db, {"base_url": provider, "api_key": GOOD, "api_style": "openai",
                   "models": {"planner": "gpt-4o-mini"}})
    out = llm.complete("planner", "be terse", "reply", engagement_id="e",
                       json_schema={"type": "object"})
    assert out["parsed"] == {"ok": True}
    assert (out["usage"]["input_tokens"], out["usage"]["output_tokens"]) == (11, 4)


def test_a_wrong_key_fails_loudly(db, provider):
    llm = LLM(db, {"base_url": provider, "api_key": "wrong", "api_style": "anthropic",
                   "models": {"planner": "claude-sonnet-4"}})
    with pytest.raises(LLMError):
        llm.complete("planner", "s", "u", engagement_id="e")


def test_protocol_is_detected_from_the_host():
    """A Claude endpoint is not a Chat Completions endpoint, and vice versa."""
    assert LLM(None, {"base_url": ANTHROPIC_URL}).protocol() == "anthropic"
    assert LLM(None, {"base_url": "https://api.openai.com/v1"}).protocol() == "openai"
    # an explicit style wins over the host, for proxies and gateways
    assert LLM(None, {"base_url": ANTHROPIC_URL, "api_style": "openai"}).protocol() == "openai"


def test_models_are_discovered_not_typed(provider):
    out = asyncio.run(list_models({}, {"base_url": provider, "api_key": GOOD,
                                       "api_style": "anthropic"}))
    assert out["status"] == "connected"
    assert [m["id"] for m in out["models"]] == ["claude-haiku-3-5", "claude-sonnet-4"]
    assert any(m["label"] == "Claude Sonnet 4" for m in out["models"])


def test_discovery_refuses_a_wrong_key(provider):
    out = asyncio.run(list_models({}, {"base_url": provider, "api_key": "wrong",
                                       "api_style": "anthropic"}))
    assert out["status"] == "invalid_credentials" and out["models"] == []


def test_discovery_refuses_an_unlisted_host(monkeypatch):
    """The same allowlist as the connection test: a key must not be usable anywhere."""
    monkeypatch.delenv("LIBELLA_PROVIDER_TEST_URLS", raising=False)
    out = asyncio.run(list_models({}, {"base_url": "https://example.com/v1", "api_key": "k"}))
    assert out["status"] == "endpoint_not_allowed" and out["models"] == []


def test_diagnostic_probe_uses_the_anthropic_shape(provider):
    """Named to avoid shadowing the imported function; asserts the real probe path."""
    res = asyncio.run(probe_provider({}, {"base_url": provider, "api_key": GOOD,
                                           "api_style": "anthropic",
                                           "default_model": "claude-sonnet-4"}))
    assert res["status"] == "connected", res
