"""Cost accounting and provider-reply handling in the LLM client."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from libella.db import DB
from libella.llm import DEFAULT_PRICING, LLM, LLMError


def test_each_builtin_model_uses_its_own_price():
    llm = LLM(None, {})  # type: ignore[arg-type]  # pricing needs no DB
    for model, price in DEFAULT_PRICING.items():
        if model != "default":
            assert llm._price(model) == price, model
    assert llm._price("gpt-4o-mini-2024-07-18") == DEFAULT_PRICING["gpt-4o-mini"]
    assert llm._price("unknown-model") == DEFAULT_PRICING["default"]


@pytest.mark.parametrize("body", [b"not json", b'{"choices": []}', b"[]", b'{"choices": [{"message": null}]}'])
def test_malformed_provider_reply_is_an_llm_error(tmp_path, body):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        llm = LLM(DB(tmp_path / "t.db"), {"base_url": f"http://127.0.0.1:{server.server_port}/v1"})
        with pytest.raises(LLMError):  # planner degrades on LLMError; anything else crashes the run
            llm.complete("planner", "s", "u")
        server.shutdown()
