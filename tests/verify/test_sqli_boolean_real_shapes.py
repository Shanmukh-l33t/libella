"""The boolean-differential SQLi check must not fire on an endpoint that merely errors.

Measured on OWASP Juice Shop (an unfamiliar app, 4,978 exchanges): the first version of
this check reported 45 SQL injection findings, of which 44 stayed unverified and ONE was
validated. The mechanism was reading a status change as a differential:

    /rest/admin?tag=<payload>   -> 500   (malformed input rejected)
    /rest/user/whoami?callback=<payload> -> 200 with a body that differed from the false case

Neither is evidence of injection. A 500 means the endpoint rejected the input; a body that
differs because the parameter is a JSONP callback name means the value was echoed, not
queried. What distinguishes a boolean injection is that both conditions SUCCEED and the
row set they return differs, reproducibly.

Each case below is a real app shape, with the vulnerable one as the positive twin.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from libella.checks import WebChecks
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.scope import Scope
from libella.tools.http_probe import HttpProbe


class App(BaseHTTPRequestHandler):
    """One server; the fixture sets `mode` to pick which real-world shape it imitates."""

    mode = "injectable"

    def do_GET(self):  # noqa: N802 - stdlib signature
        mode = type(self).mode
        query = parse_qs(urlparse(self.path).query)
        raw = (query.get("q") or query.get("tag") or query.get("callback") or [""])[0]
        truthy = "'1'='1" in raw or "%271%27%3D%271" in raw
        falsy = "'1'='2" in raw or "%271%27%3D%272" in raw

        if mode == "rejects_both":  # /rest/admin shape: malformed input is a 500
            self._send(500, "<html><title>500</title>error</html>")
            return
        if mode == "echoes_parameter":  # JSONP shape: the value comes back, no query
            self._send(200, json.dumps({"status": "success", "callback": raw}))
            return
        if mode == "same_rows":  # parameter ignored entirely
            self._send(200, json.dumps([{"id": 1, "name": "widget"}]))
            return
        # injectable: a real row-set change, both conditions succeed
        if truthy:
            self._send(200, json.dumps([{"id": 1, "name": "widget"},
                                        {"id": 2, "name": "gadget"}]))
        elif falsy:
            self._send(200, json.dumps([{"id": 1, "name": "widget"}]))
        else:
            self._send(200, json.dumps([{"id": 1, "name": "widget"}]))

    def _send(self, status: int, body: str):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass


@pytest.fixture
def lab(request, tmp_path):
    App.mode = getattr(request, "param", "injectable")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    db = DB(tmp_path / "d.sqlite")
    evidence = EvidenceStore(db, tmp_path / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": base}], "categories": ["web"],
                   "rate_limit_rps": 500})
    yield {"checks": WebChecks(HttpProbe(db, evidence), "eng", scope, db), "base": base}
    srv.shutdown()
    db.close()


@pytest.mark.parametrize("lab", ["injectable"], indirect=True)
def test_a_real_row_set_change_is_reported(lab):
    """Positive twin: both conditions succeed and the rows differ, reproducibly."""
    found = lab["checks"].sqli_boolean(lab["base"] + "/search", "q")
    assert len(found) == 1, found
    assert found[0]["cwe"] == "CWE-89"
    assert found[0]["proof"]["signal"] == "boolean_differential"


@pytest.mark.parametrize("lab", ["rejects_both"], indirect=True)
def test_an_endpoint_that_rejects_the_payload_is_not_injection(lab):
    """The Juice Shop /rest/admin case: a 500 for malformed input is a refusal, not a diff."""
    assert lab["checks"].sqli_boolean(lab["base"] + "/rest/admin", "tag") == []


@pytest.mark.parametrize("lab", ["echoes_parameter"], indirect=True)
def test_an_echoed_parameter_is_not_injection(lab):
    """The validated false positive: /rest/user/whoami?callback= echoed the value back."""
    assert lab["checks"].sqli_boolean(lab["base"] + "/rest/user/whoami", "callback") == []


@pytest.mark.parametrize("lab", ["same_rows"], indirect=True)
def test_an_ignored_parameter_is_not_injection(lab):
    assert lab["checks"].sqli_boolean(lab["base"] + "/search", "q") == []


def test_a_volatile_nonce_is_not_a_content_difference():
    """Two answers that differ only in a token must compare as the same document."""
    from libella.checks import _content_differs, _same_document
    a = '{"status":"ok","nonce":"9f8e7d6c5b4a39281706f5e4d3c2b1a0"}'
    b = '{"status":"ok","nonce":"11112222333344445555666677778888"}'
    assert _content_differs(a, b) is False
    assert _same_document(a, b) is True
