"""The egress proxy's client-disconnect guard must not hide real proxy faults.

The guard exists because a scanner that aborts its own request makes `self.wfile.write`
raise BrokenPipeError, and 778 tracebacks per acceptance run is noise, not signal. The
risk of such a guard is the opposite failure: swallowing an error that means the proxy
broke, the decision was never recorded, or an interrupted scan was reported as complete.

So each test here pairs the suppressed case with a positive control that must still fail.
"""
import http.client
import socket
import threading
from http.server import BaseHTTPRequestHandler

import pytest

from libella.db import DB
from libella.egress import EgressProxy
from libella.evidence import EvidenceStore
from libella.egress import Egress
from libella.scope import Scope


@pytest.fixture
def proxy(tmp_path):
    db = DB(tmp_path / "t.db")
    EvidenceStore(db, tmp_path / "ev")  # noqa: B018 - the store must exist for the proxy
    scope = Scope({"targets": [{"kind": "url", "value": "http://127.0.0.1:9"}],
                   "categories": ["web"], "rate_limit_rps": 1000})
    p = EgressProxy(Egress(db, scope, "eng", tool="fixture", category="web"))
    yield p, db
    p.close()


def _handler_raising(failure, monkeypatch):
    """A _ProxyHandler whose request handling raises `failure`, without a live socket.

    BaseHTTPRequestHandler is patched through monkeypatch so the change cannot leak into
    other tests in the session.
    """
    from libella.egress import _ProxyHandler
    h = _ProxyHandler.__new__(_ProxyHandler)
    h.close_connection = False

    def boom(self):
        raise failure
    monkeypatch.setattr(BaseHTTPRequestHandler, "handle_one_request", boom)
    return h


def test_the_guard_suppresses_a_broken_pipe(monkeypatch):
    """The exact error an aborted scanner produces is swallowed and the connection closes."""
    h = _handler_raising(BrokenPipeError(32, "Broken pipe"), monkeypatch)
    h.handle_one_request()  # must not raise
    assert h.close_connection is True


def test_the_guard_suppresses_a_connection_reset(monkeypatch):
    h = _handler_raising(ConnectionResetError(104, "Connection reset by peer"), monkeypatch)
    h.handle_one_request()
    assert h.close_connection is True


@pytest.mark.parametrize("failure", [RuntimeError("proxy bug"), OSError(9, "bad fd"),
                                     ValueError("malformed"), TimeoutError("stalled")],
                         ids=["runtime", "os-error", "value", "timeout"])
def test_the_guard_propagates_every_other_failure(failure, monkeypatch):
    """A genuine proxy fault must never be hidden as a client disconnect."""
    h = _handler_raising(failure, monkeypatch)
    with pytest.raises(type(failure)):
        h.handle_one_request()


def test_client_disconnect_is_not_raised_and_the_decision_is_still_recorded(proxy):
    """The suppressed case: the client hangs up before reading the denial."""
    p, _db = proxy
    host, port = p.server.server_address
    s = socket.create_connection((host, port))
    s.sendall(b"GET http://unauthorized.invalid/x HTTP/1.1\r\nHost: x\r\n\r\n")
    s.close()  # never reads the 403
    # the decision the policy took is recorded even though the reply was lost
    for _ in range(100):
        if p.server.seen:
            break
        threading.Event().wait(0.02)
    assert p.server.seen, "the client abort lost the proxy's own decision record"
    method, target, allowed, _ip = p.server.seen[0]
    assert allowed is False and "unauthorized.invalid" in target


def test_a_real_upstream_failure_still_reports_502(proxy):
    """Positive control: a genuine failure is not silenced by the disconnect guard."""
    p, _db = proxy
    host, port = p.server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    # authorized by scope (the scope names this exact url), but nothing is listening
    conn.request("GET", "http://127.0.0.1:9/nothing-here")
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 502, resp.status
    assert b"upstream" in body.lower(), body


def test_an_out_of_scope_request_is_refused_with_403_not_502(proxy):
    """A policy refusal must stay a refusal: never recorded as a proxy malfunction."""
    p, _db = proxy
    host, port = p.server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", "http://elsewhere.invalid/private")
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 403
    assert b"egress denied" in body
    assert p.server.seen[-1][2] is False


def test_a_malformed_proxy_request_is_still_an_error(proxy):
    """Non-abort HTTP problems are not swallowed by the guard."""
    p, _db = proxy
    host, port = p.server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", "/relative-path")  # not an absolute proxy URL
    resp = conn.getresponse()
    assert resp.status == 502
    conn.close()
