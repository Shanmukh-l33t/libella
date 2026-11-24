"""SSRF discovery must fire on a vulnerable fetcher and stay silent on a guarded one.

This check was wrong three times before it was right, each time on a real target:

1. Naming the app's own origin proved only that the parameter accepts a URL. A correct
   allowlist permits its own origin, so a HARDENED target was reported as vulnerable.
2. Naming an unreachable port and looking for fetch-error text failed both ways: both
   twins report fetch failures, so nothing distinguished them.
3. Looking for a foreign page but requiring a 2xx status discarded the genuine finding:
   a vulnerable proxy passes the decoy's 404 through, so the status is not the signal.

What distinguishes the two is a RESPONSE from an address the application is not entitled
to reach. Both directions are asserted here against two live servers, so a regression in
either direction fails.
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

FOREIGN = "<html><title>Decoy Service</title><h1>Not Found</h1></html>"


class Decoy(BaseHTTPRequestHandler):
    """A second service on the next port: answers anyone, so a fetch of it succeeds."""

    def do_GET(self):  # noqa: N802 - stdlib signature
        payload = FOREIGN.encode()
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass


def _app_handler(guarded: bool):
    """A tiny app whose /fetch proxies a caller-supplied URL, guarded or not."""
    import urllib.error
    import urllib.request

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib signature
            parsed = urlparse(self.path)
            if parsed.path != "/fetch":
                payload = b"<html><title>home</title>ok</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            target = (parse_qs(parsed.query).get("url") or [""])[0]
            if not target:
                self.send_response(400)
                self.end_headers()
                return
            if guarded:
                # refuse anything that is not this service's own origin
                own = f"http://127.0.0.1:{self.server.server_port}"
                if not target.startswith(own) or "/probe" in target:
                    payload = b'{"error":"url not allowed"}'
                    self.send_response(403)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
            # pass the fetched response through, status included: that is what the target
            # under test does, and the 404 passthrough is what made the status unusable as
            # a signal
            try:
                with urllib.request.urlopen(target, timeout=5) as r:
                    body, status = r.read()[:4096], r.status
            except urllib.error.HTTPError as e:  # a 4xx is a fetched response, not a failure
                body, status = e.read()[:4096], e.code
            except Exception as e:  # noqa: BLE001 - a real fetch failure
                body = json.dumps({"error": str(e)}).encode()
                status = 502
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002 - stdlib signature
            pass

    return Handler


def _free_port() -> int | None:
    """A port that is free right now, from the kernel's own ephemeral allocation."""
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _bind_pair(guarded: bool):
    """A fresh (app, decoy) on adjacent ports, or (None, None) if it cannot be arranged."""
    for _ in range(40):
        port = _free_port()
        if port is None or port >= 65535:
            continue
        app = decoy = None
        try:
            app = ThreadingHTTPServer(("127.0.0.1", port), _app_handler(guarded))
            decoy = ThreadingHTTPServer(("127.0.0.1", port + 1), Decoy)
            return app, decoy
        except OSError:
            for srv in (app, decoy):
                if srv is not None:
                    srv.server_close()
    return None, None


@pytest.fixture
def pair(request, tmp_path):
    """A guarded and an unguarded app, each with a decoy on the NEXT port.

    The decoy must sit at port+1 because that is the address fetch_param probes, so the
    fixture places it by binding first and then building the app with the expected
    relationship checked, not assumed.
    """
    # bind a candidate app port FIRST, then its neighbour, retrying until the pair is
    # adjacent: fetch_param probes port+1, so the fixture must guarantee that relationship
    # rather than skip when the OS picks unrelated ports
    guarded = getattr(request, "param", False)
    app, decoy = _bind_pair(guarded)
    if app is None:
        pytest.skip("could not bind an adjacent port pair on this host")
    threading.Thread(target=app.serve_forever, daemon=True).start()
    threading.Thread(target=decoy.serve_forever, daemon=True).start()
    yield {"app": app, "base": f"http://127.0.0.1:{app.server_port}", "tmp": tmp_path,
           "guarded": guarded}
    app.shutdown()
    decoy.shutdown()


def _checks(env, guarded: bool):
    db = DB(env["tmp"] / f"{'g' if guarded else 'u'}.sqlite")
    evidence = EvidenceStore(db, env["tmp"] / f"ev{'g' if guarded else 'u'}")
    scope = Scope({"targets": [{"kind": "url", "value": env["base"]}],
                   "categories": ["web"], "rate_limit_rps": 200})
    return db, WebChecks(HttpProbe(db, evidence), "eng", scope, db)


def test_a_vulnerable_fetcher_is_reported(pair):
    """The decoy's own page comes back, so the server fetched an address it should not."""
    db, checks = _checks(pair, guarded=pair["guarded"])
    try:
        found = checks.fetch_param(pair["base"] + "/fetch", "url")
        assert len(found) == 1, found
        assert found[0]["cwe"] == "CWE-918"
        assert found[0]["proof"]["marker"]
    finally:
        db.close()


@pytest.mark.parametrize("pair", [True], indirect=True)
def test_a_guarded_fetcher_is_not_reported(pair):
    """Negative twin: refusing the destination must produce no finding at all."""
    db, checks = _checks(pair, guarded=pair["guarded"])
    try:
        assert checks.fetch_param(pair["base"] + "/fetch", "url") == []
    finally:
        db.close()


def test_a_parameter_that_only_echoes_is_not_ssrf(pair):
    """Echoing the value is not fetching it, however URL-shaped the value is."""
    db = DB(pair["tmp"] / "echo.sqlite")
    evidence = EvidenceStore(db, pair["tmp"] / "ev-echo")

    class Echo(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib signature
            payload = self.path.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):  # noqa: A002 - stdlib signature
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    scope = Scope({"targets": [{"kind": "url", "value": base}], "categories": ["web"],
                   "rate_limit_rps": 200})
    checks = WebChecks(HttpProbe(db, evidence), "eng", scope, db)
    try:
        assert checks.fetch_param(base + "/fetch", "url") == []
    finally:
        srv.shutdown()
        db.close()
