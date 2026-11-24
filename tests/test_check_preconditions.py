"""A check must not "prove" anything from an empty input.

Every case here was a real false positive produced when a specialist agent called a native
check with an unset parameter: the agent omitted the SSRF marker and the IDOR cookie, and
both checks reported a high-severity finding which was then independently "reproduced".

The mechanism is the same in each: a substring test against an empty needle is always true,
so `marker not in body` and `foreign_marker not in body` both pass, and the check proceeds
to describe an access-control decision it never tested.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from libella.checks import WebChecks
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.scope import Scope
from libella.tools.http_probe import HttpProbe


@pytest.fixture
def box(tmp_path):
    """A target that answers 200 with a known body, so a marker can be present or absent."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"email":"lab@example.invalid","role":"user"}')

        def log_message(self, format, *args):  # noqa: A002 - signature fixed by BaseHTTPRequestHandler
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            db = DB(tmp_path / "db.sqlite")
            evidence = EvidenceStore(db, tmp_path / "evidence")
            scope = Scope({"targets": [{"kind": "url", "value": url}], "categories": ["web"],
                           "rate_limit_rps": 50})
            probe = HttpProbe(db, evidence)
            yield {"url": url, "checks": WebChecks(probe, "eng", scope)}
            db.close()
        finally:
            server.shutdown()
            worker.join()


def test_ssrf_with_no_marker_is_refused_not_proven(box):
    """An empty marker is in every body; the check must return nothing at all."""
    c, url = box["checks"], box["url"]
    assert c.ssrf(url + "/api/products", "category", url + "/internal/meta", "") == []
    assert c.ssrf(url + "/api/products", "category", url + "/internal/meta", "   ") == []


def test_ssrf_with_an_absent_marker_is_not_a_finding(box):
    """Negative control: a marker the target never returns must not match."""
    c, url = box["checks"], box["url"]
    assert c.ssrf(url + "/api/products", "category", url + "/internal/meta",
                  "LABFAKEKEY-not-present") == []


def test_ssrf_with_a_marker_the_target_returns_is_still_a_finding(box):
    """Positive control: the guard must not disable the capability."""
    c, url = box["checks"], box["url"]
    found = c.ssrf(url + "/api/products", "category", url + "/internal/meta",
                   "lab@example.invalid")
    assert len(found) == 1 and found[0]["cwe"] == "CWE-918"
    assert "lab@example.invalid" in found[0]["description"]


def test_idor_without_a_session_is_refused(box):
    """No cookie means no authenticated identity, so an access-control verdict is unsound."""
    c, url = box["checks"], box["url"]
    assert c.idor(url + "/api/profile", "", '{"email":"other@example.invalid"}', "alice") == []
    assert c.idor(url + "/api/profile", "   ", '{"email":"other@example.invalid"}', "alice") == []


def test_idor_without_a_foreign_marker_is_refused(box):
    """An empty foreign marker is in every body: the ownership claim is unfounded."""
    c, url = box["checks"], box["url"]
    assert c.idor(url + "/api/profile", "session=abc", "", "alice") == []


def test_idor_without_an_identity_is_refused(box):
    """The finding's subject is the identity; without one it names nobody."""
    c, url = box["checks"], box["url"]
    assert c.idor(url + "/api/profile", "session=abc", '{"email":"x"}', "") == []


def test_idor_with_preconditions_present_still_reports(box):
    """Positive control: the guard must not stop a genuine ownership finding."""
    c, url = box["checks"], box["url"]
    found = c.idor(url + "/api/profile", "session=abc", "lab@example.invalid", "alice")
    assert len(found) == 1 and found[0]["cwe"] == "CWE-639"
    assert "alice" in found[0]["description"]


def test_missing_header_findings_dedupe_the_root_document(box):
    """"" and "/" are one document: probing both used to yield two identical findings."""
    c, url = box["checks"], box["url"]
    with_slash = c.security_headers(url + "/")
    without = c.security_headers(url)
    assert len(with_slash) == 1 and len(without) == 1
    assert with_slash[0]["dedup_key"] == without[0]["dedup_key"]
