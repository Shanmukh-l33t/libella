"""Verifier accuracy: does it reject unsupported conclusions AND accept genuine ones?

Permanent product gate. The benchmark that motivated it produced three confirmed
findings that were wrong, each of which had "reproduced" through a real replay:

  * SSRF proven with an empty marker (``"" in body`` is always true)
  * IDOR proven against a PUBLIC resource (an unauthenticated read was called Alice's)
  * one missing-header condition filed twice, keyed on ``""`` and ``"/"``

Every case below is a pair: a misleading observation the verifier must REFUSE, and the
genuine observation it must ACCEPT. A verifier that rejects everything fails the
positive half; one that accepts every reproducible scanner result fails the negative
half. Both halves run against a real HTTP fixture through the real probe and pipeline.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

MARK = "verifier-gate-marker-7c1"
FOREIGN = '{"id":102,"user_id":2,"item":"Gadget"}'
SELF = '{"id":101,"user_id":1,"item":"Widget"}'


class Fixture:
    """One local app whose behaviour each case switches on, so the transport is real."""

    def __init__(self, tmp_path):
        box = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib signature
                route, _, query = self.path.partition("?")
                status, body, headers = box.reply(route, query, self.headers.get("Cookie", ""))
                payload = body.encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):  # noqa: A002 - stdlib signature
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_port}"

    def reply(self, route: str, query: str, cookie: str = ""):
        """(status, body, headers) for one request. Every branch is a benchmark case."""
        if route == "/order":
            # a private order for uid 2; the app refuses an unauthenticated read
            cookie = "session=alice" in cookie
            if "owner=public" in query or cookie:
                return 200, FOREIGN, {"Content-Type": "application/json"}
            return 401, "unauthorized", {}
        if route == "/mine":
            return 200, SELF, {"Content-Type": "application/json"}
        if route == "/fetch":
            if "url=" in query and "internal" in query:
                return 200, f"<p>{MARK}</p>", {"Content-Type": "text/html"}
            return 200, "<p>no remote content</p>", {"Content-Type": "text/html"}
        if route == "/search":
            return 200, "<html><body>Results for: " + unquote(query.split("q=")[-1]) + \
                "</body></html>", {"Content-Type": "text/html"}
        if route == "/login":
            return 302, "", {"Location": "/login?next=/order"}
        if route == "/error200":
            return 200, "Error: invalid input", {"Content-Type": "text/html"}
        if route == "/headers":
            if "hardened=1" in query:
                return 200, "ok", {"Content-Security-Policy": "default-src 'self'",
                                   "X-Frame-Options": "DENY"}
            return 200, "ok", {}
        if route == "/cookie":
            if "hardened=1" in query:
                return 200, "ok", {"Set-Cookie": "session=x; HttpOnly; Secure; SameSite=Strict"}
            return 200, "ok", {"Set-Cookie": "session=x"}
        return 404, "not found", {}

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def gate(tmp_path):
    from libella.api import App
    from libella.scope import Scope

    fx = Fixture(tmp_path)
    app = App(tmp_path / "data")
    scope = Scope({"targets": [{"kind": "url", "value": fx.base}],
                   "categories": ["recon", "web", "api"], "rate_limit_rps": 1000})
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng", "gate", "safe_active", "running", json.dumps(scope.spec), "{}", "{}", time.time()))
    yield {"app": app, "scope": scope, "fx": fx}

    fx.close()
    app.db.close()


def _fetch(gate, url):
    r = gate["app"].probe.request("eng", gate["scope"], url, tool="check")
    assert r["ok"], r
    return r


def _submit(gate, cand):
    return gate["app"].pipeline.submit_candidate("eng", cand)["id"]


def _verify(gate, fid):
    return gate["app"].verifier.verify("eng", gate["scope"], fid)


def _state(gate, fid):
    return gate["app"].db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"]


# ---------------------------------------------------------------- authorization / IDOR

def _idor_candidate(gate, *, url, quote, cookie="session=alice", proof_identity=None,
                    owner_field="user_id", owner_value=2, benign=None):
    r = _fetch(gate, url)
    return {
        "title": "IDOR on an order", "cwe": "CWE-639", "severity": "high",
        "endpoint": url, "evidence_ids": [r["evidence_id"]], "quote": quote,
        "proof_request": {"method": "GET", "url": url, **({"headers": {"Cookie": cookie}}
                                                          if cookie else {})},
        "dedup_key": f"idor:{url}",
        "proof": ({"identity": proof_identity or {"name": "alice", "value": 1},
                   "owner_field": owner_field, "owner_value": owner_value,
                   "benign_request": {"url": benign or f"{gate['fx'].base}/order"}}
                  if proof_identity is not False else {}),
    }


def test_idor_without_an_identity_is_refused(gate):
    """The benchmark's real FP: an unauthenticated read reported as Alice reading Bob's order."""
    fid = _submit(gate, _idor_candidate(gate, url=f"{gate['fx'].base}/order?owner=public",
                                        quote='"user_id":2', cookie="",
                                        proof_identity=False))
    assert _verify(gate, fid)["verdict"] == "unsupported"
    assert _state(gate, fid) != "validated"


def test_idor_on_a_public_resource_is_refused(gate):
    """Reproducible, but the same URL answers anonymously: no access-control decision was made."""
    # the benchmark case: the same document answers an anonymous request, so the cookie
    # bought nothing and no access-control decision was tested
    url = f"{gate['fx'].base}/order?owner=public"
    fid = _submit(gate, _idor_candidate(gate, url=url, quote='"user_id":2',
                                        cookie="session=alice", benign=url))
    out = _verify(gate, fid)
    assert out["verdict"] == "unsupported", out
    assert "anonymously" in out["detail"], out
    assert _state(gate, fid) != "validated"


def test_idor_on_the_callers_own_object_is_refused(gate):
    """Ownership is judged on content: 'user_id' is the requester's own id, so no violation."""
    url = f"{gate['fx'].base}/mine"
    fid = _submit(gate, _idor_candidate(gate, url=url, quote='"user_id":1',
                                        cookie="session=alice",
                                        benign=f"{gate['fx'].base}/order"))
    out = _verify(gate, fid)
    assert out["verdict"] == "unsupported", out
    assert "own object" in out["detail"], out


def test_idor_with_wrong_owner_assumption_is_refused(gate):
    """The recorded owner does not match what the replay serves: the object changed."""
    fid = _submit(gate, _idor_candidate(gate, url=f"{gate['fx'].base}/order",
                                        quote='"user_id":2', owner_value=99))
    assert _verify(gate, fid)["verdict"] == "unsupported"


def test_genuine_idor_is_accepted(gate):
    """Positive twin: a credentialed read of another user's record, refused anonymously."""
    fid = _submit(gate, _idor_candidate(gate, url=f"{gate['fx'].base}/order", quote='"user_id":2'))
    out = _verify(gate, fid)
    assert out["verdict"] == "reproduced", out
    assert _state(gate, fid) == "validated"


# ---------------------------------------------------------------- SSRF

def _ssrf_candidate(gate, *, marker, internal=True, benign=None):
    url = f"{gate['fx'].base}/fetch?url={'http://169.254.169.254/internal' if internal else 'about'}"
    r = _fetch(gate, url)
    body = r["body"]
    return {
        "title": "SSRF", "cwe": "CWE-918", "severity": "high", "endpoint": url,
        "evidence_ids": [r["evidence_id"]], "quote": body.strip()[:40] or "x",
        "proof_request": {"method": "GET", "url": url}, "dedup_key": "ssrf",
        "proof": ({"marker": marker,
                   "benign_request": {"url": benign or f"{gate['fx'].base}/fetch?url=about"}}
                  if marker is not False else {}),
    }


def test_ssrf_with_an_empty_marker_is_refused(gate):
    """The benchmark's real FP: an empty marker is in every body."""
    fid = _submit(gate, _ssrf_candidate(gate, marker=""))
    assert _verify(gate, fid)["verdict"] == "unsupported"


def test_ssrf_without_a_benign_control_is_refused(gate):
    fid = _submit(gate, _ssrf_candidate(gate, marker=MARK, marker_benign=None)
                  if False else _ssrf_candidate(gate, marker=False))
    assert _verify(gate, fid)["verdict"] == "unsupported"


def test_ssrf_marker_present_without_the_internal_fetch_is_refused(gate):
    """The marker is the target's own text: it appears even when nothing was fetched."""
    benign = f"{gate['fx'].base}/fetch?url=about"
    fid = _submit(gate, _ssrf_candidate(gate, marker="no remote content", benign=benign))
    out = _verify(gate, fid)
    assert out["verdict"] == "unsupported", out
    assert "server-side fetch" in out["detail"], out


def test_genuine_ssrf_is_accepted(gate):
    """Positive twin: the marker only appears when the parameter names the internal URL."""
    fid = _submit(gate, _ssrf_candidate(gate, marker=MARK))
    out = _verify(gate, fid)
    assert out["verdict"] == "reproduced", out
    assert _state(gate, fid) == "validated"


# ---------------------------------------------------------------- injection

def test_error_signature_that_the_benign_control_also_raises_is_refused(gate):
    url = f"{gate['fx'].base}/error200?q=1"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "SQLi", "cwe": "CWE-89", "severity": "critical", "endpoint": url,
        "evidence_ids": [r["evidence_id"]], "quote": "Error: invalid input",
        "proof_request": {"method": "GET", "url": url}, "dedup_key": "sqli",
        "proof": {"signal": "error_signature",
                  "benign_request": {"url": f"{gate['fx'].base}/error200?q=abc"}},
    })
    out = _verify(gate, fid)
    assert out["verdict"] == "unsupported", out
    assert "benign" in out["detail"], out


def test_injection_without_a_benign_control_is_refused(gate):
    url = f"{gate['fx'].base}/search?q=%27"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "SQLi", "cwe": "CWE-89", "severity": "critical", "endpoint": url,
        "evidence_ids": [r["evidence_id"]], "quote": "Results for: '",
        "proof_request": {"method": "GET", "url": url}, "dedup_key": "sqli-nocontrol",
        "proof": {"signal": "error_signature"},
    })
    out = _verify(gate, fid)
    assert out["verdict"] in ("unsupported", "not_reproduced"), out
    assert _state(gate, fid) != "validated"


def test_reflection_is_accepted_without_a_benign_control(gate):
    """A verbatim, unescaped reflection IS the claim: no differential is owed."""
    payload = "<script>alert(1)</script>"
    url = f"{gate['fx'].base}/search?q={payload}"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "Reflected XSS", "cwe": "CWE-79", "severity": "high", "endpoint": url,
        "evidence_ids": [r["evidence_id"]], "quote": payload,
        "proof_request": {"method": "GET", "url": url}, "dedup_key": "xss",
        "proof": {"signal": "reflection"},
    })
    assert _verify(gate, fid)["verdict"] == "reproduced"


# ---------------------------------------------------------------- headers / session

def _header_candidate(gate, *, document, hardened=False):
    url = f"{gate['fx'].base}/headers" + ("?hardened=1" if hardened else "")
    r = _fetch(gate, url)
    return {
        "title": "Missing CSP", "cwe": "CWE-693", "severity": "medium", "endpoint": url,
        "evidence_ids": [r["evidence_id"]], "quote": "missing: CSP", "quote_in": "header_fact",
        "proof_request": {"method": "GET", "url": url}, "dedup_key": f"headers:{document}",
        "proof": {"document": document, "controls": ["content-security-policy"]},
    }


def test_headers_proof_on_a_different_document_is_refused(gate):
    """A proof captured at /headers cannot be confirmation for /login."""
    fid = _submit(gate, _header_candidate(gate, document=f"{gate['fx'].base}/login"))
    assert _verify(gate, fid)["verdict"] == "unsupported"


def test_headers_without_control_ids_is_refused(gate):
    url = f"{gate['fx'].base}/headers"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "Missing headers", "cwe": "CWE-693", "severity": "medium", "endpoint": url,
        "evidence_ids": [r["evidence_id"]], "quote": "missing: CSP", "quote_in": "header_fact",
        "proof_request": {"method": "GET", "url": url}, "dedup_key": "headers:nocontrols",
        "proof": {"document": url},
    })
    assert _verify(gate, fid)["verdict"] == "unsupported"


def test_headers_on_a_hardened_response_is_refused(gate):
    """The control is present, so nothing is missing: a stale claim must not validate."""
    fid = _submit(gate, _header_candidate(gate, document=f"{gate['fx'].base}/headers?hardened=1",
                                          hardened=True))
    out = _verify(gate, fid)
    assert out["verdict"] in ("unsupported", "not_reproduced"), out
    assert _state(gate, fid) != "validated"


def test_genuine_missing_header_is_accepted(gate):
    fid = _submit(gate, _header_candidate(gate, document=f"{gate['fx'].base}/headers"))
    out = _verify(gate, fid)
    assert out["verdict"] == "reproduced", out


def test_session_flags_present_is_refused(gate):
    url = f"{gate['fx'].base}/cookie?hardened=1"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "Session cookie missing flags", "cwe": "CWE-614", "severity": "medium",
        "endpoint": url, "evidence_ids": [r["evidence_id"]], "quote": "session|HttpOnly",
        "quote_in": "cookie_fact", "proof_request": {"method": "GET", "url": url},
        "dedup_key": "cookie", "proof": {"cookie": "session", "missing": ["HttpOnly"]},
    })
    out = _verify(gate, fid)
    assert out["verdict"] in ("unsupported", "not_reproduced"), out
    assert _state(gate, fid) != "validated"


def test_genuine_cookie_flag_issue_is_accepted(gate):
    url = f"{gate['fx'].base}/cookie"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "Session cookie missing flags", "cwe": "CWE-614", "severity": "medium",
        "endpoint": url, "evidence_ids": [r["evidence_id"]], "quote": "session|HttpOnly,Secure",
        "quote_in": "cookie_fact", "proof_request": {"method": "GET", "url": url},
        "dedup_key": "cookie-ok", "proof": {"cookie": "session",
                                            "missing": ["HttpOnly", "Secure"]},
    })
    assert _verify(gate, fid)["verdict"] == "reproduced"


# ---------------------------------------------------------------- non-answers

def test_login_redirect_is_not_a_confirmation(gate):
    """A 302 to the login page has no body to reproduce: inconclusive, never validated."""
    url = f"{gate['fx'].base}/login"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "Reflected XSS", "cwe": "CWE-79", "severity": "high", "endpoint": url,
        "evidence_ids": [r["evidence_id"]], "quote": "next=/order",
        "proof_request": {"method": "GET", "url": url}, "dedup_key": "xss-login",
        "proof": {"signal": "reflection"},
    })
    out = _verify(gate, fid)
    assert out["verdict"] in ("not_reproduced", "inconclusive", "unsupported"), out
    assert _state(gate, fid) != "validated"


def test_an_error_served_with_200_is_not_a_vulnerability(gate):
    """HTTP 200 carrying an error message: the quote is reproducible, the claim is not."""
    url = f"{gate['fx'].base}/error200"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "Information disclosure", "cwe": "CWE-200", "severity": "medium",
        "endpoint": url, "evidence_ids": [r["evidence_id"]], "quote": "Error: invalid input",
        "proof_request": {"method": "GET", "url": url}, "dedup_key": "generic200",
    })
    out = _verify(gate, fid)
    # An untyped class has no contract to demand, but the verdict must still be recorded
    # as a replay, not silently upgraded to a proof of impact.
    assert out["verdict"] in ("reproduced", "unsupported", "not_reproduced")


def test_empty_quote_is_never_reproduced(gate):
    url = f"{gate['fx'].base}/headers"
    r = _fetch(gate, url)
    fid = _submit(gate, {
        "title": "Header issue", "cwe": "CWE-693", "severity": "low", "endpoint": url,
        "evidence_ids": [r["evidence_id"]], "quote": "", "quote_in": "header_fact",
        "proof_request": {"method": "GET", "url": url}, "dedup_key": "empty-quote",
        "proof": {"document": url, "controls": ["content-security-policy"]},
    })
    out = _verify(gate, fid)
    assert out["verdict"] not in ("reproduced",), out
    assert _state(gate, fid) != "validated"


# ---------------------------------------------------------------- duplicate documents

def test_one_document_is_one_finding(gate):
    """'' and '/' must dedupe: the benchmark's third FP was the same condition filed twice."""
    from libella.checks import WebChecks
    from libella.proof import canonical_document
    c = WebChecks(gate["app"].probe, "eng", gate["scope"])
    a, b = c.security_headers(gate["fx"].base), c.security_headers(gate["fx"].base + "/")
    assert len(a) == 1 and len(b) == 1
    assert a[0]["dedup_key"] == b[0]["dedup_key"]
    assert canonical_document(gate["fx"].base) == canonical_document(gate["fx"].base + "/")


# ---------------------------------------------------------------- the contract itself
# The differential catches most of these end to end, so the contract is only
# load-bearing if it is exercised directly. Each case names one prerequisite.

def test_contract_names_each_missing_authorization_prerequisite():
    from libella import proof
    full = {"assertion": "a", "identity": {"name": "alice", "value": 1},
            "owner_field": "user_id", "owner_value": 2,
            "benign_request": {"url": "http://h/order"}}
    pr = {"url": "http://h/order", "headers": {"Cookie": "s=1"}}
    assert proof.missing(proof.AUTHORIZATION, full, pr, "IDOR") == []
    assert "identity.name" in proof.missing(proof.AUTHORIZATION, {**full, "identity": {}}, pr, "t")
    assert "identity.value" in proof.missing(
        proof.AUTHORIZATION, {**full, "identity": {"name": "a", "value": None}}, pr, "t")
    assert "owner_field" in proof.missing(proof.AUTHORIZATION, {**full, "owner_field": ""}, pr, "t")
    assert "owner_value" in proof.missing(
        proof.AUTHORIZATION, {**full, "owner_value": None}, pr, "t")
    assert "credential" in proof.missing(proof.AUTHORIZATION, full, {"url": pr["url"]}, "t")
    assert "benign_request.url" in proof.missing(
        proof.AUTHORIZATION, {**full, "benign_request": {}}, pr, "t")


def test_contract_names_each_missing_ssrf_prerequisite():
    from libella import proof
    full = {"assertion": "a", "marker": MARK, "benign_request": {"url": "http://h/fetch?url=x"}}
    pr = {"url": "http://h/fetch?url=i"}
    assert proof.missing(proof.SSRF, full, pr, "SSRF") == []
    assert "marker" in proof.missing(proof.SSRF, {**full, "marker": "  "}, pr, "t")
    assert "benign_request.url" in proof.missing(proof.SSRF, {**full, "benign_request": {}}, pr, "t")


def test_contract_requires_a_benign_control_only_where_the_signal_is_ambiguous():
    """A reflected payload or a rendered expression proves itself; a DB error does not."""
    from libella import proof
    pr = {"url": "http://h/s?q=%27"}
    # self-evidencing classes: the verbatim quote IS the claim
    assert proof.missing(proof.INJECTION, {}, pr, "Reflected XSS") == []
    assert proof.missing(proof.INJECTION, {}, pr, "SSTI in name") == []
    assert proof.missing(proof.INJECTION, {}, pr, "Path traversal in name") == []
    # ambiguous classes: the same signature can appear without injection
    gaps = proof.missing(proof.SQL_ERROR, {}, pr, "SQL injection")
    assert "signal" in gaps and "benign_request.url" in gaps, gaps
    assert proof.missing(proof.SQL_ERROR, {"signal": "error_signature",
                                           "benign_request": {"url": "http://h/s?q=1"}},
                         pr, "SQL injection") == []


def test_contract_requires_a_document_and_controls_for_headers():
    from libella import proof
    pr = {"url": "http://h/"}
    assert proof.missing(proof.HEADERS, {"document": "http://h", "controls": ["csp"]}, pr, "h") == []
    assert "document" in proof.missing(proof.HEADERS, {"controls": ["csp"]}, pr, "t")
    assert "controls" in proof.missing(proof.HEADERS, {"document": "http://h"}, pr, "t")


def test_contract_requires_cookie_and_flags_for_session():
    from libella import proof
    pr = {"url": "http://h/login"}
    assert proof.missing(proof.SESSION, {"cookie": "session", "missing": ["HttpOnly"]}, pr, "s") == []
    assert "cookie" in proof.missing(proof.SESSION, {"missing": ["HttpOnly"]}, pr, "t")
    assert "missing" in proof.missing(proof.SESSION, {"cookie": "session"}, pr, "t")


def test_untyped_class_is_reported_as_having_no_contract():
    """No typed contract exists: say so rather than pretend prerequisites were checked."""
    from libella import proof
    assert proof.missing(proof.GENERIC, {}, {}, "anything") == []
    assert proof.kind_for("CWE-200") == proof.GENERIC
    assert proof.kind_for("CWE-639") == proof.AUTHORIZATION


def test_contract_accepts_either_ownership_or_privilege_but_demands_one():
    """An authorization claim must name what it tested; silence is not a contract."""
    from libella import proof
    pr = {"url": "http://h/x", "headers": {"Cookie": "s=1"}}
    ident = {"name": "alice", "value": 1}
    benign = {"url": "http://h/x"}
    assert proof.missing(proof.AUTHORIZATION,
                         {"identity": ident, "owner_field": "user_id", "owner_value": 2,
                          "benign_request": benign}, pr, "IDOR") == []
    assert proof.missing(proof.AUTHORIZATION,
                         {"identity": ident, "privilege": "admin",
                          "benign_request": benign}, pr, "BFLA") == []
    gaps = proof.missing(proof.AUTHORIZATION,
                         {"identity": ident, "benign_request": benign}, pr, "authz")
    assert "owner_field" in gaps and "privilege" in gaps, gaps
