"""A WAF/CDN challenge is a non-answer, not the application.

Real-target regression: keyreed.com (Vercel) answered the assessment client with a
403 challenge that lacked every security header, and the header check reported a
medium "missing security headers" finding for a site that sets all of them. A
challenge page must make the check inconclusive, never a finding, and must not let
verification or retest claim anything either way.
"""
import threading
import time

import pytest
from flask import Flask, Response
from werkzeug.serving import make_server

from libella.checks import WebChecks
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.scope import Scope
from libella.tools.http_probe import HttpProbe, mitigation
from libella.verifier import Verifier

MARK = "proof-marker-42"
GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=63072000",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


class Box:
    def __init__(self, tmp_path):
        self.mode = "normal"
        box = self

        lab = Flask(__name__)

        @lab.get("/page")
        def page():
            if box.mode == "normal":
                return Response(f"<p>{MARK}</p>", status=200, headers=GOOD_HEADERS)
            if box.mode == "vercel":
                # what keyreed.com really returned: no application headers at all
                return Response("challenge", status=403,
                                headers={"x-vercel-mitigated": "challenge", "retry-after": "30"})
            if box.mode == "bare":
                return Response("<p>no headers set at all</p>", status=200)
            if box.mode == "cloudflare":
                return Response("<title>Just a moment...</title>", status=403)
            if box.mode == "captcha":
                return Response("please solve the captcha", status=429)
            return Response("plain error", status=500)

        self.srv = make_server("127.0.0.1", 0, lab)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        time.sleep(0.2)
        self.base = f"http://127.0.0.1:{self.srv.port}"
        self.url = self.base + "/page"
        self.db = DB(tmp_path / "m.db")
        self.ev = EvidenceStore(self.db, tmp_path / "ev")
        self.probe = HttpProbe(self.db, self.ev)
        self.pipe = FindingPipeline(self.db, self.ev)
        self.ver = Verifier(self.db, self.ev, self.probe, self.pipe)
        self.scope = Scope({"targets": [{"kind": "url", "value": self.base}],
                           "categories": ["recon", "web"], "rate_limit_rps": 1000})

    def close(self):
        self.srv.shutdown()

    def finding(self):
        r = self.probe.request("eng", self.scope, self.url, tool="check")
        assert r["ok"] and not r.get("mitigated")
        fid = self.pipe.submit_candidate("eng", {
            "title": "marker reflected", "cwe": "CWE-79", "severity": "medium",
            "endpoint": self.url, "evidence_ids": [r["evidence_id"]], "quote": MARK,
            "proof_request": {"method": "GET", "url": self.url}, "dedup_key": "k",
        })["id"]
        assert self.ver.verify("eng", self.scope, fid)["verdict"] == "reproduced"
        return fid

    def state(self, fid):
        return self.db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"]


@pytest.fixture
def box(tmp_path):
    b = Box(tmp_path)
    yield b
    b.close()


@pytest.mark.parametrize("headers,status,body,expected", [
    ({"x-vercel-mitigated": "challenge"}, 403, b"", "vercel:challenge"),
    ({"cf-mitigated": "challenge"}, 403, b"", "cloudflare:challenge"),
    ({}, 403, b"<title>Just a moment...</title>", "waf:checkpoint"),
    ({}, 429, b"please solve the captcha", "captcha"),
    ({}, 200, b"<p>hello</p>", None),
    ({}, 404, b"not found", None),
])
def test_mitigation_detector(headers, status, body, expected):
    assert mitigation(status, headers, body) == expected


def test_probe_flags_a_challenge_response(box):
    box.mode = "vercel"
    r = box.probe.request("eng", box.scope, box.url, tool="check")
    assert r["ok"] and r["mitigated"] == "vercel:challenge"


def test_header_check_does_not_report_a_challenge_page_as_missing_headers(box):
    box.mode = "vercel"
    checks = WebChecks(box.probe, "eng", box.scope)
    assert checks.security_headers(box.url) == []
    assert checks.mitigated and "vercel:challenge" in checks.mitigated[0]


def test_header_check_still_reports_real_missing_headers(box):
    # a 200 page that genuinely lacks them must still raise the finding
    box.mode = "bare"
    found = WebChecks(box.probe, "eng", box.scope).security_headers(box.url)
    assert found and "missing:" in found[0]["quote"]


def test_challenged_client_falls_back_to_the_browser(box, monkeypatch):
    # the CDN challenges python-httpx but serves the page to a browser: read it there
    page = {"ok": True, "via": "browser", "status": 200, "headers": GOOD_HEADERS,
            "body": "<p>x</p>", "evidence_id": "ev_browser"}
    monkeypatch.setattr(box.probe, "request", lambda *a, **k: {
        "ok": True, "status": 403, "headers": {}, "body": "", "evidence_id": "ev_plain",
        "mitigated": "vercel:challenge"})
    monkeypatch.setattr(box.probe, "browser_request", lambda *a, **k: dict(page))
    checks = WebChecks(box.probe, "eng", box.scope)
    assert checks.security_headers(box.url) == []      # headers are present in the browser view
    assert box.url in checks.browser_urls
    assert checks.mitigated == []                      # answered, not blocked


def test_a_browser_read_candidate_replays_over_the_browser(box, monkeypatch):
    page = {"ok": True, "via": "browser", "status": 200, "headers": {}, "body": "<p>x</p>",
            "evidence_id": "ev_browser"}
    monkeypatch.setattr(box.probe, "request", lambda *a, **k: {
        "ok": True, "status": 403, "headers": {}, "body": "", "evidence_id": "ev_plain",
        "mitigated": "vercel:challenge"})
    monkeypatch.setattr(box.probe, "browser_request", lambda *a, **k: dict(page))
    found = WebChecks(box.probe, "eng", box.scope).security_headers(box.url)
    assert found, "a page without the headers, read through the browser, is still a finding"
    assert found[0]["proof_request"]["via"] == "browser"


def test_verification_of_a_challenged_replay_is_inconclusive(box):
    fid = box.finding()
    box.mode = "vercel"
    res = box.ver.verify("eng", box.scope, fid)
    assert res["verdict"] == "inconclusive", res
    assert "vercel:challenge" in res["detail"]
    assert box.state(fid) == "validated"  # a non-answer cannot demote a validated finding


def test_retest_of_a_challenged_replay_is_inconclusive_not_fixed(box):
    fid = box.finding()
    box.mode = "cloudflare"
    res = box.ver.retest("eng", box.scope, fid)
    assert res["verdict"] == "inconclusive", res
    assert box.state(fid) == "validated"
