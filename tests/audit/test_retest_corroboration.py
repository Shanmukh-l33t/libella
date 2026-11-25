"""Retest corroboration: a status-class change earns 'fixed' only with signals.

A removed route (200 -> 404) proves nothing on its own: it can be an outage, a
WAF block, or an auth change. 'fixed' now also needs a same-origin control URL
from the engagement still answering as it did, a consistent repeat replay, and
no block-page signature. Every signal goes through the scope-checked probe.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from libella.api import App
from libella.scope import Scope

MARK = "proof-marker-77"


class Box:
    """Loopback lab: per-path responses, swappable, with a hit counter."""

    def __init__(self, tmp_path):
        self.routes = {}
        self.hits = []
        box = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib handler contract
                box.hits.append(self.path)
                route = box.routes.get(self.path, (404, "not found", {}))
                status, body, headers = route() if callable(route) else route
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
        self.url = self.base + "/vuln"
        self.control = self.base + "/ok"
        self.routes["/vuln"] = (200, f"<p>{MARK}</p>", {})
        self.routes["/ok"] = (200, "healthy", {})
        self.app = App(tmp_path / "data")
        self.scope = Scope({"targets": [{"kind": "url", "value": self.base}],
                            "categories": ["recon", "web", "api"],
                            "rate_limit_rps": 1000})
        self.engagement()

    def engagement(self, **window):
        self.app.db.execute(
            "INSERT OR REPLACE INTO engagements(id, name, profile, status, scope_json, "
            "auth_json, budgets_json, window_start, window_end, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("eng", "retest", "safe_active", "running", json.dumps(self.scope.spec), "{}", "{}",
             window.get("start"), window.get("end"), time.time()))

    def finding(self) -> str:
        # a known-good control URL the engagement saw answer 2xx before
        assert self.app.probe.request("eng", self.scope, self.control, tool="check")["ok"]
        r = self.app.probe.request("eng", self.scope, self.url, tool="check")
        assert r["ok"] and r["status"] == 200
        fid = self.app.pipeline.submit_candidate("eng", {
            "title": "marker reflected", "cwe": "CWE-79", "severity": "medium",
            "endpoint": self.url, "evidence_ids": [r["evidence_id"]], "quote": MARK,
            "proof_request": {"method": "GET", "url": self.url}, "dedup_key": "k",
        })["id"]
        assert self.app.verifier.verify("eng", self.scope, fid)["verdict"] == "reproduced"
        return fid

    def retest(self, fid) -> dict:
        return self.app.verifier.retest("eng", self.scope, fid)

    def state(self, fid) -> str:
        return self.app.db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def box(tmp_path):
    b = Box(tmp_path)
    yield b
    b.close()


def test_removed_route_with_target_up_is_fixed_route_removed(box):
    fid = box.finding()
    box.routes["/vuln"] = (404, "no such route", {})
    res = box.retest(fid)
    assert res["verdict"] == "fixed", res
    assert "fixed (route removed)" in res["detail"], res
    assert "/ok" in res["detail"] and "ev_" in res["detail"], res
    assert box.state(fid) == "retested_fixed"
    row = box.app.db.one("SELECT verdict, detail FROM retests WHERE finding_id=?", (fid,))
    assert row["verdict"] == "fixed" and "route removed" in row["detail"]


def test_input_rejected_keeps_its_own_fixed_label(box):
    fid = box.finding()
    box.routes["/vuln"] = (200, "parameter rejected", {})
    res = box.retest(fid)
    assert res["verdict"] == "fixed", res
    assert "fixed (input rejected)" in res["detail"], res


def test_whole_target_down_is_inconclusive(box):
    fid = box.finding()
    box.routes["/vuln"] = (404, "no such route", {})
    box.close()  # nothing answers any more: an outage, not a fix
    res = box.retest(fid)
    assert res["verdict"] == "inconclusive", res
    assert "request failed" in res["detail"], res
    assert box.state(fid) == "validated"


def test_control_no_longer_healthy_is_inconclusive(box):
    fid = box.finding()
    box.routes["/vuln"] = (404, "no such route", {})
    box.routes["/ok"] = (500, "boom", {})
    res = box.retest(fid)
    assert res["verdict"] == "inconclusive", res
    assert "unhealthy" in res["detail"] or "down" in res["detail"], res
    assert box.state(fid) == "validated"


def test_flapping_replay_never_reads_fixed(box):
    fid = box.finding()
    answers = iter([(404, "no such route", {}), (200, f"<p>{MARK}</p>", {})])
    # first replay 404, repeat replay still reproduces the quote
    box.routes["/vuln"] = lambda: next(answers, (404, "no such route", {}))
    res = box.retest(fid)
    assert res["verdict"] != "fixed", res
    assert res["verdict"] in ("persists", "inconclusive"), res
    assert box.state(fid) != "retested_fixed"


def test_block_page_is_inconclusive(box):
    fid = box.finding()
    box.routes["/vuln"] = (404, "<html><title>Attention Required! | Cloudflare</title></html>",
                           {"cf-ray": "8a1b2c"})
    res = box.retest(fid)
    assert res["verdict"] == "inconclusive", res
    assert "block page" in res["detail"], res
    assert box.state(fid) == "validated"


def test_login_redirect_is_inconclusive(box):
    fid = box.finding()
    box.routes["/vuln"] = (302, "", {"Location": "/login?next=/vuln"})
    res = box.retest(fid)
    assert res["verdict"] == "inconclusive", res
    assert "auth" in res["detail"].lower(), res


def test_out_of_scope_control_is_never_contacted(box):
    fid = box.finding()
    box.app.db.execute("UPDATE engagements SET scope_json=? WHERE id='eng'", (json.dumps({
        **box.scope.spec, "exclusions": [{"kind": "url_prefix", "value": box.base + "/admin"}]}),))
    row = box.app.db.one("SELECT scope_json FROM engagements WHERE id='eng'")
    assert row is not None
    scope = Scope(json.loads(row["scope_json"]))
    # an asset a WIDER earlier scope had seen answer 2xx, now excluded
    box.app.db.execute(
        "INSERT INTO exchanges(id, engagement_id, evidence_id, method, url, status, created_at) "
        "VALUES('ex_admin','eng',NULL,'GET',?,200,?)",
        (box.base + "/admin/panel", time.time() + 1))
    box.routes["/vuln"] = (404, "no such route", {})
    box.hits.clear()
    res = box.app.verifier.retest("eng", scope, fid)
    assert res["verdict"] == "fixed", res
    assert not any(h.startswith("/admin") for h in box.hits), box.hits


def test_no_in_scope_control_leaves_it_inconclusive(box):
    fid = box.finding()
    box.routes["/vuln"] = (404, "no such route", {})
    # authorization narrowed to the proof path: no control URL is left in scope
    narrow = Scope({"targets": [{"kind": "url", "value": box.url}],
                    "categories": ["web"], "rate_limit_rps": 1000})
    res = box.app.verifier.retest("eng", narrow, fid)
    assert res["verdict"] == "inconclusive", res
    assert "no in-scope control" in res["detail"], res
    assert box.state(fid) == "validated"


def test_closed_window_makes_no_requests(box):
    fid = box.finding()
    box.engagement(end="1")  # window_end long past
    box.hits.clear()
    res = box.retest(fid)
    assert res["verdict"] == "inconclusive", res
    assert "window" in res["detail"]
    assert box.hits == [], box.hits


def test_control_uses_the_scoped_probe_path(box, monkeypatch):
    """Every signal dials through app.probe: no private HTTP client of its own."""
    fid = box.finding()
    box.routes["/vuln"] = (404, "no such route", {})
    seen = []
    orig = box.app.probe.request

    def spy(engagement_id, scope, url, **kw):
        seen.append((url, kw.get("tool")))
        return orig(engagement_id, scope, url, **kw)

    monkeypatch.setattr(box.app.probe, "request", spy)
    res = box.retest(fid)
    assert res["verdict"] == "fixed", res
    assert seen == [(box.url, "retest"), (box.url, "retest"), (box.control, "retest_control")], seen
