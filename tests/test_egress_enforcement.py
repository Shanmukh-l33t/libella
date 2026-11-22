"""Egress enforcement, proven against real sockets.

Every assertion is made on the fixture servers' hit logs, not on the policy
function's return value: if the fixture recorded nothing, nothing was contacted.

127.0.0.2 is a distinct host on Linux loopback, so "another host" is real
without any external egress.
"""
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

import libella.egress as egress_mod  # noqa: E402
from libella.browser_crawl import BrowserCrawler, browser_available  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools import ToolSpec  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402
from libella.tools.runner import ToolRunner  # noqa: E402

SLOW_CHUNKS = 40


class _Node:
    """A fixture HTTP server that records every request it really receives."""

    def __init__(self, host: str, kind: str = "http"):
        self.hits: list[tuple[str, str]] = []
        self.chunks = 0
        node = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status, body: bytes, headers=None):
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_GET(self):
                node.hits.append((self.path, self.headers.get("Via") or ""))
                path = self.path.split("?")[0]
                if path == "/redir":
                    out = self.path.split("to=", 1)[1]
                    self._send(302, b"", {"Location": out})
                    return
                if path == "/slow":
                    body = b"x" * (1024 * SLOW_CHUNKS)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    for i in range(SLOW_CHUNKS):
                        node.chunks += 1
                        try:
                            self.wfile.write(b"x" * 1024)
                            self.wfile.flush()
                        except OSError:
                            return
                        time.sleep(0.05)
                    return
                if path == "/hostile":
                    sink = self.path.split("base=", 1)[1]
                    ws = sink.replace("http://", "")
                    html = f"""<!doctype html><html><head><title>hostile</title></head><body>
<h1>hostile</h1>
<script src="{sink}/x.js"></script>
<img src="{sink}/pixel.png">
<a id="dl" href="{sink}/file.bin" download>x</a>
<script>
fetch('{sink}/beacon').catch(() => {{}});
try {{ new WebSocket('ws://{ws}/ws'); }} catch (e) {{}}
window.open('{sink}/popup');
document.title = 'rendered: ' + document.querySelectorAll('h1').length;
</script></body></html>"""
                    self._send(200, html.encode())
                    return
                self._send(200, b"<html><title>ok</title>hello libella</html>")

        self.httpd = ThreadingHTTPServer((host, 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://{host}:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def app_node():
    n = _Node("127.0.0.1")
    yield n
    n.close()


@pytest.fixture
def other_node():
    n = _Node("127.0.0.2")
    yield n
    n.close()


@pytest.fixture
def engine(tmp_path):
    db = DB(tmp_path / "egress.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        ("eng_egress", "egress", "safe_active", "running", "{}", "{}", "{}", 0.0))
    return db, ev


@pytest.fixture
def probe(engine):
    return HttpProbe(engine[0], engine[1])


def _scope(*targets, ports=None):
    spec = {"targets": [{"kind": "url", "value": t} for t in targets],
            "categories": ["recon", "web", "api", "infra"], "rate_limit_rps": 1000}
    if ports:
        spec["allowed_ports"] = ports
    return Scope(spec)


def _events(db, kind):
    return [e["payload_json"] for e in db.query(
        "SELECT payload_json FROM events WHERE engagement_id='eng_egress' AND kind=?", (kind,))]


# -- HTTP client -------------------------------------------------------------

def test_authorized_host_and_port_is_contacted(probe, app_node):
    r = probe.request("eng_egress", _scope(app_node.base), app_node.base + "/ok")
    assert r["ok"] is True and r["status"] == 200, r
    assert [h for h in app_node.hits if h[0] == "/ok"], app_node.hits


def test_unauthorized_port_is_refused_and_never_dialed(probe, app_node, other_node):
    r = probe.request("eng_egress", _scope(app_node.base),
                      f"http://127.0.0.1:{other_node.port}/ok")
    assert r["ok"] is False and "out_of_scope" in r["error"], r
    assert other_node.hits == [] and app_node.hits == []


def test_redirect_to_another_host_is_refused(probe, app_node, other_node):
    scope = _scope(app_node.base)
    r = probe.request("eng_egress", scope, f"{app_node.base}/redir?to={other_node.base}/stolen")
    assert r["ok"] is False and "out_of_scope" in r["error"], r
    assert [h for h in app_node.hits if h[0].startswith("/redir")], "the first hop was not real"
    assert other_node.hits == [], "the redirect target was actually contacted"


def test_redirect_to_an_unauthorized_port_is_refused(probe, app_node, other_node):
    scope = _scope(app_node.base)
    target = f"http://127.0.0.1:{other_node.port}/stolen"
    r = probe.request("eng_egress", scope, f"{app_node.base}/redir?to={target}")
    assert r["ok"] is False and "out_of_scope" in r["error"], r
    assert other_node.hits == []


def test_dns_change_between_check_and_connect_is_pinned(probe, app_node, other_node, monkeypatch):
    """The host is resolved once; the socket goes to the address that was authorized."""
    calls = {"n": 0}
    real = egress_mod._resolve

    def rebinding(host):
        if host != "pin.test":
            return real(host)
        calls["n"] += 1
        return ["127.0.0.1"] if calls["n"] == 1 else ["127.0.0.2"]

    monkeypatch.setattr(egress_mod, "_resolve", rebinding)
    scope = Scope({"targets": [{"kind": "url", "value": f"http://pin.test:{app_node.port}/"},
                               {"kind": "ip", "value": "127.0.0.1"}],
                   "categories": ["web"], "rate_limit_rps": 1000})
    r = probe.request("eng_egress", scope, f"http://pin.test:{app_node.port}/ok")
    assert r["ok"] is True, r
    assert calls["n"] == 1, "the host was resolved again between the check and the connect"
    assert [h for h in app_node.hits if h[0] == "/ok"], app_node.hits
    assert other_node.hits == [], "the second DNS answer decided where the socket went"


def test_rebinding_to_metadata_or_private_is_refused(probe, monkeypatch):
    real = egress_mod._resolve
    monkeypatch.setattr(egress_mod, "_resolve", lambda h: ["169.254.169.254"] if h == "meta.test"
                        else (real(h) if h != "priv.test" else ["10.255.255.1"]))
    for url, scope in ((("http://meta.test/latest/meta-data/"),
                        Scope({"targets": [{"kind": "url", "value": "http://meta.test/"}],
                               "categories": ["web"]})),
                       (("http://priv.test/internal"),
                        Scope({"targets": [{"kind": "domain", "value": "priv.test"}],
                               "categories": ["web"]}))):
        r = probe.request("eng_egress", scope, url)
        assert r["ok"] is False and "out_of_scope" in r["error"], (url, r)
    assert any("169.254" in p for p in _events(probe.db, "egress_denied"))


def test_pause_mid_response_stops_the_body(probe, app_node, engine):
    db = engine[0]
    scope = _scope(app_node.base)
    out = {}

    def run():
        out.update(probe.request("eng_egress", scope, app_node.base + "/slow", body_cap=1 << 20))

    t = threading.Thread(target=run)
    t.start()
    for _ in range(100):
        if app_node.chunks >= 2:
            break
        time.sleep(0.02)
    db.execute("UPDATE engagements SET status='paused' WHERE id='eng_egress'")
    t.join(15)
    assert not t.is_alive()
    assert out["ok"] is False and "paused" in out["error"], out
    time.sleep(0.6)          # let anything already in the socket buffer drain
    served = app_node.chunks
    time.sleep(0.6)
    assert app_node.chunks == served, "the target kept streaming after the pause"
    assert served < SLOW_CHUNKS, "the whole body was delivered before the pause was honored"


# -- browser -----------------------------------------------------------------

browser_only = pytest.mark.skipif(not browser_available(), reason="playwright/chromium not installed")


@browser_only
def test_third_party_subresources_websocket_and_popup_are_never_contacted(engine, app_node, other_node):
    db, ev = engine
    scope = _scope(app_node.base)
    with BrowserCrawler(db, ev, scope, "eng_egress", max_pages=1, timeout_ms=8000) as crawler:
        result = crawler.crawl(f"{app_node.base}/hostile?base={other_node.base}")
    page = [p for p in result["pages"] if "/hostile" in p["url"]]
    assert page and page[0]["title"].startswith("rendered"), result["pages"]
    assert other_node.hits == [], f"a non-authorized origin was contacted: {other_node.hits}"
    assert "127.0.0.2" in str(result["egress"]["blocked_hosts"]), result["egress"]
    assert any("egress_blocked_third_party" in d for d in result["degraded"]), result["degraded"]
    assert _events(db, "egress_denied"), "blocked requests were not audited"


@browser_only
def test_browser_fetch_fallback_is_gated_too(engine, app_node, other_node):
    db, ev = engine
    probe = HttpProbe(db, ev)
    r = probe.browser_request("eng_egress", _scope(app_node.base),
                              f"{app_node.base}/hostile?base={other_node.base}")
    assert r["ok"] is True, r
    assert other_node.hits == []
    assert "rendered" in r["body"]


@browser_only
def test_popup_navigation_to_another_origin_is_refused(engine, app_node, other_node):
    db, ev = engine
    scope = _scope(app_node.base)

    with BrowserCrawler(db, ev, scope, "eng_egress", max_pages=1, timeout_ms=8000) as crawler:
        page = crawler._ctx.new_page()
        page.goto(app_node.base + "/ok", wait_until="domcontentloaded")
        page.evaluate(f"window.open('{other_node.base}/popup')")
        page.wait_for_timeout(1500)
        page.close()
    assert other_node.hits == [], f"popup left the policy: {other_node.hits}"


# -- scanner subprocesses ----------------------------------------------------

TOOL = """
import sys, urllib.request
mode, url = sys.argv[1], sys.argv[2]
try:
    if mode == "loop":
        for _ in range(200):
            try:
                urllib.request.urlopen(url, timeout=5).read()
            except Exception:
                pass
        sys.exit(0)
    print(urllib.request.urlopen(url, timeout=5).status)
except Exception as e:
    print("ERR", type(e).__name__, e)
    sys.exit(3)
"""


@pytest.fixture
def fake_tool(tmp_path):
    p = tmp_path / "fake_tool.py"
    p.write_text(TOOL)
    return str(p)


def _spec(fake_tool, mode, url):
    return ToolSpec(name="fake_http", description="", category="recon", binary=None, timeout_s=30,
                    params={"target": {"type": "string"}}, required=["target"],
                    handler=lambda p, d: [sys.executable, fake_tool, mode, url])


@pytest.fixture
def runner(engine, tmp_path):
    return ToolRunner(engine[0], engine[1], tmp_path / "runs")


def test_scanner_traffic_goes_through_the_policy_proxy(runner, fake_tool, app_node):
    scope = _scope(app_node.base)
    r = runner.run(_spec(fake_tool, "once", app_node.base + "/ok"),
                   {"target": app_node.base}, scope, "eng_egress", None,
                   target=app_node.base, category="recon")
    assert r["ok"] is True, r
    assert r["egress"]["level"] == "proxy" and r["egress"]["proxy"]
    hits = [h for h in app_node.hits if h[0] == "/ok"]
    assert hits and hits[0][1] == "1.1 libella-egress", f"request bypassed the proxy: {app_node.hits}"


def test_scanner_cannot_dial_an_unauthorized_host(runner, fake_tool, app_node, other_node, engine):
    """The declared target is authorized; the tool tries a different host anyway."""
    scope = _scope(app_node.base)
    r = runner.run(_spec(fake_tool, "once", other_node.base + "/steal"),
                   {"target": app_node.base}, scope, "eng_egress", None,
                   target=app_node.base, category="recon")
    assert other_node.hits == [], f"the subprocess reached a non-authorized host: {other_node.hits}"
    assert r["egress"]["denied_requests"] >= 1, r.get("egress")
    denied = _events(engine[0], "egress_denied")
    assert any("127.0.0.2" in d for d in denied), denied


def test_raw_socket_tool_is_marked_unconfined_not_trusted(runner, fake_tool, app_node, engine):
    spec = ToolSpec(name="nmap", description="", category="infra", binary=None, timeout_s=30,
                    params={"target": {"type": "string"}}, required=["target"],
                    handler=lambda p, d: [sys.executable, fake_tool, "once", app_node.base + "/ok"])
    r = runner.run(spec, {"target": "127.0.0.1"}, Scope(
        {"targets": [{"kind": "url", "value": app_node.base}], "categories": ["infra"]}),
        "eng_egress", None, target="127.0.0.1", category="infra")
    assert r["egress"]["level"] == "unconfined", r["egress"]
    assert r["egress"]["residual"], "an unconfined tool must state its residual"
    degradation = _events(engine[0], "egress_degradation")
    assert any("egress_unconfined" in d for d in degradation), degradation


def test_cancel_mid_run_stops_proxied_traffic(runner, fake_tool, app_node, engine):
    db = engine[0]
    scope = _scope(app_node.base)
    result = {}

    def run():
        result.update(runner.run(_spec(fake_tool, "loop", app_node.base + "/slow?x=1"),
                                 {"target": app_node.base}, scope, "eng_egress", None,
                                 target=app_node.base, category="recon"))

    t = threading.Thread(target=run)
    t.start()
    for _ in range(200):
        if len(app_node.hits) >= 2:
            break
        time.sleep(0.02)
    db.execute("UPDATE engagements SET status='cancelled' WHERE id='eng_egress'")
    t.join(20)
    assert not t.is_alive(), "a cancelled engagement left the tool running"
    seen = len(app_node.hits)
    time.sleep(0.5)
    assert len(app_node.hits) == seen, "traffic continued after the cancel"
    assert result["cancelled"] is True, result
