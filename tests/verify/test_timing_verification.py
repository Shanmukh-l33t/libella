"""A timing claim is verified by replaying time, not by finding a string in a body.

Blind command injection quotes a measurement (`"duration_ms": N`), which no response body
ever contains, so the string comparator returned not_reproduced for a genuine finding and
the CWE-78 contract could never reach validated. The contract is now checked by replaying
the payload AND the benign control in the same verification run and comparing the two.

Both directions are asserted: a target that really delays for the payload validates, and a
target that is uniformly slow -- or uniformly fast -- does not.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from libella.verifier import TIMING_FLOOR_MS, TIMING_FACTOR

PAYLOAD = "127.0.0.1;sleep 2"
BENIGN = "127.0.0.1"


class Lab:
    """Serves /run?host=..., sleeping per the mode selected by the test."""

    def __init__(self, tmp_path):
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib signature
                if "host=" in self.path and ";sleep" in self.path:
                    if lab.mode in ("vulnerable", "always_slow"):
                        time.sleep(lab.delay)
                payload = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):  # noqa: A002 - stdlib signature
                pass

        self.mode = "vulnerable"
        self.delay = 2.0
        # ThreadingHTTPServer so the control replay is not queued behind the slow request
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_port}"

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def env(tmp_path):
    from libella.api import App
    from libella.scope import Scope

    lab = Lab(tmp_path)
    app = App(tmp_path / "data")
    scope = Scope({"targets": [{"kind": "url", "value": lab.base}],
                   "categories": ["web"], "rate_limit_rps": 1000})
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng", "timing", "safe_active", "running", __import__("json").dumps(scope.spec),
         "{}", "{}", time.time()))
    yield {"app": app, "scope": scope, "lab": lab}
    lab.close()
    app.db.close()


def _timing_finding(env, *, payload_url, benign_url, declare_signal=True):
    """Submit a CWE-78 candidate whose quote is a duration, as the audit does."""
    app = env["app"]
    r = app.probe.request("eng", env["scope"], payload_url, tool="injection_cmd_probe")
    assert r["ok"]
    ms = app.db.one("SELECT duration_ms FROM exchanges WHERE id=?", (r["exchange_id"],))
    proof = {"benign_request": {"url": benign_url}}
    if declare_signal:
        proof["signal"] = "timing"
    return app.pipeline.submit_candidate("eng", {
        "title": "OS command injection: blind time-based delay", "cwe": "CWE-78",
        "severity": "critical", "endpoint": payload_url,
        "evidence_ids": [r["evidence_id"]],
        "quote": f'"duration_ms": {ms["duration_ms"]}', "quote_in": "duration_ms",
        "proof_request": {"method": "GET", "url": payload_url},
        "dedup_key": f"cmd:{payload_url}", "proof": proof,
    })["id"]


def test_a_real_delay_validates(env):
    """Positive twin: the payload is slower than the control by the required margin."""
    vuln = env["lab"].base + "/run?host=" + PAYLOAD.replace(" ", "%20")
    benign = env["lab"].base + "/run?host=" + BENIGN
    fid = _timing_finding(env, payload_url=vuln, benign_url=benign)
    out = env["app"].verifier.verify("eng", env["scope"], fid)
    assert out["verdict"] == "reproduced", out
    assert env["app"].db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"] == "validated"


def test_a_uniformly_slow_target_does_not_validate(env):
    """Negative control: a slow box is not a slow query; both requests take 2s."""
    env["lab"].mode = "always_slow"
    vuln = env["lab"].base + "/run?host=" + PAYLOAD.replace(" ", "%20") + "&slow=1"
    benign = env["lab"].base + "/run?host=" + BENIGN + "&slow=1"
    # make the control slow too by labelling it with the same marker the handler checks
    benign = env["lab"].base + "/run?host=" + BENIGN + "&slow=1;sleep"
    fid = _timing_finding(env, payload_url=vuln, benign_url=benign)
    out = env["app"].verifier.verify("eng", env["scope"], fid)
    assert out["verdict"] == "not_reproduced", out


def test_no_benign_control_is_refused_by_the_contract(env):
    """A delay with no recorded control cannot be attributed to the payload.

    The contract refuses it before any replay: the guard inside the timing path is a
    second line of defence and is covered by the contract, so this asserts the refusal
    and its reason rather than a specific internal branch.
    """
    vuln = env["lab"].base + "/run?host=" + PAYLOAD.replace(" ", "%20")
    r = env["app"].probe.request("eng", env["scope"], vuln, tool="probe")
    fid = env["app"].pipeline.submit_candidate("eng", {
        "title": "OS command injection: blind time-based delay", "cwe": "CWE-78",
        "severity": "critical", "endpoint": vuln, "evidence_ids": [r["evidence_id"]],
        "quote": '"duration_ms": 2000', "quote_in": "duration_ms",
        "proof_request": {"method": "GET", "url": vuln}, "dedup_key": "cmd:nocontrol",
        "proof": {"signal": "timing"},  # no benign_request
    })["id"]
    out = env["app"].verifier.verify("eng", env["scope"], fid)
    assert out["verdict"] == "unsupported", out
    assert "benign control" in out["detail"] or "benign_request" in out["detail"], out
    assert env["app"].db.one("SELECT state FROM findings WHERE id=?", (fid,))["state"] != "validated"


def test_a_fast_server_with_a_proportional_delay_still_needs_the_floor(env):
    """20ms baseline, 100ms payload: 5x faster-looking but under the absolute floor.

    Without the floor a relative comparison alone calls this injection on any server that
    answers in microseconds, which is most of them.
    """
    env["lab"].delay = 0.10
    vuln = env["lab"].base + "/run?host=" + PAYLOAD.replace(" ", "%20")
    benign = env["lab"].base + "/run?host=" + BENIGN
    fid = _timing_finding(env, payload_url=vuln, benign_url=benign)
    out = env["app"].verifier.verify("eng", env["scope"], fid)
    assert out["verdict"] == "not_reproduced", out
    assert "threshold" in out["detail"], out


def test_a_control_that_also_delays_refuses_the_claim(env):
    """If the benign value is slow too, the delay is not evidence of injection."""
    env["lab"].mode = "always_slow"
    vuln = env["lab"].base + "/run?host=" + PAYLOAD.replace(" ", "%20")
    # the control carries the same marker the handler delays on
    benign = env["lab"].base + "/run?host=" + BENIGN + ";sleep"
    fid = _timing_finding(env, payload_url=vuln, benign_url=benign)
    out = env["app"].verifier.verify("eng", env["scope"], fid)
    assert out["verdict"] == "not_reproduced", out


def test_the_threshold_is_both_relative_and_absolute():
    """Neither a fast server nor a loaded one may flip the verdict on its own."""
    assert TIMING_FACTOR >= 2.0 and TIMING_FLOOR_MS >= 1000
    # 40ms baseline: relative factor alone would accept 130ms, the floor forbids it
    assert max(40 * TIMING_FACTOR, 40 + TIMING_FLOOR_MS) > 130
