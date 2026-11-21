"""Execution controls: window, concurrency, declared rates, cancellation, budgets.

Every fix here *restricts* execution. The tests assert the ceiling holds even when
no model is in the loop, and that refusals are recorded rather than silent.
Localhost only; no external egress.
"""
import json
import threading
import time

import pytest
from flask import Flask, request
from werkzeug.serving import make_server

from libella.api import App
from libella.orchestrator import ConcurrencyGate, window_state
from libella.policy import PROFILES, permits
from libella.scope import Scope
from libella.tools import ToolSpec
from libella.tools.runner import ToolRunner


LAB_SEEN: list[str] = []  # paths that actually reached the target in the lab fixture


@pytest.fixture
def lab():
    LAB_SEEN.clear()
    app = Flask("exec-controls-lab")

    @app.get("/")
    def index():
        LAB_SEEN.append("/")
        return "<html><body>home</body></html>"

    @app.get("/search")
    def search():
        LAB_SEEN.append("/search")
        return f"<html><body>Results: {request.args.get('q', '')}</body></html>"

    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def app(tmp_path):
    return App(tmp_path / "data")


def _spec(lab, **over):
    spec = {"targets": [{"kind": "url", "value": lab}],
            "categories": ["recon", "web", "api", "infra"], "rate_limit_rps": 1000}
    spec.update(over)
    return spec


def _eng(app, scope_spec, profile="safe_active", budgets=None, window=(None, None),
         status="draft"):
    eid = f"eng_{time.time_ns()}"
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
        "budgets_json, objectives_json, window_start, window_end, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (eid, "exec controls", profile, status, json.dumps(scope_spec), "{}",
         json.dumps(budgets or {}), "[]", window[0], window[1], time.time()))
    return eid


def _row(app, eid):
    return app.db.one("SELECT * FROM engagements WHERE id=?", (eid,))


def _degradations(app, eid):
    return [json.loads(r["payload_json"]) for r in app.db.query(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind='degradation'", (eid,))]


def _events(app, eid, kind):
    return [json.loads(r["payload_json"]) for r in app.db.query(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind=?", (eid, kind))]


# ---- 1. the authorized time window is enforced ----

def test_window_state_allows_inside_the_window():
    now = time.time()
    ok, detail = window_state({"window_start": now - 60, "window_end": now + 60}, now=now)
    assert ok, detail


def test_window_state_refuses_before_it_opens():
    now = time.time()
    ok, detail = window_state({"window_start": now + 3600, "window_end": None}, now=now)
    assert not ok and "window_start" in detail


def test_window_state_refuses_after_it_closes():
    now = time.time()
    ok, detail = window_state({"window_start": now - 7200, "window_end": now - 60}, now=now)
    assert not ok and "window_end" in detail


def test_window_state_parses_iso8601_and_epoch_strings():
    now = time.time()
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 60))
    assert window_state({"window_start": iso, "window_end": None}, now=now)[0]
    assert window_state({"window_start": None, "window_end": str(int(now + 60))}, now=now)[0]
    assert window_state({}, now=now)[0]  # no window declared means unrestricted


def test_malformed_window_fails_closed():
    with pytest.raises(ValueError):
        window_state({"window_start": "not-a-timestamp"}, now=time.time())


def test_start_is_refused_before_the_window_opens(app, lab):
    now = time.time()
    eid = _eng(app, _spec(lab), window=(now + 3600, now + 7200))
    app.orchestrator().start(eid, "deterministic")
    row = _row(app, eid)
    assert row["status"] == "failed", row
    assert "window" in (row["status_detail"] or "").lower(), row["status_detail"]
    assert started_events(app, eid) == []
    assert app.db.one("SELECT COUNT(*) n FROM intents WHERE engagement_id=?", (eid,))["n"] == 0


def started_events(app, eid):
    return _events(app, eid, "engagement_started")


def test_malformed_window_refuses_the_start(app, lab):
    eid = _eng(app, _spec(lab), window=("whenever", None))
    app.orchestrator().start(eid, "deterministic")
    row = _row(app, eid)
    assert row["status"] == "failed"
    assert "window" in (row["status_detail"] or "").lower(), row["status_detail"]


def test_start_inside_the_window_runs(app, lab):
    now = time.time()
    # recon-only, closed loopback port: proves the window gate admits the run cheaply
    cheap = {"targets": [{"kind": "url", "value": "http://127.0.0.1:9/"}],
             "categories": ["recon"], "rate_limit_rps": 1000}
    eid = _eng(app, cheap, window=(now - 60, now + 3600))
    app.orchestrator().start(eid, "deterministic")
    row = _row(app, eid)
    assert row["status"] == "done", row["status_detail"]
    assert row["started_at"] and "window" not in (row["status_detail"] or "").lower()


def test_run_loop_stops_when_the_window_has_closed(app, lab):
    now = time.time()
    eid = _eng(app, _spec(lab), window=(now - 7200, now - 60), status="running")
    app.db.execute("INSERT INTO intents(id, engagement_id, role, objective, status, created_at) "
                   "VALUES('i_open', ?, 'recon', 'Fingerprint', 'open', ?)", (eid, now))
    eng = _row(app, eid)
    app.orchestrator()._run_loop(eid, Scope(json.loads(eng["scope_json"])), eng, "deterministic")
    row = _row(app, eid)
    assert row["status"] == "window_closed", row
    assert "window_end" in (row["status_detail"] or "")
    assert app.db.one("SELECT status FROM intents WHERE id='i_open'")["status"] == "open"


def test_closed_window_never_replays_for_verification(app, lab, monkeypatch):
    """Once the authorized window has passed, finishing may report but not touch the target."""
    now = time.time()
    eid = _eng(app, _spec(lab), window=(now - 7200, now - 60), status="running")
    app.db.execute(
        "INSERT INTO findings(id, engagement_id, title, severity, confidence, state, "
        "evidence_ids_json, created_at, updated_at) VALUES('f_open', ?, 'candidate', 'low', "
        "'low', 'suspected', '[]', ?, ?)", (eid, now, now))
    orch = app.orchestrator()
    calls = []
    monkeypatch.setattr(orch.verifier, "verify", lambda *a, **k: calls.append(a))
    eng = _row(app, eid)
    orch._run_loop(eid, Scope(json.loads(eng["scope_json"])), eng, "deterministic")
    assert _row(app, eid)["status"] == "window_closed"
    assert calls == []
    assert any(d.get("code") == "verification_skipped_window_closed" for d in _degradations(app, eid))


# ---- 2. max_concurrency is a real ceiling ----

def test_concurrency_gate_never_exceeds_its_limit():
    gate = ConcurrencyGate(2)
    lock = threading.Lock()
    active = peak = 0

    def work():
        nonlocal active, peak
        with gate.slot():
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.05)
            with lock:
                active -= 1

    threads = [threading.Thread(target=work) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert peak <= 2, f"{peak} concurrent executors exceeded max_concurrency 2"
    assert peak == 2, "the gate serialized everything instead of bounding it"


def test_orchestrator_gate_uses_scope_max_concurrency(app, lab):
    scope = Scope(_spec(lab, max_concurrency=3))
    assert app.orchestrator()._gate_for(scope).limit == 3


# ---- 3. declared rates, bounded for nmap, shared with the probe ----

class CapturingRunner:
    """Stands in for the tool runner: records the params the orchestrator sent."""

    def __init__(self):
        self.calls = []

    def run(self, spec, params, *a, **k):
        self.calls.append((spec.name, dict(params)))
        return {"ok": False, "error": "captured", "call_id": "tc_captured"}


def _bare_orchestrator(app):
    orch = app.orchestrator()
    orch.runner = CapturingRunner()
    return orch


def test_nuclei_receives_the_declared_rate_not_five_times_it(app, lab):
    scope = Scope(_spec(lab, rate_limit_rps=7))
    eid = _eng(app, _spec(lab, rate_limit_rps=7))
    orch = _bare_orchestrator(app)
    orch._do_nuclei(eid, scope, f"Template scan {lab}", "i1")
    (name, params), = orch.runner.calls
    assert name == "nuclei" and params["rate_limit"] == 7, params


def test_nmap_is_bounded_by_the_declared_rate(app, lab):
    scope = Scope(_spec(lab, rate_limit_rps=7))
    eid = _eng(app, _spec(lab, rate_limit_rps=7))
    orch = _bare_orchestrator(app)
    orch._do_infra(eid, scope, f"TLS and service audit {lab}", "i1")
    (name, params), = orch.runner.calls
    assert name == "nmap" and params["rate_limit"] == 7, params


def test_nmap_rate_is_capped_conservatively(app, lab):
    from libella.tools.adapters import NMAP_MAX_RATE, _nmap_argv

    scope = Scope(_spec(lab, rate_limit_rps=10000))
    eid = _eng(app, _spec(lab, rate_limit_rps=10000))
    orch = _bare_orchestrator(app)
    orch._do_infra(eid, scope, f"TLS and service audit {lab}", "i1")
    (_, params), = orch.runner.calls
    assert params["rate_limit"] == NMAP_MAX_RATE
    argv = _nmap_argv({"target": "127.0.0.1", "rate_limit": params["rate_limit"]},
                      type("D", (), {"resolved_ips": ["127.0.0.1"]})())
    assert argv[argv.index("--max-rate") + 1] == str(NMAP_MAX_RATE)


def test_run_consults_the_rate_gate_before_launching_a_tool(app, lab):
    waits = []
    seen = []

    class _Limiter:
        def wait(self):
            waits.append(time.time())

    def limiter(engagement_id, rps):
        seen.append((engagement_id, rps))
        return _Limiter()

    runner = ToolRunner(app.db, app.evidence, app.data_dir / "runs2", limiter=limiter)
    spec = ToolSpec(name="noop", description="", category="recon", binary="sh", timeout_s=10,
                    params={"target": {"type": "string"}}, required=["target"],
                    handler=lambda p, d: ["sh", "-c", "printf ok"])
    eid = _eng(app, _spec(lab, rate_limit_rps=5))
    r = runner.run(spec, {"target": "127.0.0.1"}, Scope(_spec(lab, rate_limit_rps=5)),
                   eid, None, target="127.0.0.1", category="recon")
    assert r["ok"], r
    assert seen == [(eid, 5)] and len(waits) == 1


def test_external_tools_share_the_probes_per_engagement_limiter(app, lab):
    """One limiter per engagement: probe requests and tool launches interleave."""
    orch = app.orchestrator()
    assert orch.runner.limiter is not None
    assert orch.runner.limiter("eng_shared", 5) is app.probe._limiter("eng_shared", 5)


# ---- 4. cancellation interrupts a running subprocess ----

def test_cancelling_the_engagement_kills_a_running_tool(app, lab):
    eid = _eng(app, _spec(lab), status="running")
    spec = ToolSpec(name="slow", description="", category="recon", binary="sh", timeout_s=120,
                    params={"target": {"type": "string"}}, required=["target"],
                    handler=lambda p, d: ["sh", "-c", "sleep 30"])
    result = {}

    def run():
        result.update(app.runner.run(spec, {"target": "127.0.0.1"}, Scope(_spec(lab)),
                                     eid, None, target="127.0.0.1", category="recon"))

    t = threading.Thread(target=run)
    started = time.time()
    t.start()
    time.sleep(0.4)
    app.orchestrator().cancel(eid)
    t.join(10)
    elapsed = time.time() - started
    assert not t.is_alive(), "cancelled engagement left the subprocess running"
    assert elapsed < 5, f"cancel took {elapsed:.1f}s"
    assert result["status"] == "cancelled", result


def test_pausing_stops_a_running_tool_and_the_probe(app, lab):
    """Pause is a control, not a label: it kills the tool and stops probe traffic."""
    eid = _eng(app, _spec(lab), status="running")
    spec = ToolSpec(name="slow", description="", category="recon", binary="sh", timeout_s=120,
                    params={"target": {"type": "string"}}, required=["target"],
                    handler=lambda p, d: ["sh", "-c", "sleep 30"])
    result = {}

    def run():
        result.update(app.runner.run(spec, {"target": "127.0.0.1"}, Scope(_spec(lab)),
                                     eid, None, target="127.0.0.1", category="recon"))

    t = threading.Thread(target=run)
    started = time.time()
    t.start()
    time.sleep(0.4)
    app.orchestrator().pause(eid)
    t.join(10)
    assert not t.is_alive(), "a paused engagement left the subprocess running"
    assert time.time() - started < 5
    assert result["status"] == "cancelled" and "paused" in result["stopped_by"], result

    r = app.probe.request(eid, Scope(_spec(lab)), f"{lab}/", category="recon")
    assert r["ok"] is False and "paused" in r["error"], r
    assert LAB_SEEN == [], "a paused engagement still sent a request to the target"


def test_cancelling_stops_the_probe_too(app, lab):
    eid = _eng(app, _spec(lab), status="running")
    app.orchestrator().cancel(eid)
    r = app.probe.request(eid, Scope(_spec(lab)), f"{lab}/", category="recon")
    assert r["ok"] is False and "cancelled" in r["error"], r
    assert LAB_SEEN == [], "a cancelled engagement still sent a request to the target"


def test_closed_window_kills_a_running_tool(app, lab):
    """A window that closes mid-tool ends the tool, not the tool's own timeout."""
    now = time.time()
    eid = _eng(app, _spec(lab), window=(now - 60, now + 0.6), status="running")
    spec = ToolSpec(name="slow", description="", category="recon", binary="sh", timeout_s=120,
                    params={"target": {"type": "string"}}, required=["target"],
                    handler=lambda p, d: ["sh", "-c", "sleep 30"])
    result = {}
    t = threading.Thread(target=lambda: result.update(
        app.runner.run(spec, {"target": "127.0.0.1"}, Scope(_spec(lab)), eid, None,
                       target="127.0.0.1", category="recon")))
    started = time.time()
    t.start()
    t.join(10)
    assert not t.is_alive(), "the tool outlived the authorized window"
    assert time.time() - started < 5
    assert "window_end" in result["stopped_by"], result


def test_pause_reopens_the_interrupted_intent(app, lab, monkeypatch):
    """A pause lands mid-intent: the step is re-opened for resume, not recorded as done."""
    eid = _eng(app, _spec(lab), status="running")
    app.db.execute("INSERT INTO intents(id, engagement_id, role, objective, status, created_at) "
                   "VALUES('i_open', ?, 'recon', 'Fingerprint', 'open', ?)", (eid, time.time()))
    orch = app.orchestrator()

    def paused_mid_step(*a, **k):
        app.db.execute("UPDATE engagements SET status='paused' WHERE id=?", (eid,))
        return "done", {"partial": True}

    monkeypatch.setattr(orch, "_execute", paused_mid_step)
    eng = _row(app, eid)
    orch._run_loop(eid, Scope(json.loads(eng["scope_json"])), eng, "deterministic")
    it = app.db.one("SELECT * FROM intents WHERE id='i_open'")
    assert it["status"] == "open" and it["result_json"] is None, it
    assert _row(app, eid)["status"] == "paused", _row(app, eid)["status"]


def test_tool_timeout_cap_is_kept(app, lab):
    eid = _eng(app, _spec(lab), status="running")
    spec = ToolSpec(name="sleepy", description="", category="recon", binary="sh", timeout_s=1,
                    params={"target": {"type": "string"}}, required=["target"],
                    handler=lambda p, d: ["sh", "-c", "sleep 20"])
    r = app.runner.run(spec, {"target": "127.0.0.1"}, Scope(_spec(lab)), eid, None,
                       target="127.0.0.1", category="recon")
    assert r["status"] == "timeout" and r["partial"] is True, r


# ---- 5. budgets are enforced by code, not by the agent ----

def test_duration_budget_stops_the_loop_without_any_model(app, lab):
    # a spent wall-clock budget: no intent may start, whatever an agent would like
    eid = _eng(app, _spec(lab), budgets={"max_duration_s": 0.0}, status="running")
    app.db.execute("INSERT INTO intents(id, engagement_id, role, objective, status, created_at) "
                   "VALUES('i_open', ?, 'recon', 'Fingerprint', 'open', ?)", (eid, time.time()))
    eng = _row(app, eid)
    app.orchestrator()._run_loop(eid, Scope(json.loads(eng["scope_json"])), eng, "deterministic")
    row = _row(app, eid)
    assert row["status"] == "budget_exhausted"
    assert row["status_detail"] == "max_duration_s reached"
    assert app.db.one("SELECT status FROM intents WHERE id='i_open'")["status"] == "open"


def test_usd_budget_stops_the_loop_without_asking_the_model(app, lab):
    class SpentLLM:
        asked = 0

        def spend(self, eid):
            return {"cost_usd": 99.0}

        def complete(self, *a, **k):
            SpentLLM.asked += 1
            raise AssertionError("the model must not be consulted to enforce a budget")

    eid = _eng(app, _spec(lab), budgets={"max_usd": 1.0}, status="running")
    app.db.execute("INSERT INTO intents(id, engagement_id, role, objective, status, created_at) "
                   "VALUES('i_open', ?, 'recon', 'Fingerprint', 'open', ?)", (eid, time.time()))
    orch = app.orchestrator()
    orch.llm = SpentLLM()
    eng = _row(app, eid)
    orch._run_loop(eid, Scope(json.loads(eng["scope_json"])), eng, "deterministic")
    row = _row(app, eid)
    assert row["status"] == "budget_exhausted" and row["status_detail"] == "max_usd reached"
    assert SpentLLM.asked == 0


# ---- 6. profile: production_safe is a stricter ceiling, nothing wider ----

def test_new_profiles_sit_between_the_existing_ones():
    assert PROFILES == ("passive", "production_safe", "safe_active", "advanced_validation")
    # production_safe: the read-only surface only
    assert permits("security_headers", "production_safe")
    assert permits("crawl", "production_safe")
    assert not permits("sqli", "production_safe")
    assert not permits("nuclei", "production_safe")
    # existing profiles keep their relative rank: advanced_validation is still widest
    assert permits("file_upload", "advanced_validation")
    assert not permits("file_upload", "passive")
    assert not permits("some_future_check", "advanced_validation")


def test_production_safe_execution_refuses_an_active_intent(app, lab):
    eid = _eng(app, _spec(lab), profile="production_safe")
    app.db.execute(
        "INSERT INTO intents(id, engagement_id, role, objective, status, created_at) "
        "VALUES('i_forced', ?, 'nuclei_scan', ?, 'running', ?)",
        (eid, f"Template scan {lab}", time.time()))
    eng = _row(app, eid)
    intent = app.db.one("SELECT * FROM intents WHERE id='i_forced'")
    status, result = app.orchestrator()._execute(
        eid, Scope(json.loads(eng["scope_json"])), eng, intent)
    assert status == "exhausted" and result["skipped"] == "policy_restriction"
    assert app.db.one("SELECT COUNT(*) n FROM tool_calls WHERE engagement_id=?", (eid,))["n"] == 0
    assert any(d["code"] == "policy_restriction" for d in _degradations(app, eid))


def test_api_accepts_production_safe_and_no_wider_profile(app):
    """api.py validates against policy.PROFILES dynamically: one stricter profile, nothing wider."""
    from fastapi.testclient import TestClient

    from libella.api import create_api

    client = TestClient(create_api(app))
    client.headers.update({"Authorization": f"Bearer {app.token}"})
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:9/"}],
             "categories": ["recon"]}
    ok = client.post("/api/engagements",
                     json={"name": "ps", "scope": scope, "profile": "production_safe"})
    assert ok.status_code == 200, ok.text
    bad = client.post("/api/engagements",
                      json={"name": "x", "scope": scope, "profile": "controlled_validation"})
    assert bad.status_code == 400 and "profile" in bad.json()["detail"]


def test_production_safe_plan_skips_active_work(app, lab):
    spec = _spec(lab)
    spec["targets"].append({"kind": "url", "value": "https://127.0.0.1:9/"})
    eid = _eng(app, spec, profile="production_safe")
    eng = _row(app, eid)
    orch = app.orchestrator()
    orch._plan_deterministic(eid, Scope(json.loads(eng["scope_json"])), eng)
    roles = {r["role"] for r in app.db.query(
        "SELECT role FROM intents WHERE engagement_id=?", (eid,))}
    assert {"recon", "crawl", "web_checks", "verify", "report"} <= roles
    assert "nuclei_scan" not in roles and "infra_scan" not in roles
    assert {d["unit"] for d in _degradations(app, eid)} >= {"nuclei_scan", "infra_scan"}
