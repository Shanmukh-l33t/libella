"""Operations workspace state contracts found by benchmarks/acceptance_operations.py.

1. A tool that never ran (missing binary, bad argv) is "not run", not a scope refusal:
   the report summary must not count it as "blocked before egress".
2. The browser rebuilds the activity feed from the persisted event log by cursor, so the
   endpoint must return every kind with created_at and page at 500 without gaps or repeats.
"""
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from libella.api import App, create_api  # noqa: E402
from libella.report import render_report  # noqa: E402


@pytest.fixture
def app(tmp_path):
    app = App(tmp_path / "data")
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
             "categories": ["web"], "rate_limit_rps": 20}
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng_x", "ops", "safe_active", "running", json.dumps(scope), "{}", "{}", time.time()))
    return app


def _call(app, cid, tool, decision):
    app.db.execute(
        "INSERT INTO tool_calls(id, engagement_id, tool, argv_json, target, scope_decision, "
        "created_at) VALUES(?,?,?,?,?,?,?)",
        (cid, "eng_x", tool, "[]", "http://127.0.0.1:8801", decision, time.time()))


def test_report_counts_only_scope_refusals(app):
    _call(app, "tc_1", "httpx", "executed: ok")
    _call(app, "tc_2", "nuclei", "refused: missing binary")
    _call(app, "tc_3", "ffuf", "refused: argv build error: boom")
    _call(app, "tc_4", "nmap", "refused: 10.0.0.9 not in engagement scope")
    summary = json.loads((Path(render_report(app.db, app.evidence, "eng_x")["outdir"])
                          / "report.json").read_text())["summary"]
    assert summary["tool_calls"] == 4 and summary["scope_refusals"] == 1


def test_event_log_pages_without_gaps_for_cursor_catch_up(app):
    kinds = ["intent_created", "egress_denied", "scan_profile", "investigation_step", "degradation"]
    for n in range(620):
        app.db.emit("eng_x", kinds[n % len(kinds)], {"n": n})
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    got, cursor = [], 0
    while True:
        rows = c.get("/api/engagements/eng_x/events", params={"since": cursor}).json()
        got += rows
        if len(rows) < 500:
            break
        cursor = rows[-1]["seq"]
    assert [r["payload"]["n"] for r in got] == list(range(620))
    assert all(r["created_at"] for r in got) and {r["kind"] for r in got} == set(kinds)


def test_client_feed_is_cursor_filled_from_the_event_log():
    src = (ROOT / "web/src/pages/Engagement.tsx").read_text()
    assert "events?since=${last}" in src and "feed.current.set(seq" not in src
