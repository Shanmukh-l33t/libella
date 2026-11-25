"""A report must not omit a coverage limitation it knows about.

An engagement where nuclei is not installed skipped a whole phase, and the report said
nothing: only the Coverage page reflected it, so a reader of the report saw a complete
assessment. The report is the artifact that leaves the building, so a missing tool is
stated there as a gap, explicitly not as a pass.
"""
import json
import time

from libella.report import render_report


def _engagement(app, eid: str):
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at, started_at, finished_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (eid, eid, "safe_active", "done",
         json.dumps({"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
                     "categories": ["recon", "web"], "rate_limit_rps": 20}),
         "{}", "{}", time.time(), time.time(), time.time()))


def _missing_tool_call(app, eid: str, tool: str):
    app.db.execute(
        "INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
        "scope_decision, exit_code, duration_ms, artifact_id, error, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (f"tc_{tool}", eid, None, tool, "[]", "http://127.0.0.1:8801", "allowed",
         None, 3.0, None, f"missing_tool: {tool} not found on this host", time.time()))


def test_a_missing_tool_is_a_stated_coverage_limitation(app):
    eid = "eng_missing"
    _engagement(app, eid)
    _missing_tool_call(app, eid, "nuclei")

    out = render_report(app.db, app.evidence, eid)
    md = open(f"{out['outdir']}/report.md").read()

    assert "Coverage limitations" in md, md[:800]
    assert "missing_tool" in md
    assert "nuclei" in md
    # the wording must not let a reader see it as tested and clean
    assert "never ran" in md


def test_a_complete_engagement_states_no_missing_tool(app):
    eid = "eng_full"
    _engagement(app, eid)
    app.db.execute(
        "INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
        "scope_decision, exit_code, duration_ms, artifact_id, error, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("tc_ok", eid, None, "nuclei", "[]", "http://127.0.0.1:8801", "allowed",
         0, 12.0, None, None, time.time()))
    out = render_report(app.db, app.evidence, eid)
    md = open(f"{out['outdir']}/report.md").read()
    assert "missing_tool" not in md
