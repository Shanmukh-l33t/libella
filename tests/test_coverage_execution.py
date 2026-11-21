"""Execution-derived WSTG coverage: statuses come from what the engagement ran.

Each test seeds the same tables the orchestrator writes (tool_calls, intents,
exchanges, degradations, findings) and asserts the derived status. The point of
these tests is honesty: a policy skip is not a failure, a timeout is not a pass,
and a manual review never hides what executed.
"""
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from libella import check_mapping, coverage, standards  # noqa: E402
from libella.api import App, create_api  # noqa: E402
from libella.report import render_report  # noqa: E402

WEB_SCOPE = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
             "categories": ["web"], "rate_limit_rps": 20}


def _app(tmp_path, categories=("web",), profile="safe_active"):
    app = App(tmp_path / "data")
    scope = {**WEB_SCOPE, "categories": list(categories)}
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng_x", "exec", profile, "draft", json.dumps(scope), "{}", "{}", time.time()))
    return app


@pytest.fixture
def app(tmp_path):
    return _app(tmp_path)


@pytest.fixture
def client(app):
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    return c


def intent(app, iid, role, status="done"):
    app.db.execute(
        "INSERT INTO intents(id, engagement_id, role, objective, status, created_at) "
        "VALUES(?,?,?,?,?,?)", (iid, "eng_x", role, f"{role} run", status, time.time()))
    return iid


def call(app, cid, tool, decision="executed: ok", error=None, exit_code=0):
    app.db.execute(
        "INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
        "scope_decision, exit_code, error, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (cid, "eng_x", None, tool, "[]", "http://127.0.0.1:8801", decision, exit_code,
         error, time.time()))
    return cid


def exchange(app, eid, tool):
    app.db.execute(
        "INSERT INTO exchanges(id, engagement_id, method, url, status, tool, created_at) "
        "VALUES(?,?,?,?,?,?,?)", (eid, "eng_x", "GET", "http://127.0.0.1:8801/", 200,
                                  tool, time.time()))
    return eid


def degradation(app, code, **payload):
    app.db.emit("eng_x", "degradation", {"code": code, **payload})


def finding(app, fid, cwe, state, title="x"):
    app.db.execute(
        "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
        "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (fid, "eng_x", title, cwe, "high", "high", state, time.time(), time.time()))
    return fid


def item(ws, test_id):
    return next(t for c in ws["categories"] for t in c["tests"] if t["id"] == test_id)


def test_mapping_covers_the_engine_surface_and_stays_bounded():
    assert check_mapping.TESTS  # mapping is non-empty
    assert "WSTG-INPV-05" in check_mapping.TESTS


def test_mapping_only_claims_tests_the_check_executes():
    # every mapped unit must justify every ID with a rationale and a real unit name
    for unit, row in check_mapping.CHECKS.items():
        assert row["why"] and len(row["why"]) > 20
        assert all(t in standards.spec("wstg")["requirements"] for t in row["wstg"]), unit
    # untested surfaces are absent, not assumed
    assert "WSTG-CLNT-08" not in check_mapping.TESTS
    assert "WSTG-INPV-05" in check_mapping.tests_for("sqli")
    # a union row equals the union of its members
    assert set(check_mapping.tests_for("web_checks")) >= set(
        check_mapping.tests_for("reflected_xss")) | set(check_mapping.tests_for("auth_bypass"))


def test_catalog_totals_still_add_up(app):
    ws = coverage.workspace(app.db, "eng_x")
    s = ws["summary"]
    assert s["total"] == 96
    assert sum(s["statuses"].values()) == 96
    assert s["applicable"] == 96
    assert s["supported"] == len(check_mapping.TESTS)
    assert s["not_tested"] == s["applicable"] - s["completed"]


def test_completed_check_reports_completed_no_issue(app):
    intent(app, "i_web", "web_checks")
    exchange(app, "ex_hdr", "headers_check")
    ws = coverage.workspace(app.db, "eng_x")
    it = item(ws, "WSTG-CONF-07")
    assert it["automatic"]["status"] == "completed_no_issue"
    assert "ex_hdr" in it["evidence"]["exchanges"]
    assert "i_web" in it["evidence"]["intents"]
    assert ws["summary"]["completed"] >= 1


def test_passive_engagement_skips_active_checks_instead_of_failing(tmp_path):
    app = _app(tmp_path, profile="passive")
    intent(app, "i_web", "web_checks")
    degradation(app, "policy_restriction", unit="sqli, ssti", profile="passive")
    exchange(app, "ex_hdr", "headers_check")
    ws = coverage.workspace(app.db, "eng_x")
    sqli = item(ws, "WSTG-INPV-05")
    assert sqli["automatic"]["status"] == "skipped_policy"
    assert "passive" in sqli["automatic"]["reason"]
    assert sqli["automatic"]["status"] != "failed"
    # the passive half that did run is still credited
    assert item(ws, "WSTG-CONF-07")["automatic"]["status"] == "completed_no_issue"
    assert ws["summary"]["skipped"] >= 2


def test_missing_binary_is_a_dependency_skip(app):
    call(app, "tc_nuclei", "nuclei", decision="refused: missing binary",
         error="missing_tool: nuclei not installed", exit_code=None)
    ws = coverage.workspace(app.db, "eng_x")
    it = item(ws, "WSTG-CONF-02")
    assert it["automatic"]["status"] == "skipped_dependency"
    assert "tc_nuclei" in it["evidence"]["tool_calls"]


def test_timeout_is_inconclusive_not_a_pass(app):
    call(app, "tc_nuclei", "nuclei", decision="executed: timeout", error="timeout",
         exit_code=None)
    ws = coverage.workspace(app.db, "eng_x")
    it = item(ws, "WSTG-CONF-04")
    assert it["automatic"]["status"] == "inconclusive"
    assert ws["summary"]["completed"] == sum(
        n for s, n in ws["summary"]["statuses"].items()
        if s in ("completed_no_issue", "finding_unverified", "finding_verified"))


def test_failed_tool_call_is_failed(app):
    call(app, "tc_ffuf", "ffuf", decision="executed: failed", error="failed", exit_code=2)
    it = item(coverage.workspace(app.db, "eng_x"), "WSTG-CONF-05")
    assert it["automatic"]["status"] == "failed"


def produced(app, fid, cwe, state, tool, controls=()):
    """A finding bound to evidence a named check captured, as the pipeline writes it."""
    ev = f"ev_{fid}"
    app.db.execute(
        "INSERT INTO evidence(id, engagement_id, sha256, kind, path, bytes, created_at, "
        "prev_hash, chain_hash) VALUES(?,?,?,?,?,?,?,?,?)",
        (ev, "eng_x", "x" * 64, "http", "blob/" + ev, 1, time.time(), "p", "c"))
    app.db.execute(
        "INSERT INTO exchanges(id, engagement_id, evidence_id, method, url, status, tool, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (f"ex_{fid}", "eng_x", ev, "GET", "http://127.0.0.1:8801/", 200, tool, time.time()))
    app.db.execute(
        "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
        "evidence_ids_json, controls_json, controls_source, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (fid, "eng_x", "x", cwe, "high", "high", state, json.dumps([ev]),
         json.dumps(list(controls)), "check" if controls else "none", time.time(), time.time()))
    return fid


def test_findings_upgrade_status_and_keep_verification_honest(app):
    produced(app, "f_verified", "CWE-79", "validated", "xss_check")
    produced(app, "f_suspected", "CWE-89", "suspected", "sqli_check")
    ws = coverage.workspace(app.db, "eng_x")
    xss = item(ws, "WSTG-INPV-01")
    sqli = item(ws, "WSTG-INPV-05")
    assert xss["automatic"]["status"] == "finding_verified"
    assert xss["evidence"]["findings"] == ["f_verified"]
    assert sqli["automatic"]["status"] == "finding_unverified"
    # a SQL injection found by the parameter probe is NOT authentication-bypass
    # evidence, even though both checks emit CWE-89: attribution follows the producer
    assert "f_suspected" not in item(ws, "WSTG-ATHN-04")["evidence"]["findings"]
    assert ws["summary"]["with_findings"] == 2
    # CWE-79 must not leak onto SQL injection coverage
    assert "f_verified" not in sqli["evidence"]["findings"]


def test_a_finding_without_a_recoverable_producer_is_never_auto_attributed(app):
    finding(app, "f_orphan", "CWE-79", "validated")  # no evidence trail at all
    ws = coverage.workspace(app.db, "eng_x")
    assert "f_orphan" not in item(ws, "WSTG-INPV-01")["evidence"]["findings"]
    orphan = [f for f in ws["unattributed_findings"] if f["id"] == "f_orphan"]
    assert orphan and "no producing check" in orphan[0]["reason"]


def test_planned_but_unrun_check_is_inconclusive(app):
    intent(app, "i_api", "api_audit", status="open")
    it = item(coverage.workspace(app.db, "eng_x"), "WSTG-ATHZ-04")
    assert it["automatic"]["status"] in ("attempted", "inconclusive")


def test_non_web_scope_makes_the_web_framework_not_applicable(tmp_path):
    app = _app(tmp_path, categories=("code",))
    ws = coverage.workspace(app.db, "eng_x")
    assert ws["summary"]["applicable"] == 0
    assert {t["automatic"]["status"] for c in ws["categories"] for t in c["tests"]} == {
        "not_applicable"}


def test_manual_entry_and_automatic_status_stay_both_visible(app):
    exchange(app, "ex_hdr", "headers_check")
    ev = app.evidence.put("eng_x", b'{"a":1}', "note")
    ws = coverage.record(app.db, "eng_x", "WSTG-CONF-07", "covered", "checked by hand",
                         ev["id"])
    it = item(ws, "WSTG-CONF-07")
    assert it["status"] == "covered"
    assert it["manual"]["note"] == "checked by hand"
    assert it["automatic"]["status"] == "completed_no_issue"
    assert ws["summary"]["manual"]["covered"] == 1


def test_unsupported_and_manual_are_distinct_denominators(app):
    ws = coverage.workspace(app.db, "eng_x")
    assert item(ws, "WSTG-CONF-09")["automatic"]["status"] == "not_supported"
    assert item(ws, "WSTG-BUSL-06")["automatic"]["status"] == "requires_manual"
    assert ws["summary"]["manual_required"] >= 1


def test_api_exposes_automatic_status_and_evidence_pointers(client, app):
    intent(app, "i_web", "web_checks")
    exchange(app, "ex_xss", "xss_check")
    r = client.get("/api/engagements/eng_x/coverage/wstg")
    assert r.status_code == 200
    it = item(r.json(), "WSTG-INPV-01")
    assert it["automatic"]["status"] == "completed_no_issue"
    assert it["evidence"]["exchanges"] == ["ex_xss"]


def test_report_has_coverage_summary_and_not_tested_list(app):
    exchange(app, "ex_hdr", "headers_check")
    out = render_report(app.db, app.evidence, "eng_x", app.data_dir / "report")
    doc = json.loads((Path(out["outdir"]) / "report.json").read_text())
    cov = doc["coverage"]
    assert cov["summary"]["total"] == 96
    assert cov["summary"]["completed"] >= 1
    assert any(t["id"] == "WSTG-BUSL-06" for t in cov["not_tested"])
    assert all(t["id"] != "WSTG-CONF-07" for t in cov["not_tested"])
    md = (Path(out["outdir"]) / "report.md").read_text()
    assert "## WSTG 4.2 coverage" in md
    assert "not tested" in md.lower()
