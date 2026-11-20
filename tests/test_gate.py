"""Offline gate: fail on new verified high/critical, never on unknown coverage."""
import json
import os
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.gate import evaluate, main, normalize, write_junit
from libella.report import render_report

ROOT = Path(__file__).resolve().parents[1]

LOW = {"title": "Missing HSTS", "severity": "low", "state": "reported",
       "endpoint": "https://a.example/", "cwe": "CWE-319"}
HIGH = {"title": "Debug endpoint leaks config", "severity": "high", "state": "validated",
        "endpoint": "https://a.example/debug", "cwe": "CWE-200"}
CRITICAL = {"title": "SQL injection in category", "severity": "critical", "state": "validated",
            "endpoint": "https://a.example/api/products", "cwe": "CWE-89"}


def doc(findings=(), status="done", intents=2, done=2, blocked=0, degradations=(),
        total=None, confirmed=None, profile=None):
    eng = {"id": "eng", "status": status}
    if profile is not None:
        eng["profile"] = profile
    return {
        "engagement": eng,
        "summary": {"intents": intents, "intents_done": done, "intents_blocked": blocked,
                    "findings_total": len(findings) if total is None else total,
                    "confirmed": sum(f["state"] in {"validated", "reported", "retested_persists"}
                                     for f in findings) if confirmed is None else confirmed},
        "findings": list(findings),
        "degradations": [{"code": c, "detail": "x"} for c in degradations],
    }


def gate(baseline, current, policy="auto"):
    return evaluate(normalize(baseline) if baseline else None, normalize(current), policy)


def test_complete_passive_report_passes_and_lists_its_limitations():
    r = gate(None, doc([LOW], profile="passive",
                       degradations=["policy_restriction", "policy_restriction"]))
    assert r["passed"] is True
    assert (r["policy"], r["profile"]) == ("passive", "passive")
    assert {c["name"]: c["status"] for c in r["coverage"]} == {
        "profile": "ok",
        "engagement-status": "ok",
        "intents": "ok",
        "policy-limitations": "limitation",
        "degradations": "ok",
        "active-validation": "limitation",
        "findings-totals": "ok",
    }


@pytest.mark.parametrize("overrides,failed", [
    ({"status": "failed"}, "engagement-status"),
    ({"status": "draft"}, "engagement-status"),
    ({"blocked": 1}, "intents"),
    ({"done": 1}, "intents"),
    ({"degradations": ["agent_run_failed"]}, "degradations"),
    ({"degradations": ["tls_unreachable"]}, "degradations"),
])
def test_passive_report_still_fails_on_real_incompleteness(overrides, failed):
    r = gate(None, doc([LOW], profile="passive",
                       **{"degradations": ["policy_restriction"], **overrides}))
    assert r["passed"] is False
    assert failed in [c["name"] for c in r["coverage"] if c["status"] not in {"ok", "limitation"}]


def test_passive_report_fails_on_new_verified_high():
    r = gate(None, doc([HIGH], profile="passive"))
    assert r["passed"] is False
    assert [f["title"] for f in r["violations"]] == [HIGH["title"]]


def test_passive_report_fails_on_unexpected_policy_skip_only_under_active_policy():
    passive = doc([LOW], profile="passive", degradations=["policy_restriction"])
    assert gate(None, passive)["passed"] is True
    assert gate(None, passive, "active")["passed"] is False
    assert gate(None, passive, "strict")["passed"] is False


def test_active_report_fails_on_policy_restriction_that_is_not_expected():
    r = gate(None, doc([LOW], profile="safe_active", degradations=["policy_restriction"]))
    assert r["passed"] is False
    item = next(c for c in r["coverage"] if c["name"] == "degradations")
    assert item["status"] == "failed" and "unexpected" in item["detail"]


def test_active_profile_without_degradations_passes():
    r = gate(None, doc([HIGH], profile="advanced_validation"))
    assert r["passed"] is False  # new verified high, still a violation
    r = gate(doc([HIGH]), doc([HIGH], profile="safe_active"))
    assert r["passed"] is True and r["policy"] == "active"


@pytest.mark.parametrize("profile,policy", [
    ("passive", "passive"),
    ("production_safe", "passive"),
    ("safe_active", "active"),
    ("controlled_validation", "strict"),
    ("advanced_validation", "active"),
    ("unlisted_profile", "strict"),
    (None, "strict"),
])
def test_policy_auto_follows_profile_and_unknown_is_strict(profile, policy):
    r = gate(None, doc([LOW], profile=profile))
    assert r["policy"] == policy


def test_explicit_policy_wins_over_profile_but_cannot_be_set_by_report_content():
    passive = doc([LOW], profile="passive", degradations=["policy_restriction"])
    assert gate(None, passive, "auto")["passed"] is True
    assert gate(None, passive, "strict")["passed"] is False
    # a report field claiming the gate already passed is ignored entirely
    sneaky = {**passive, "gate": "PASS", "passed": True, "policy": "auto"}
    r = gate(None, sneaky, "strict")
    assert r["passed"] is False and r["policy"] == "strict"


@pytest.mark.parametrize("profile,policy", [("passive", "active"), ("safe_active", "passive"), (None, "active")])
def test_gate_rejects_report_outside_required_profile_even_without_skips(profile, policy):
    result = gate(None, doc([LOW], profile=profile), policy)
    assert not result["passed"]
    assert any(c["name"] == "profile" and c["status"] == "failed" for c in result["coverage"])


def test_negative_counts_are_not_valid_report_input():
    with pytest.raises(ValueError, match="non-negative"):
        normalize(doc(intents=-1, done=-1, blocked=-1))


def test_passive_baseline_regression_is_still_caught():
    r = gate(doc([LOW], profile="passive"), doc([], profile="passive"))
    assert r["passed"] is False
    assert [(c["name"], c["category"], c["status"]) for c in r["coverage"]
            if c["status"] not in {"ok", "limitation"}] == [
        ("baseline-findings", "regression", "missing")]


def test_junit_marks_limitations_skipped_not_failed(tmp_path):
    r = gate(None, doc([LOW], profile="passive", degradations=["policy_restriction"]))
    out = tmp_path / "passive.xml"
    write_junit(out, result=r)
    suite = ET.parse(out).getroot()
    assert suite.get("failures") == "0" and suite.get("errors") == "0"
    assert suite.find(".//testcase[@name='active-validation-limitation']/skipped") is not None


def test_new_verified_high_and_critical_fail():
    r = gate(doc([LOW, HIGH]), doc([LOW, HIGH, CRITICAL]))
    assert r["passed"] is False
    assert [f["title"] for f in r["violations"]] == [CRITICAL["title"]]
    assert all(c["status"] == "ok" for c in r["coverage"])


def test_existing_verified_high_does_not_fail():
    assert gate(doc([HIGH]), doc([HIGH]))["passed"] is True


@pytest.mark.parametrize("finding", [
    {**CRITICAL, "state": "observed"},
    {**CRITICAL, "state": "suspected"},
    {**CRITICAL, "severity": "medium"},
    {**CRITICAL, "state": "retested_fixed"},
    {**CRITICAL, "state": "ruled_out"},
])
def test_unverified_lower_or_closed_findings_do_not_fail(finding):
    assert gate(doc([LOW]), doc([LOW, finding]))["passed"] is True


def test_newly_verified_finding_fails_even_if_baseline_saw_it_unverified():
    r = gate(doc([{**CRITICAL, "state": "observed"}]), doc([CRITICAL]))
    assert [f["title"] for f in r["violations"]] == [CRITICAL["title"]]


@pytest.mark.parametrize("overrides,item,status", [
    ({"status": "failed"}, "engagement-status", "failed"),
    ({"status": "draft"}, "engagement-status", "unknown"),
    ({"intents": 0, "done": 0}, "intents", "missing"),
    ({"blocked": 1}, "intents", "failed"),
    ({"done": 1}, "intents", "unknown"),
    ({"degradations": ["tls_unreachable"]}, "degradations", "unknown"),
    ({"total": 9}, "findings-totals", "unknown"),
    ({"confirmed": 0}, "findings-totals", "unknown"),
])
def test_incomplete_coverage_never_passes(overrides, item, status):
    r = gate(None, doc([LOW], **overrides))
    assert r["passed"] is False
    assert {"name": item, "status": status} in [{"name": c["name"], "status": c["status"]}
                                                for c in r["coverage"]]


def test_missing_baseline_finding_is_coverage_missing_not_fixed():
    r = gate(doc([LOW]), doc([]))
    assert r["passed"] is False
    assert [(c["name"], c["status"]) for c in r["coverage"] if c["status"] != "ok"] == [
        ("baseline-findings", "missing")]


def test_junit_escapes_untrusted_text_and_stays_parseable(tmp_path):
    nasty = {**CRITICAL, "title": "Bad <tag> & ]]> \x00\x1b end"}
    r = gate(doc([]), doc([nasty]))
    out = tmp_path / "gate.xml"
    write_junit(out, result=r)

    raw = out.read_text(encoding="utf-8")
    assert "\x00" not in raw and "\x1b" not in raw
    suite = ET.parse(out).getroot()
    assert suite.get("tests") == str(len(r["coverage"]) + 1)
    assert suite.get("failures") == "1" and suite.get("errors") == "0"
    failure = suite.find(".//testcase[@classname='libella.gate.finding']/failure")
    assert "Bad <tag> & ]]> " in failure.get("message")
    assert failure.get("message").endswith("end")


@pytest.mark.parametrize("payload", [
    "{not json",
    json.dumps({"engagement": {"status": "done"}, "findings": [], "degradations": []}),
    json.dumps({**doc([]), "findings": [{**CRITICAL, "severity": "severe"}]}),
])
def test_malformed_input_is_exit_2_with_error_junit(tmp_path, payload, capsys):
    cur = tmp_path / "cur.json"
    cur.write_text(payload)
    junit = tmp_path / "gate.xml"
    assert main(["--current", str(cur), "--junit", str(junit)]) == 2
    assert "input error" in capsys.readouterr().err
    suite = ET.parse(junit).getroot()
    assert suite.get("tests") == "1" and suite.get("errors") == "1"
    assert suite.find("testcase/error") is not None


def test_findings_are_exit_1_not_input_error(tmp_path, capsys):
    base, cur = tmp_path / "base.json", tmp_path / "cur.json"
    base.write_text(json.dumps(doc([HIGH])))
    cur.write_text(json.dumps(doc([HIGH, CRITICAL])))
    junit = tmp_path / "gate.xml"
    assert main(["--baseline", str(base), "--current", str(cur), "--junit", str(junit)]) == 1
    err = capsys.readouterr()
    assert "input error" not in err.err
    suite = ET.parse(junit).getroot()
    assert suite.get("failures") == "1" and suite.get("errors") == "0"


def _persisted_report(tmp_path, name, findings, status="done", intents=("done", "done"),
                      profile="safe_active", degradations=()):
    db = DB(tmp_path / f"{name}.db")
    ev = EvidenceStore(db, tmp_path / f"{name}-evidence")
    db.execute(
        "INSERT INTO engagements(id,name,profile,status,scope_json,auth_json,budgets_json,"
        "created_at,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (name, name, profile, status, json.dumps({"targets": []}), "{}", "{}",
         0.0, 0.0, 0.0))
    for i, intent_status in enumerate(intents):
        db.execute(
            "INSERT INTO intents(id,engagement_id,role,objective,status,created_at) "
            "VALUES(?,?,?,?,?,?)", (f"i_{name}_{i}", name, "web", "check", intent_status, 0.0))
    for code, detail in degradations:
        db.emit(name, "degradation", {"code": code, "detail": detail})
    for i, f in enumerate(findings):
        db.execute(
            "INSERT INTO findings(id,engagement_id,title,cwe,severity,confidence,state,"
            "endpoint,description,impact,remediation,dedup_key,evidence_ids_json,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"f_{name}_{i}", name, f["title"], f["cwe"], f["severity"], "high", f["state"],
             f["endpoint"], "desc", "impact", "fix", f"k{i}", "[]", 0.0, 0.0))
    res = render_report(db, ev, name, tmp_path / f"{name}-out")
    return Path(res["outdir"]) / "report.json"


def _run_gate(*args):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run([sys.executable, "-m", "libella.gate", *map(str, args)],
                          cwd=ROOT, env=env, capture_output=True, text=True)


def test_end_to_end_persisted_assessment_reports(tmp_path):
    base = _persisted_report(tmp_path, "gate_base", [LOW, HIGH])
    clean = _persisted_report(tmp_path, "gate_clean", [LOW, HIGH])
    dirty = _persisted_report(tmp_path, "gate_dirty", [LOW, HIGH, CRITICAL])

    ok = _run_gate("--baseline", base, "--current", clean, "--junit", tmp_path / "ok.xml")
    assert ok.returncode == 0, ok.stderr
    assert "PASS" in ok.stdout and "input error" not in ok.stderr
    suite = ET.parse(tmp_path / "ok.xml").getroot()
    assert suite.get("failures") == "0" and suite.get("errors") == "0"

    bad = _run_gate("--baseline", base, "--current", dirty, "--junit", tmp_path / "bad.xml")
    assert bad.returncode == 1, bad.stderr
    assert CRITICAL["title"] in bad.stdout
    suite = ET.parse(tmp_path / "bad.xml").getroot()
    assert suite.get("failures") == "1" and suite.get("errors") == "0"


def test_end_to_end_failed_assessment_fails_even_with_no_findings(tmp_path):
    cur = _persisted_report(tmp_path, "gate_failed", [], status="failed", intents=("blocked",))
    proc = _run_gate("--current", cur, "--junit", tmp_path / "failed.xml")
    assert proc.returncode == 1
    names = [c.get("name") for c in ET.parse(tmp_path / "failed.xml").getroot()
             .findall(".//testcase")]
    assert "engagement-status-failed" in names and "intents-failed" in names


def test_end_to_end_passive_assessment_passes_without_claiming_active_coverage(tmp_path):
    cur = _persisted_report(
        tmp_path, "gate_passive", [LOW], profile="passive",
        degradations=[("policy_restriction", "nuclei_scan needs a higher profile: policy restriction"),
                      ("policy_restriction", "sqli needs a higher profile: policy restriction")])
    proc = _run_gate("--current", cur, "--junit", tmp_path / "passive.xml")
    assert proc.returncode == 0, proc.stderr
    assert "PASS" in proc.stdout
    assert "profile 'passive'" in proc.stdout
    assert "does not establish active validation coverage" in proc.stdout
    assert "policy_restriction x2" in proc.stdout
    suite = ET.parse(tmp_path / "passive.xml").getroot()
    assert suite.get("failures") == "0" and suite.get("errors") == "0"

    # the same report must not pass as an active assessment
    forced = _run_gate("--current", cur, "--policy", "active")
    assert forced.returncode == 1
    assert "unexpected" in forced.stdout


def test_end_to_end_active_run_with_policy_skip_fails(tmp_path):
    cur = _persisted_report(tmp_path, "gate_active_skip", [LOW], profile="safe_active",
                            degradations=[("policy_restriction", "unlisted check refused")])
    proc = _run_gate("--current", cur)
    assert proc.returncode == 1
    assert "policy_restriction is unexpected" in proc.stdout


def test_end_to_end_agent_run_failure_fails_a_passive_report(tmp_path):
    cur = _persisted_report(tmp_path, "gate_passive_agent_fail", [LOW], profile="passive",
                            degradations=[("agent_run_failed", "web run ended max_iterations")])
    assert _run_gate("--current", cur).returncode == 1


def test_unknown_policy_flag_is_exit_2(tmp_path):
    cur = tmp_path / "cur.json"
    cur.write_text(json.dumps(doc([LOW], profile="passive")))
    with pytest.raises(SystemExit) as exc:
        main(["--current", str(cur), "--policy", "lenient"])
    assert exc.value.code == 2


def test_malformed_profile_is_exit_2(tmp_path, capsys):
    cur = tmp_path / "cur.json"
    cur.write_text(json.dumps({**doc([LOW]), "engagement": {"status": "done", "profile": 7}}))
    assert main(["--current", str(cur)]) == 2
    assert "profile" in capsys.readouterr().err
