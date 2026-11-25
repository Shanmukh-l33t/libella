"""Structural attribution and the never-inflate rule for the ASVS / API Top 10 / WSTG ledgers.

Every positive case follows evidence -> exchange tool -> unit -> requirement (plus the control
id where one check asserts several). Every negative case proves a requirement does not move to
an executed status for work that did not run.
"""
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from libella import coverage, standards  # noqa: E402
from libella.api import App  # noqa: E402

SCOPE = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
         "categories": ["web", "api"], "rate_limit_rps": 20}
EXECUTED = coverage.COMPLETED
NOT_EXECUTED = ("requires_manual", "not_supported", "skipped_policy", "skipped_dependency",
                "inconclusive", "not_applicable")


@pytest.fixture
def app(tmp_path):
    a = App(tmp_path / "data")
    a.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at, standards_json) VALUES(?,?,?,?,?,?,?,?,?)",
        ("eng_a", "attr", "safe_active", "draft", json.dumps(SCOPE), "{}", "{}", time.time(),
         json.dumps({"asvs": {"level": 2}})))
    return a


def ws(app, fid="asvs"):
    return {t["id"]: t for c in coverage.workspace(app.db, "eng_a", fid)["categories"]
            for t in c["tests"]}


def exchange(app, xid, tool):
    app.db.execute("INSERT INTO exchanges(id, engagement_id, method, url, status, tool, created_at)"
                   " VALUES(?,?,?,?,?,?,?)",
                   (xid, "eng_a", "GET", "http://127.0.0.1:8801/", 200, tool, time.time()))


def finding(app, fid, cwe, tool, controls=(), state="validated"):
    ev = f"ev_{fid}"
    app.db.execute("INSERT INTO evidence(id, engagement_id, sha256, kind, path, bytes, created_at,"
                   " prev_hash, chain_hash) VALUES(?,?,?,?,?,?,?,?,?)",
                   (ev, "eng_a", "x" * 64, "http", "b/" + ev, 1, time.time(), "p", "c"))
    app.db.execute("INSERT INTO exchanges(id, engagement_id, evidence_id, method, url, status, tool,"
                   " created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (f"x_{fid}", "eng_a", ev, "GET", "http://127.0.0.1:8801/", 200, tool, time.time()))
    app.db.execute("INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state,"
                   " evidence_ids_json, controls_json, controls_source, created_at, updated_at)"
                   " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (fid, "eng_a", "t", cwe, "high", "high", state, json.dumps([ev]),
                    json.dumps(list(controls)), "check" if controls else "none",
                    time.time(), time.time()))


def tool_call(app, cid, tool, decision="executed: ok", error=None):
    app.db.execute("INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target,"
                   " scope_decision, exit_code, error, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (cid, "eng_a", None, tool, "[]", "http://127.0.0.1:8801", decision, 0, error,
                    time.time()))


# ---- positive: sub-exchanges of a unit resolve to that unit ------------------------------

@pytest.mark.parametrize("tool,cwe,asvs,wstg,api", [
    ("idor_check_anon", "CWE-306", "V8.2.2", "WSTG-ATHZ-04", "API1:2023"),
    ("object_enum", "CWE-639", "V8.2.2", "WSTG-ATHZ-04", "API1:2023"),
    ("object_enum_anon", "CWE-306", "V8.2.2", "WSTG-ATHZ-04", "API1:2023"),
    ("sqli_bool_true", "CWE-89", "V1.2.4", "WSTG-INPV-05", None),
    ("ssrf_discovery", "CWE-918", "V1.3.6", "WSTG-INPV-19", "API7:2023"),
])
def test_sub_exchange_of_a_unit_attributes_to_the_units_requirements(app, tool, cwe, asvs, wstg, api):
    finding(app, "f1", cwe, tool)
    assert ws(app)[asvs]["evidence"]["findings"] == ["f1"]
    assert ws(app, "wstg")[wstg]["evidence"]["findings"] == ["f1"]
    if api:
        assert ws(app, "api-top10")[api]["evidence"]["findings"] == ["f1"]
    for fid in ("asvs", "wstg") + (("api-top10",) if api else ()):  # nothing is left orphaned
        assert coverage.workspace(app.db, "eng_a", fid)["unattributed_findings"] == []


def test_unauthenticated_object_read_is_not_attributed_to_an_unrelated_requirement(app):
    finding(app, "f1", "CWE-306", "idor_check_anon")
    t = ws(app)
    assert all("f1" not in t[r]["evidence"]["findings"] for r in ("V8.2.1", "V1.2.4", "V8.4.1"))


# ---- positive: one path probe, several controls -----------------------------------------

@pytest.mark.parametrize("control,cwe,asvs,not_asvs,api", [
    ("exposure.directory_listing", "CWE-548", "V13.4.3", ("V13.4.1", "V13.4.2", "V13.4.5"), "API8:2023"),
    ("exposure.excess_fields", "CWE-200", "V15.3.1", ("V13.4.1", "V13.4.2", "V13.4.3", "V13.4.5"),
     "API3:2023"),
    ("exposure.vcs_metadata", "CWE-200", "V13.4.1", ("V13.4.2", "V13.4.5", "V15.3.1"), "API8:2023"),
])
def test_path_probe_findings_follow_the_control_the_path_asserted(app, control, cwe, asvs, not_asvs, api):
    finding(app, "f1", cwe, "path_probe", controls=(control,))
    t = ws(app)
    assert t[asvs]["automatic"]["status"] == "finding_verified"
    for rid in not_asvs:
        assert "f1" not in t[rid]["evidence"]["findings"], rid
    assert "f1" in ws(app, "api-top10")[api]["evidence"]["findings"]
    if control == "exposure.excess_fields":  # credential fields are API3, not API8/API9
        a = ws(app, "api-top10")
        assert "f1" not in a["API8:2023"]["evidence"]["findings"]
        assert "f1" not in a["API9:2023"]["evidence"]["findings"]


def test_a_path_probe_finding_with_no_control_id_attributes_to_no_exposure_requirement(app):
    finding(app, "f1", "CWE-200", "path_probe")  # e.g. a legacy row, or .env: no requirement
    t = ws(app)
    assert all("f1" not in t[r]["evidence"]["findings"]
               for r in ("V13.4.1", "V13.4.2", "V13.4.3", "V13.4.5", "V15.3.1"))
    assert [u["id"] for u in coverage.workspace(app.db, "eng_a", "asvs")["unattributed_findings"]] == ["f1"]


def test_a_debug_page_does_not_fail_the_source_metadata_requirement(app):
    exchange(app, "x_probe", "path_probe")
    finding(app, "f1", "CWE-200", "path_probe", controls=("exposure.debug_endpoint",))
    t = ws(app)
    assert t["V13.4.2"]["automatic"]["status"] == "finding_verified"
    assert t["V13.4.1"]["automatic"]["status"] == "completed_no_issue"  # .git was probed, absent


def test_requirements_the_probe_only_partly_covers_never_report_a_pass(app):
    exchange(app, "x_probe", "path_probe")
    t = ws(app)
    for rid in ("V13.4.3", "V15.3.1", "V13.4.5"):
        assert t[rid]["automatic"]["status"] == "partial_evidence", rid
        assert t[rid]["automatic"]["strength"] == "partial", rid


# ---- strength comes from the units that ran, not from every mapped unit -----------------

def test_a_partial_unit_that_ran_does_not_inherit_direct_from_one_that_did_not(app):
    # V13.4.1 is direct for sensitive_paths and partial for ffuf; only ffuf ran
    tool_call(app, "tc_ffuf", "ffuf")
    it = ws(app)["V13.4.1"]["automatic"]
    assert it["status"] == "partial_evidence" and it["strength"] == "partial"


# ---- negative: work that did not run never becomes executed -----------------------------

def test_policy_refused_unit_stays_out_of_executed_even_with_stray_exchanges(app):
    exchange(app, "x_probe", "path_probe")
    exchange(app, "x_idor", "idor_check")
    app.db.emit("eng_a", "degradation", {"code": "policy_restriction",
                                         "unit": "sensitive_paths, idor", "profile": "passive"})
    for fid, rids in (("asvs", ("V13.4.3", "V15.3.1", "V13.4.1", "V8.2.2")),
                      ("api-top10", ("API3:2023", "API1:2023")),
                      ("wstg", ("WSTG-ATHZ-04", "WSTG-INFO-05"))):
        t = ws(app, fid)
        for rid in rids:
            assert t[rid]["automatic"]["status"] == "skipped_policy", (fid, rid)


def test_missing_tool_unit_stays_out_of_executed(app):
    tool_call(app, "tc_nuclei", "nuclei", decision="refused: missing binary",
              error="missing_tool: nuclei not installed")
    t = ws(app)
    # V13.4.2 is mapped to sensitive_paths and nuclei; neither produced anything
    assert t["V13.4.2"]["automatic"]["status"] == "skipped_dependency"
    assert t["V13.4.2"]["automatic"]["status"] not in EXECUTED


def test_blocked_role_matrix_is_inconclusive_not_a_pass(app):
    app.db.execute("INSERT INTO intents(id, engagement_id, role, objective, status, created_at) "
                   "VALUES(?,?,?,?,?,?)", ("i1", "eng_a", "privesc_audit", "r", "done", time.time()))
    app.db.emit("eng_a", "degradation", {"code": "audit_blocked", "unit": "privesc_audit",
                                         "detail": "no identity could log in"})
    for fid, rid in (("asvs", "V8.2.1"), ("api-top10", "API5:2023")):
        assert ws(app, fid)[rid]["automatic"]["status"] == "inconclusive"


def test_a_role_matrix_that_ran_is_partial_evidence_only(app):
    exchange(app, "x_rm", "role_matrix")
    t = ws(app)
    for rid in ("V8.2.1", "V8.2.2"):
        assert t[rid]["automatic"]["status"] == "partial_evidence"
    assert ws(app, "api-top10")["API5:2023"]["automatic"]["status"] == "partial_evidence"


def test_tls_cipher_suites_are_never_passed_by_a_check_that_only_records_one_cipher(app):
    tool_call(app, "tc_tls", "tls_audit")
    t = ws(app)
    assert t["V12.1.2"]["automatic"]["status"] == "partial_evidence"
    assert t["V12.1.2"]["automatic"]["strength"] == "indirect"


def test_nothing_ran_nothing_is_executed(app):
    for fid in ("asvs", "wstg", "api-top10"):
        assert not [r for r, t in ws(app, fid).items() if t["automatic"]["status"] in EXECUTED]


def test_unmapped_requirements_cannot_become_executed_by_any_amount_of_activity(app):
    """Record every exchange tool and tool name any unit knows: only mapped requirements move."""
    for fid in ("asvs", "wstg", "api-top10"):
        spec = standards.spec(fid)
        for i, name in enumerate(spec["external_unit"]):
            exchange(app, f"x_{fid}_{i}", name)
        for unit in spec["units"]:
            tool_call(app, f"tc_{fid}_{unit}", unit)
    for fid in ("asvs", "wstg", "api-top10"):
        spec = standards.spec(fid)
        for rid, t in ws(app, fid).items():
            if not spec["by_requirement"].get(rid):
                assert t["automatic"]["status"] in ("requires_manual", "not_supported"), (fid, rid)
    # the retired-technology WSTG test and the WebRTC chapter have no check at all
    assert ws(app, "wstg")["WSTG-CONF-09"]["automatic"]["status"] == "not_supported"
    assert ws(app)["V17.1.1"]["automatic"]["status"] == "requires_manual"
    assert ws(app, "api-top10")["API6:2023"]["automatic"]["status"] == "requires_manual"


def test_mapped_exchange_names_belong_to_exactly_one_unit_per_standard():
    for fid in ("asvs", "wstg", "api-top10"):
        seen = {}
        for unit, row in standards.spec(fid)["units"].items():
            for name in row["exchanges"]:
                assert seen.setdefault(name, unit) == unit, (fid, name)
