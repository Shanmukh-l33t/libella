"""Positive, negative and boundary tests for libella.codeaudit.

Seeded issues must be found in labs/vulnrepo, nothing may be found in
labs/cleanrepo, and dependency CVEs may only ever be observations.
"""
import json

import pytest

from pathlib import Path

from libella.codeaudit import CATALOG, assess_repo

# Scanner-dependent suite: skip where the binaries are absent (dev machines).
# CI installs them; test_missing_tools.py covers the absent-tool paths.
from libella.codeaudit import _binary  # noqa: E402

pytestmark = pytest.mark.skipif(
    not all(_binary(b) for b in ("semgrep", "trivy", "gitleaks")),
    reason="semgrep/trivy/gitleaks required for scanner integration tests")

GT = json.loads((Path(__file__).resolve().parents[2]
                 / "labs/vulnrepo/ground_truth.json").read_text())
SEEDS = GT["findings"]
CODE_CWES = {"CWE-798", "CWE-94", "CWE-78", "CWE-502", "CWE-489"}


# --- positive: every seeded class is detected -------------------------------

@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_vulnrepo_detects_seeded_issue(findings, seed):
    rows = findings("vulnrepo")
    hits = [f for f in rows if f["cwe"] == seed["cwe"]
            and f["endpoint"].split("#")[0].endswith(seed["file"])]
    assert hits, f"missed {seed['id']}: have {[(f['cwe'], f['endpoint']) for f in rows]}"


def test_vulnrepo_findings_are_observed_and_evidence_bound(findings, assessed):
    rows = findings("vulnrepo")
    assert rows
    for f in rows:
        assert f["state"] == "observed", f["title"]
        ids = json.loads(f["evidence_ids_json"])
        assert any(i.startswith("ev_") for i in ids), ids
        for i in ids:
            assert assessed.db.one("SELECT id FROM evidence WHERE id=?", (i,)), i


def test_vulnrepo_evidence_quotes_come_from_the_seeded_lines(findings, assessed):
    rows = findings("vulnrepo")
    seed_files = {s["file"] for s in SEEDS}
    quoted = 0
    for f in rows:
        for ev_id in json.loads(f["evidence_ids_json"]):
            kind = assessed.db.one("SELECT kind FROM evidence WHERE id=?", (ev_id,))["kind"]
            if kind != "code_finding":
                continue
            blob = json.loads(assessed.evidence.read(ev_id))
            assert blob["quote"], blob
            assert blob["file"] in seed_files, blob
            quoted += 1
    assert quoted >= len(SEEDS)


def test_vulnrepo_has_no_duplicate_or_spurious_code_findings(findings):
    rows = findings("vulnrepo")
    assert {f["cwe"] for f in rows} == CODE_CWES
    assert len(rows) == len(SEEDS), [(f["cwe"], f["endpoint"]) for f in rows]


# --- negative: the hardened twin is clean -----------------------------------

def test_cleanrepo_yields_zero_code_findings(findings):
    assert [f for f in findings("cleanrepo") if f["cwe"] in CODE_CWES] == []


def test_cleanrepo_patched_pin_is_not_flagged(observations):
    obs = [o for o in observations("cleanrepo") if o["kind"] == "potentially_affected"]
    assert not [o for o in obs if "PyYAML" in o["summary"] and "6.0.2" in o["summary"]]


def test_cleanrepo_dependency_observations_are_backed_by_osv(assessed, observations):
    run = assessed.runs["cleanrepo"]
    artifact = json.loads(assessed.evidence.read(run["dependencies"]["artifact_id"]))
    for o in observations("cleanrepo"):
        if o["kind"] != "potentially_affected":
            continue
        hit = json.loads(o["summary"])
        query = next(q for q in artifact["queries"]
                     if q["package"] == hit["package"] and q["version"] == hit["version"])
        assert query["response"].get("vulns"), hit


# --- the OSV distinction: version match is not confirmed exposure ------------

def test_dependency_cve_is_potentially_affected_observation(assessed, observations):
    obs = [o for o in observations("vulnrepo") if o["kind"] == "potentially_affected"]
    assert obs, "PyYAML 5.3.1 must match an OSV advisory"
    hit = json.loads(obs[0]["summary"])
    assert set(hit) >= {"cve", "package", "version", "source", "retrieved_at"}
    assert hit["source"] == "osv"
    assert hit["package"].lower() == "pyyaml"
    assert hit["version"] == "5.3.1"
    assert hit["cve"].startswith("CVE-")
    assert obs[0]["evidence_id"].startswith("ev_")
    assert obs[0]["source_derived"] == "captured_exchange"


def test_dependency_cve_never_becomes_a_finding(assessed, findings, observations):
    run = assessed.runs["vulnrepo"]
    rows = findings("vulnrepo")
    assert {f["cwe"] for f in rows} == CODE_CWES
    assert all(f["dedup_key"].startswith("code:") for f in rows)
    cves = {h["cve"] for h in run["dependencies"]["potentially_affected"]}
    assert cves
    for f in rows:
        assert not any(c in (f["title"] + f["description"] + f["dedup_key"]) for c in cves)
    assert [o for o in observations("vulnrepo") if o["kind"] == "potentially_affected"]


def test_static_finding_cannot_be_promoted_to_validated(assessed, findings):
    rows = findings("vulnrepo")
    with pytest.raises(ValueError):
        assessed.pipeline.transition(rows[0]["id"], "validated", "no replay exists")


def test_dependency_evidence_is_never_bound_to_a_finding(findings, assessed):
    for f in findings("vulnrepo"):
        kinds = {assessed.db.one("SELECT kind FROM evidence WHERE id=?", (i,))["kind"]
                 for i in json.loads(f["evidence_ids_json"])}
        assert kinds <= {"code_finding", "proof_spec"}, kinds
        assert "osv_query" not in kinds


# --- audit + evidence -------------------------------------------------------

def test_every_scanner_call_is_audited(assessed):
    for name in ("vulnrepo", "cleanrepo"):
        calls = assessed.db.query(
            "SELECT * FROM tool_calls WHERE engagement_id=?",
            (assessed.runs[name]["engagement_id"],))
        tools = {c["tool"] for c in calls}
        assert {"semgrep", "trivy_fs", "gitleaks", "osv"} <= tools, tools
        for c in calls:
            argv = json.loads(c["argv_json"])
            assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
            assert c["artifact_id"].startswith("ev_")
            assert "local filesystem" in c["scope_decision"] or "public advisory" in c[
                "scope_decision"]
        for row in calls:
            if row["tool"] in ("semgrep", "trivy_fs", "gitleaks"):
                argv = json.loads(row["argv_json"])
                assert argv[0].startswith("/"), argv[0]


def test_evidence_chain_is_intact_after_a_scan(assessed):
    for name in ("vulnrepo", "cleanrepo"):
        assert assessed.evidence.verify_chain(
            assessed.runs[name]["engagement_id"])["ok"] is True


def test_scan_result_shape(assessed):
    run = assessed.runs["vulnrepo"]
    assert run["degradations"] == []
    assert set(run["scanners"]) == {"semgrep", "trivy_fs", "gitleaks"}
    assert run["dependencies"]["pins"] == ["Flask==3.1.3", "PyYAML==5.3.1"]
    assert set(CATALOG) == CODE_CWES


# --- trust boundary: repo path ---------------------------------------------

@pytest.mark.parametrize("bad", [
    "/etc", "/etc/passwd", "/proc/self", "../labs/vulnrepo", "labs/../../",
    "does-not-exist", "",
])
def test_repo_path_outside_the_code_roots_is_rejected(assessed, bad):
    with pytest.raises(ValueError):
        assess_repo(bad, assessed.db, assessed.evidence, assessed.pipeline,
                    "eng_reject", roots=[str(assessed.labs)], dependencies=False)


@pytest.mark.parametrize("bad", [
    "labs/vulnrepo; touch /tmp/libella_pwn",
    "labs/vulnrepo|id",
    "labs/vulnrepo&whoami",
    "labs/vulnrepo$(id)",
    "labs/vulnrepo`id`",
    "labs/vulnrepo\nrm -rf /",
    "labs/vulnrepo>out",
    "labs/vulnrepo\x00",
])
def test_metacharacters_in_repo_path_are_rejected(assessed, bad):
    with pytest.raises(ValueError):
        assess_repo(bad, assessed.db, assessed.evidence, assessed.pipeline,
                    "eng_reject", roots=[str(assessed.labs)], dependencies=False)


def test_rejected_path_writes_no_finding(assessed):
    before = assessed.db.query("SELECT COUNT(*) AS n FROM findings")[0]["n"]
    with pytest.raises(ValueError):
        assess_repo("../vulnrepo", assessed.db, assessed.evidence, assessed.pipeline,
                    "eng_reject", roots=[str(assessed.labs)], dependencies=False)
    after = assessed.db.query("SELECT COUNT(*) AS n FROM findings")[0]["n"]
    assert before == after
