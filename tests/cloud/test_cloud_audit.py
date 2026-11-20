"""Cloud posture audit: positive on the vuln lab, clean on the hardened twin."""
import pytest

from libella.cloud_audit import READ_ONLY_PREFIXES, Clients, ReadOnlyViolation, assess_cloud

# (title fragment, cwe, severity) — one per seeded defect in labs/cloudlab.
SEEDS = [
    ("grants wildcard permissions", "CWE-732", "critical"),
    ("enables privilege escalation", "CWE-269", "high"),
    ("is publicly accessible", "CWE-284", "high"),
    ("has no default encryption", "CWE-311", "medium"),
    ("exposes 22/tcp", "CWE-284", "high"),
    ("exposes 3389/tcp", "CWE-284", "high"),
    ("CloudTrail is not configured", "CWE-778", "high"),
    ("no configuration recorder", "CWE-778", "low"),
    ("volume", "CWE-311", "medium"),
    ("storage is unencrypted", "CWE-311", "high"),
    ("Root account has no MFA", "CWE-306", "high"),
    ("days old", "CWE-324", "medium"),
]


def _run(env, cloud):
    return assess_cloud(env.endpoint, "us-east-1", cloud.creds(), env.db, env.evidence,
                        env.pipeline, env.scope, env.eid)


@pytest.mark.parametrize("fragment,cwe,severity", SEEDS)
def test_vuln_lab_reports_each_seed(vuln, fragment, cwe, severity):
    env, result = vuln
    assert result["ok"] is True, result.get("errors")
    matches = [f for f in env.pipeline.list(env.eid)
               if fragment in f["title"] and f["cwe"] == cwe]
    assert matches, [f["title"] for f in env.pipeline.list(env.eid)]
    assert matches[0]["severity"] == severity


def test_vuln_finding_count_matches_ground_truth(vuln):
    env, result = vuln
    assert len(result["findings"]) == 12
    assert len(env.pipeline.list(env.eid)) == 12
    assert result["errors"] == {}


def test_hardened_lab_is_clean(audit_env, labs, cloud):
    env = audit_env(labs["hardened"], eid="eng_hardened")
    result = _run(env, cloud)
    assert result["ok"] is True, result.get("errors")
    assert env.pipeline.list(env.eid) == []
    assert result["findings"] == []
    assert all(n == 0 for n in result["checks"].values())


def test_evidence_is_bound_and_chain_verifies(vuln):
    env, _result = vuln
    assert env.evidence.verify_chain(env.eid)["ok"] is True
    kinds = {r["kind"] for r in env.db.query(
        "SELECT DISTINCT kind FROM evidence WHERE engagement_id=?", (env.eid,))}
    assert {"cloud_iam_posture", "cloud_s3_posture", "cloud_sg_posture",
            "cloud_logging_posture", "cloud_encryption_posture", "cloud_root_posture",
            "cloud_credential_age"} <= kinds
    for f in env.pipeline.list(env.eid):
        assert f["evidence_ids"], f["title"]
        for eid in f["evidence_ids"]:
            assert env.db.one("SELECT 1 FROM evidence WHERE id=? AND engagement_id=?",
                              (eid, env.eid)) is not None
    iam_ev = env.db.one("SELECT id FROM evidence WHERE engagement_id=? AND kind=?",
                        (env.eid, "cloud_iam_posture"))
    doc = env.evidence.read_json(iam_ev["id"])
    assert any("*" in p["document"]["Statement"][0]["Action"] for p in doc["policies"]
               if isinstance(p["document"]["Statement"][0]["Action"], str))


def test_s3_evidence_holds_raw_bucket_state(vuln):
    env, _result = vuln
    ev = env.db.one("SELECT id FROM evidence WHERE engagement_id=? AND kind=?",
                    (env.eid, "cloud_s3_posture"))
    bucket = next(b for b in env.evidence.read_json(ev["id"])["buckets"]
                  if b["bucket"].endswith("-data"))
    assert bucket["public_access_block"] is None
    assert '"Principal":"*"' in bucket["policy"]
    assert bucket["encryption"] is None


def test_credential_age_is_measured_from_api_data(vuln):
    env, _result = vuln
    ev = env.db.one("SELECT id FROM evidence WHERE engagement_id=? AND kind=?",
                    (env.eid, "cloud_credential_age"))
    blob = env.evidence.read_json(ev["id"])
    assert max(k["age_days"] for k in blob["access_keys"]) > blob["threshold_days"]


def test_no_write_calls_are_made(vuln):
    _env, result = vuln
    assert result["read_calls"]
    assert all(c.startswith(READ_ONLY_PREFIXES) for c in result["read_calls"])


def test_read_only_gate_blocks_a_write_before_the_wire(labs, cloud):
    clients = Clients(labs["vuln"], "us-east-1", cloud.creds())
    s3 = clients.client("s3")
    with pytest.raises(ReadOnlyViolation):
        s3.create_bucket(Bucket="should-never-exist")
    assert clients.calls == []


def test_candidate_shape(vuln):
    env, _result = vuln
    required = {"title", "cwe", "severity", "confidence", "endpoint", "description",
                "impact", "remediation", "evidence_ids", "dedup_key"}
    for f in env.pipeline.list(env.eid):
        assert required <= set(f), f
        assert f["state"] == "observed"
        assert f["remediation"] and f["impact"] and f["description"]
        assert f["confidence"] in ("low", "medium", "high")
        assert f["cwe"].startswith("CWE-")


def test_cloud_scope_kind_matches_account_or_endpoint():
    from libella.scope import Scope

    by_account = Scope({"targets": [{"kind": "cloud", "value": "123456789012"}],
                        "categories": ["cloud"]})
    assert by_account.check_cloud("123456789012", "http://127.0.0.1:4566").allowed
    assert not by_account.check_cloud("999999999999", "http://127.0.0.1:4566").allowed
    by_endpoint = Scope({"targets": [{"kind": "cloud", "value": "http://127.0.0.1:4566"}],
                         "categories": ["cloud"]})
    assert by_endpoint.check_cloud("123456789012", "http://127.0.0.1:4566").allowed
    assert not by_endpoint.check_cloud("123456789012", "http://127.0.0.1:4567").allowed
    wrong_category = Scope({"targets": [{"kind": "cloud", "value": "123456789012"}],
                            "categories": ["web"]})
    assert not wrong_category.check_cloud("123456789012").allowed


def test_scope_refusal_leaves_no_findings(audit_env, labs, cloud):
    env = audit_env(labs["vuln"], account_scope="999999999999", eid="eng_refused")
    result = _run(env, cloud)
    assert result["refused"] is True
    assert env.pipeline.list(env.eid) == []
    assert env.db.one("SELECT 1 FROM events WHERE engagement_id=? AND kind=?",
                      (env.eid, "scope_refusal"))


def test_metadata_endpoint_is_refused(audit_env, cloud):
    env = audit_env("http://169.254.169.254", eid="eng_metadata")
    result = _run(env, cloud)
    assert result["ok"] is False
    assert "metadata" in result["error"]
    assert env.pipeline.list(env.eid) == []


def test_unreachable_endpoint_degrades_without_findings(audit_env, cloud):
    env = audit_env("http://127.0.0.1:1", eid="eng_down")
    result = _run(env, cloud)
    assert result["ok"] is False
    assert env.pipeline.list(env.eid) == []
    assert env.db.one("SELECT 1 FROM events WHERE engagement_id=? AND kind=?",
                      (env.eid, "cloud_audit_failed"))
