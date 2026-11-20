"""Each seeded class fires on the vulnerable twin and not on the hardened twin."""
import json

import pytest

SEEDS = ["CWE-639", "CWE-285", "CWE-915", "CWE-200", "CWE-306"]


def _cands(results, mode, cwe):
    return [c for c in results[mode][1]["candidates"] if c["cwe"] == cwe]


@pytest.mark.parametrize("cwe", SEEDS)
def test_seed_detected_in_vuln(results, cwe):
    assert _cands(results, "vuln", cwe), f"{cwe} not reported on the vulnerable twin"


@pytest.mark.parametrize("cwe", SEEDS)
def test_seed_absent_in_hardened(results, cwe):
    assert _cands(results, "hardened", cwe) == [], f"{cwe} false positive on the hardened twin"


def test_hardened_produces_no_findings_or_observations(results):
    eng, res = results["hardened"]
    assert res["status"] == "assessed"
    assert res["candidates"] == []
    assert res["observations"] == []
    assert eng.findings() == []


def test_every_identity_logs_in_with_a_cookie(results):
    eng, res = results["vuln"]
    assert set(res["logins"]) == {"alice", "bob", "admin"}
    assert all(v["authenticated"] and v["cookie"] for v in res["logins"].values())


def test_findings_are_evidence_bound_with_proof_specs(results):
    eng, _ = results["vuln"]
    findings = eng.findings()
    assert len(findings) == len(SEEDS)
    for f in findings:
        kinds = {eng.app.db.one("SELECT kind FROM evidence WHERE id=?", (e,))["kind"]
                 for e in f["evidence_ids"]}
        assert {"http_exchange", "proof_spec"} <= kinds
        assert f["state"] == "observed"


def test_schema_conformance_flags_undescribed_fields(results):
    eng, res = results["vuln"]
    fields = {o["field"] for o in res["observations"]}
    assert "owner_password_hash" in fields  # returned by the listing, absent from ItemSummary
    assert "is_admin" in fields
    obs = eng.app.db.one("SELECT COUNT(*) AS n FROM observations WHERE engagement_id=? "
                         "AND kind='schema_conformance'", (eng.eid,))
    assert obs["n"] == len(res["observations"])


def test_bad_credentials_produce_no_candidates(engine_for):
    eng = engine_for("vuln")
    bad = [{"username": "alice", "password": "wrong"}]
    res = eng.assess(identities=bad)
    assert res["status"] == "no_authenticated_identity"
    assert res["candidates"] == []
    assert eng.findings() == []


def test_proof_requests_are_replayable_shapes(results):
    eng, _ = results["vuln"]
    for f in eng.findings():
        spec = next(eng.app.evidence.read_json(e) for e in f["evidence_ids"]
                    if eng.app.db.one("SELECT kind FROM evidence WHERE id=?", (e,))["kind"] == "proof_spec")
        pr = spec["proof_request"]
        assert pr["url"].startswith(eng.base)
        assert pr["method"] in ("GET", "POST")
        assert spec["quote"] and ": " not in spec["quote"]  # compact JSON fragment
        if f["cwe"] == "CWE-306":
            assert "Cookie" not in (pr.get("headers") or {})  # anonymous by design
        else:
            assert "Cookie" in (pr.get("headers") or {})
        if pr["method"] == "POST":
            assert json.loads(pr["body"])
