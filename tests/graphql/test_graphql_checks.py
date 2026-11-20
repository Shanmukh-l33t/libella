"""Each GraphQL check: positive in vuln mode, silent in hardened mode."""
import json

import pytest


def _by_dedup(eng, dedup):
    return [f for f in eng.findings() if f["dedup_key"] == dedup]


@pytest.mark.parametrize("index", range(7))
def test_vuln_mode_lands_every_check(results, seeds, index):
    dedup, cwe = seeds[index]
    eng, res = results["vuln"]
    hits = _by_dedup(eng, dedup)
    assert res["status"] == "assessed"
    assert len(hits) == 1, [f["dedup_key"] for f in eng.findings()]
    assert hits[0]["cwe"] == cwe
    assert hits[0]["state"] in ("observed", "validated")
    assert hits[0]["endpoint"].endswith("/graphql")


@pytest.mark.parametrize("index", range(7))
def test_hardened_mode_claims_nothing(results, seeds, index):
    dedup, _ = seeds[index]
    eng, res = results["hardened"]
    assert res["status"] == "assessed"
    assert _by_dedup(eng, dedup) == []
    assert eng.findings() == []  # zero findings overall: any one is a false positive


def test_every_vuln_finding_carries_a_replayable_post_proof(results):
    eng, _ = results["vuln"]
    for finding in eng.findings():
        spec = eng.proof_spec(finding)
        assert spec, finding["title"]
        pr = spec["proof_request"]
        assert pr["method"] == "POST" and pr["url"].endswith("/graphql")
        assert pr["headers"]["Cookie"] and pr["headers"]["Content-Type"] == "application/json"
        json.loads(pr["body"])  # exact body, valid JSON
        assert spec["quote"] and spec["quote_in"] == "body"
        # compact JSON separators only; the GraphQL document itself keeps its own spacing
        assert '": ' not in pr["body"] and '", "' not in pr["body"]


def test_introspection_is_an_observation_and_honest_low(results):
    eng, res = results["vuln"]
    obs = [o for o in res["observations"] if "types" in o]
    assert len(obs) == 1 and "AdminStats" in obs[0]["types"]
    intro = _by_dedup(eng, "gql:introspection")
    assert intro and intro[0]["severity"] == "low"
    # hardened: introspection off means no observation at all, not a "clean" claim
    hard_eng, hard_res = results["hardened"]
    assert hard_res["observations"] == []


def test_injection_finding_quotes_a_database_error(results):
    eng, _ = results["vuln"]
    spec = eng.proof_spec(_by_dedup(eng, "gql:sqli:users")[0])
    assert "sqlite3" in spec["quote"].lower()


def test_no_authenticated_identity_says_so(engine):
    """Wrong credentials: no check runs and the status names the reason."""
    bad = [{"username": "alice", "password": "not-the-lab-password", "role": "user"}]
    res = engine.assess(identities=bad)
    assert res["status"] == "no_authenticated_identity"
    assert res["candidates"] == [] and engine.findings() == []
