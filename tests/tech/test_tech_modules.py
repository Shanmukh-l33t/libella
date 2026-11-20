"""Technology modules: each stack yields its seeded finding on the vuln twin,
nothing on the hardened twin, and every candidate is bound to real evidence."""
import json
from pathlib import Path

import pytest

from libella.tech_modules import detect_technologies

GT = json.loads((Path(__file__).resolve().parents[2]
                 / "labs/techlab/ground_truth.json").read_text())
PREFIX, TECHS = GT["prefixes"], list(GT["prefixes"])

EXPECTED = {  # tech -> (cwe of a seeded finding, path fragment)
    "wordpress": ("CWE-538", "/wp-config.php.bak"),
    "php": ("CWE-538", "/index.php.bak"),
    "java": ("CWE-200", "/actuator/env"),
    "coldfusion": ("CWE-284", "/CFIDE/administrator/"),
    "node": ("CWE-200", "/package.json"),
    "iis": ("CWE-200", "/web.config"),
    "apache": ("CWE-22", "/static../WEB-INF/web.xml"),
}


@pytest.mark.parametrize("tech", TECHS)
def test_detects_the_stack(results, tech):
    assert tech in results["vuln"][1][tech]["technologies"], tech


@pytest.mark.parametrize("tech", TECHS)
def test_positive_finding_on_vuln_twin(results, tech):
    cwe, path = EXPECTED[tech]
    cands = results["vuln"][1][tech]["candidates"]
    hit = [c for c in cands if c["cwe"] == cwe and c["endpoint"].endswith(path)]
    assert hit, f"{tech}: no {cwe} finding for {path}; got {[c['endpoint'] for c in cands]}"
    assert hit[0]["evidence_ids"] and hit[0]["quote"] and hit[0]["proof_request"]


@pytest.mark.parametrize("tech", TECHS)
def test_hardened_twin_is_clean(results, tech):
    res = results["hardened"][1][tech]
    assert tech in res["technologies"], "hardening must not hide the stack itself"
    assert res["candidates"] == [], [c["endpoint"] for c in res["candidates"]]


def test_all_seeded_findings_fire_exactly_once_on_vuln(results):
    seen = {tid for res in results["vuln"][1].values() for c in res["candidates"]
            for tid in [c["dedup_key"]]}
    assert len(seen) == sum(len(r["candidates"]) for r in results["vuln"][1].values())


@pytest.mark.parametrize("mode", ["vuln", "hardened"])
def test_every_candidate_is_evidence_bound(results, mode):
    eng, per_tech = results[mode]
    for res in per_tech.values():
        for c in res["candidates"]:
            for ev in c["evidence_ids"]:
                assert eng.evidence_exists(ev), c["title"]
            assert c["quote_in"] in ("body", "header_fact")


def test_wordpress_specials(results):
    cands = results["vuln"][1]["wordpress"]["candidates"]
    titles = " | ".join(c["title"] for c in cands)
    assert "system.multicall" in titles           # xmlrpc POST method call
    assert "?author=1" in titles                  # user enumeration redirect
    author = next(c for c in cands if "?author=1" in c["title"])
    assert author["quote_in"] == "header_fact" and "location:" in author["quote"]
    assert "hello-dolly" in titles                # plugin readme version disclosure


def test_php_expose_php_is_an_observation_not_a_finding(results):
    obs = results["vuln"][1]["php"]["observations"]
    assert any(o["kind"] == "version_signal" and o["value"].startswith("PHP/") for o in obs)
    assert results["hardened"][1]["php"]["observations"] == []
    assert not [c for c in results["vuln"][1]["php"]["candidates"] if c["cwe"] == "CWE-16"]


def test_sensitive_path_dedup_key_matches_generic_check(results):
    cands = results["vuln"][1]["node"]["candidates"]
    env = next(c for c in cands if c["endpoint"].endswith("/.env"))
    assert env["dedup_key"] == f"path:{env['endpoint']}"


def test_detection_needs_a_response():
    assert detect_technologies({"ok": False}) == []
    assert detect_technologies({"ok": True, "headers": {"Server": "Microsoft-IIS/10.0"},
                                "body": ""}) == ["iis"]


def test_scope_refusal_yields_no_findings(engine_for, labs):
    eng = engine_for("hardened", target=labs["vuln"])
    res = eng.assess("wordpress")
    assert res["candidates"] == []
    assert eng.events("scope_refusal"), "out-of-scope probes must be audited"
