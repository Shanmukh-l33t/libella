"""The OAuth audit finds every seeded flaw and nothing on the hardened control."""
import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.api import App  # noqa: E402
from libella.oauth_audit import audit_oauth  # noqa: E402
from libella.scope import Scope  # noqa: E402

LAB = ROOT / "labs/oauthlab/app.py"


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("oauthlab", LAB)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    started = mod.start_lab()
    yield started
    started["server"].shutdown()


class Engine:
    """One engagement over the lab: DB, evidence, probe, pipeline, real scope."""

    def __init__(self, data_dir: Path, base: str, attacker: str, mode: str,
                 with_attacker: bool = True):
        self.app = App(data_dir)
        self.base = base
        targets = [{"kind": "url", "value": base}]
        if with_attacker:  # the lab's attacker origin is only in scope when we test a landing
            targets.append({"kind": "url", "value": attacker})
        self.scope = Scope({"targets": targets, "categories": ["web", "api"],
                            "rate_limit_rps": 1000})
        self.eid = f"eng_oauth_{int(time.time() * 1e6)}"
        prefix = "" if mode == "vuln" else "/hard"
        self.auth = {"oauth": {"authorize_url": base + prefix + "/authorize",
                               "token_url": base + prefix + "/token",
                               "client_id": "labclient",
                               "redirect_uri": base + prefix + "/callback",
                               "scope": "profile", "attacker_origin": attacker,
                               "pkce": True}}
        self.app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (self.eid, "oauthlab", "safe_active", "draft",
             json.dumps({"targets": [{"kind": "url", "value": base}]}),
             json.dumps(self.auth), "{}", time.time()))

    def run(self, auth=None):
        return audit_oauth(self.app.db, self.app.evidence, self.app.probe, self.scope,
                           self.eid, auth if auth is not None else self.auth,
                           self.app.pipeline)

    def findings(self):
        return self.app.pipeline.list(self.eid)


@pytest.fixture(scope="module")
def results(tmp_path_factory, lab):
    out = {}
    for mode in ("vuln", "hard"):
        eng = Engine(tmp_path_factory.mktemp("oauth_" + mode), lab["base"], lab["attacker"], mode)
        out[mode] = (eng, eng.run())
    return out


def _by_cwe(res, cwe):
    return [c for c in res["candidates"] if c["cwe"] == cwe]


def _holds(app, ev_ids, quote, quote_in):
    for e in ev_ids:
        resp = app.evidence.read_json(e)["response"]
        if quote_in == "header_fact":
            hk, _, hv = quote.partition(":")
            if any(k.lower() == hk.strip().lower() and
                   (v == hv.strip() or v.startswith(hv.strip()))
                   for k, v in resp["headers"].items()):
                return True
        elif quote in resp["body"]:
            return True
    return False


def test_redirect_uri_bypass_is_proven_by_the_location_header(results):
    eng, res = results["vuln"]
    cand = _by_cwe(res, "CWE-601")[0]
    assert cand["quote"].startswith("Location: ")
    assert eng.base.replace("127.0.0.1", "127.0.0.2") in cand["quote"]
    assert cand["quote"].endswith("code=")  # the code really is on its way to the attacker
    assert _by_cwe(res, "CWE-601")[0]["deduped"] is False
    assert cand["proof_request"]["url"].startswith(eng.base)


def test_several_bypass_variants_reach_the_attacker_origin(results):
    _, res = results["vuln"]
    hit = {v["variant"] for v in res["vectors"] if v["attacker_host"]}
    assert {"attacker_host_swap", "userinfo_at", "trailing_dot_host"} <= hit
    # a registered-host prefix in the path is not a bypass and must not be counted
    assert "attacker_path_append" not in hit


def test_state_and_pkce_absence_only_when_the_grant_completes(results):
    _, res = results["vuln"]
    cand = _by_cwe(res, "CWE-352")[0]
    assert "state" in cand["title"] and "PKCE" in cand["title"]
    assert cand["evidence_ids"]  # authorize + token exchanges


def test_scope_escalation_quotes_the_granted_scope(results):
    _, res = results["vuln"]
    cand = _by_cwe(res, "CWE-285")[0]
    assert '"scope":"profile admin"' in cand["quote"]
    assert cand["proof_request"]["method"] == "POST"


def test_implicit_flow_token_is_reported(results):
    _, res = results["vuln"]
    cand = _by_cwe(res, "CWE-598")[0]
    assert "access_token=" in cand["quote"]


def test_hardened_control_produces_no_findings_or_observations(results):
    eng, res = results["hard"]
    assert res["status"] == "assessed"
    assert res["candidates"] == []
    assert res["observations"] == []
    assert eng.findings() == []


def test_every_candidate_quote_occurs_in_its_evidence(results):
    eng, res = results["vuln"]
    assert len(res["candidates"]) == 4
    for c in res["candidates"]:
        assert _holds(eng.app, c["evidence_ids"], c["quote"], c["quote_in"]), c["title"]
    assert len(eng.findings()) == 4  # every candidate is bound to a finding


def test_every_request_stayed_inside_scope(results):
    for eng, _ in results.values():
        rows = eng.app.db.query("SELECT url FROM exchanges WHERE engagement_id=?", (eng.eid,))
        assert rows
        for row in rows:
            assert row["url"].startswith((eng.base, eng.base.replace("127.0.0.1", "127.0.0.2")))


def test_missing_authorize_url_is_a_recorded_limitation(tmp_path, lab):
    eng = Engine(tmp_path / "nc", lab["base"], lab["attacker"], "vuln")
    res = eng.run({"oauth": {"client_id": "labclient"}})
    assert res["status"] == "not_configured"
    assert res["candidates"] == [] and res["limitations"]
    row = eng.app.db.one("SELECT COUNT(*) AS n FROM observations WHERE engagement_id=? "
                         "AND kind='oauth_audit_limitation'", (eng.eid,))
    assert row["n"] == 1


def test_out_of_scope_authorize_url_is_refused_and_recorded(tmp_path, lab):
    eng = Engine(tmp_path / "oos", lab["base"], lab["attacker"], "vuln", with_attacker=False)
    res = eng.run({"oauth": {**eng.auth["oauth"],
                             "authorize_url": lab["attacker"] + "/authorize"}})
    assert res["status"] == "blocked"
    assert res["candidates"] == [] and res["limitations"]
    refusal = eng.app.db.one("SELECT COUNT(*) AS n FROM events WHERE engagement_id=? "
                             "AND kind='scope_refusal'", (eng.eid,))
    assert refusal["n"] == 1
    assert eng.app.db.query("SELECT url FROM exchanges WHERE engagement_id=?", (eng.eid,)) == []
