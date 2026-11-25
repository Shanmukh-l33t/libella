"""The session audit proves fixation, logout and re-auth failures on the lab,
and reports nothing on the hardened control."""
import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.api import App  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.session_audit import audit_session  # noqa: E402

LAB = ROOT / "labs/oauthlab/app.py"
PASSWORD = "SI_SECRET_PASSWORD_OAUTHLAB_A1"


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("oauthlab_session", LAB)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    started = mod.start_lab()
    yield started
    started["server"].shutdown()


class Engine:
    def __init__(self, data_dir: Path, base: str, mode: str):
        self.app = App(data_dir)
        self.base = base
        self.scope = Scope({"targets": [{"kind": "url", "value": base}],
                            "categories": ["web"], "rate_limit_rps": 1000})
        self.eid = f"eng_session_{int(time.time() * 1e6)}"
        prefix = "" if mode == "vuln" else "/hard"
        self.auth = {"session": {
            "login_url": base + prefix + "/session/login",
            "username_field": "username", "password_field": "password",
            "username": "alice", "password": PASSWORD,
            "protected_url": base + prefix + "/session/me",
            "logout_url": base + prefix + "/session/logout",
            "password_change_url": base + prefix + "/session/password"}}
        self.app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (self.eid, "oauthlab", "safe_active", "draft",
             json.dumps({"targets": [{"kind": "url", "value": base}]}),
             json.dumps(self.auth), "{}", time.time()))

    def run(self, auth=None):
        return audit_session(self.app.db, self.app.evidence, self.app.probe, self.scope,
                             self.eid, auth if auth is not None else self.auth,
                             self.app.pipeline)

    def findings(self):
        return self.app.pipeline.list(self.eid)


@pytest.fixture(scope="module")
def results(tmp_path_factory, lab):
    out = {}
    for mode in ("vuln", "hard"):
        eng = Engine(tmp_path_factory.mktemp("session_" + mode), lab["base"], mode)
        out[mode] = (eng, eng.run())
    return out


def _by_cwe(res, cwe):
    return [c for c in res["candidates"] if c["cwe"] == cwe]


def _holds(app, ev_ids, quote):
    return any(quote in app.evidence.read_json(e)["response"]["body"] for e in ev_ids)


def test_fixation_is_proven_with_the_chosen_id_after_login(results):
    eng, res = results["vuln"]
    cand = _by_cwe(res, "CWE-384")[0]
    cookie = cand["proof_request"]["headers"]["Cookie"]
    assert cookie == f"sid={res['login']['fixed_id']}"
    assert _holds(eng.app, cand["evidence_ids"], cand["quote"])
    assert "alice" in cand["quote"]


def test_logout_leaves_the_old_cookie_authenticated(results):
    eng, res = results["vuln"]
    cand = _by_cwe(res, "CWE-613")[0]
    assert cand["proof_request"]["url"].endswith("/session/me")
    assert "Cookie" in cand["proof_request"]["headers"]
    assert _holds(eng.app, cand["evidence_ids"], cand["quote"])


def test_password_change_needs_no_current_password(results):
    eng, res = results["vuln"]
    cand = _by_cwe(res, "CWE-620")[0]
    body = cand["proof_request"]["body"]
    assert "new_password" in body and "current_password" not in body
    assert _holds(eng.app, cand["evidence_ids"], cand["quote"])


def test_cookie_scope_and_token_in_url_are_observations_only(results):
    eng, res = results["vuln"]
    kinds = {o["kind"] for o in res["observations"]}
    assert {"session_cookie_scope", "session_token_in_url"} <= kinds
    assert not [c for c in res["candidates"] if "cookie" in c["title"].lower()]


def test_hardened_control_produces_no_findings_or_observations(results):
    eng, res = results["hard"]
    assert res["status"] == "assessed"
    assert res["candidates"] == [] and res["observations"] == []
    assert eng.findings() == []


def test_every_request_stayed_inside_scope(results):
    for eng, res in results.values():
        rows = eng.app.db.query("SELECT url FROM exchanges WHERE engagement_id=?", (eng.eid,))
        assert rows
        assert all(row["url"].startswith(eng.base) for row in rows)
        assert res["status"] == "assessed"


def test_missing_session_config_is_a_recorded_limitation(tmp_path, lab):
    eng = Engine(tmp_path / "nc", lab["base"], "vuln")
    res = eng.run({"session": {"login_url": eng.base + "/session/login"}})
    assert res["status"] == "not_configured"
    assert res["candidates"] == [] and res["limitations"]
    row = eng.app.db.one("SELECT COUNT(*) AS n FROM observations WHERE engagement_id=? "
                         "AND kind='session_audit_limitation'", (eng.eid,))
    assert row["n"] == 1
