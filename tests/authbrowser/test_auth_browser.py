"""Authenticated browser workflows against a real chromium and the AuthLab twins.

Login, session reuse, authenticated crawl, scripted workflow evidence, and
multi-identity access comparison. The lab's vuln twin is genuinely vulnerable and
the hardened twin genuinely hardened, so a pass here means the module observed
real access differences with real sessions.
"""
import json

import pytest

from libella.auth_browser import AuthBrowser
from libella.browser_crawl import browser_available

pytestmark = pytest.mark.skipif(not browser_available(), reason="playwright/chromium not installed")


def _ctx(db, aid):
    return db.one("SELECT * FROM auth_contexts WHERE id=?", (aid,))


def test_login_captures_session(engine, do_login):
    db, ev, scope, base = engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = do_login(browser, base, "alice")
    assert res["status"] == "active", res
    assert res["cookie_count"] >= 1
    row = _ctx(db, res["id"])
    assert row["status"] == "active" and row["username"] == "alice"
    cookies = json.loads(row["cookies_json"])
    assert any(c["name"] == "session" for c in cookies)
    # the password is used for the attempt, never persisted
    assert "SI_SECRET_PASSWORD" not in row["login_flow_json"]
    assert ev.read(res["evidence_id"]).startswith(b"\x89PNG")  # post-login page


def test_login_failure_is_recorded(engine, do_login):
    db, ev, scope, base = engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = do_login(browser, base, "alice", password="SI_SECRET_PASSWORD_WRONG01")
    assert res["status"] == "failed"
    assert "not met" in res["reason"]
    assert _ctx(db, res["id"])["status"] == "failed"
    events = db.query("SELECT payload_json FROM events WHERE engagement_id=? AND kind='auth_context'",
                      ("eng_auth",))
    assert any(json.loads(e["payload_json"])["status"] == "failed" for e in events)


def test_expired_session_detected(engine, do_login):
    db, ev, scope, base = engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = do_login(browser, base, "alice")
        row = _ctx(db, res["id"])
        assert browser.verify(row)["status"] == "active"  # stored cookies still valid
        stale = {**row, "cookies_json": json.dumps([
            {**c, "value": "not-a-valid-session"} for c in json.loads(row["cookies_json"])])}
        verdict = browser.verify(stale)
    assert verdict["status"] == "expired"
    assert "login" in verdict["reason"]
    assert _ctx(db, res["id"])["status"] == "expired"


def test_authenticated_crawl_reaches_protected_routes(engine, do_login):
    db, ev, scope, base = engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = do_login(browser, base, "alice")
        crawled = browser.authenticated_crawl(base, _ctx(db, res["id"]))
    urls = [p["url"] for p in crawled["pages"]]
    assert base + "/dashboard" in urls, urls
    assert base + "/api/me" in crawled["endpoints"], crawled["endpoints"]
    # only the vulnerable listing shows alice another user's item and the admin link
    assert base + "/items/2" in urls, urls
    assert base + "/admin" in urls, urls
    assert crawled["auth_context_id"] == res["id"]
    for eid in crawled["screenshots"]:
        assert ev.read(eid).startswith(b"\x89PNG")


def test_authenticated_crawl_hardened_hides_other_routes(hardened_engine, do_login):
    db, ev, scope, base = hardened_engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = do_login(browser, base, "alice")
        crawled = browser.authenticated_crawl(base, _ctx(db, res["id"]))
    urls = [p["url"] for p in crawled["pages"]]
    assert base + "/dashboard" in urls, urls
    assert base + "/items/1" in urls, urls
    assert base + "/items/2" not in urls, urls
    assert base + "/admin" not in urls, urls


WORKFLOW = [
    {"action": "navigate", "value": "/dashboard"},
    {"action": "assert", "selector": "#dashboard"},
    {"action": "fill", "selector": "form[action='/items/1/transfer'] input[name=to]", "value": "bob"},
    {"action": "click", "selector": "form[action='/items/1/transfer'] button[type=submit]"},
    {"action": "assert", "selector": "#owner", "value": "bob"},
    {"action": "extract", "selector": "#owner"},
]


def _steps(base):
    return [{**s, "value": base + s["value"] if s["action"] == "navigate" else s.get("value")}
            for s in WORKFLOW]


def test_run_workflow_with_evidence(engine, do_login):
    db, ev, scope, base = engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = do_login(browser, base, "alice")
        run = browser.run_workflow(_steps(base), _ctx(db, res["id"]))
    assert run["ok"] is True, run["steps"]
    assert [s["action"] for s in run["steps"]] == [s["action"] for s in WORKFLOW]
    assert run["steps"][-1]["value"] == "bob"  # transfer really landed (extract)
    assert any(n["method"] == "POST" and n["url"].endswith("/items/1/transfer")
               for n in run["network"]), run["network"]
    assert len(run["screenshots"]) == len(WORKFLOW)  # one per step, under the cap
    for eid in run["screenshots"]:
        assert ev.read(eid).startswith(b"\x89PNG")
    blob = ev.read_json(run["evidence_id"])
    assert len(blob["steps"]) == len(WORKFLOW) and blob["network"]
    assert ev.verify_chain("eng_auth")["ok"] is True


def test_workflow_assert_failure_is_not_success(engine, do_login):
    db, ev, scope, base = engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = do_login(browser, base, "alice")
        run = browser.run_workflow(
            [{"action": "navigate", "value": base + "/dashboard"},
             {"action": "assert", "selector": "#missing-widget"}], _ctx(db, res["id"]))
    assert run["ok"] is False
    assert run["steps"][1]["reason"] == "assertion failed"


def test_multi_role_exposes_bola_in_vuln(engine, identities, login_kwargs):
    db, ev, scope, base = engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = browser.multi_role_check(base + "/items/2", identities,
                                       login_url=base + "/login", **login_kwargs)
    observed = {r["username"]: r for r in res["results"]}
    assert observed["alice"]["observed"] == "allow" and observed["alice"]["exposed"] is True
    assert observed["bob"]["observed"] == "allow" and observed["bob"]["exposed"] is False
    assert res["unexpected_access"] == ["alice"] and res["consistent"] is False
    assert observed["alice"]["screenshot"]  # access claim bound to a rendered page


def test_multi_role_clean_in_hardened(hardened_engine, identities, login_kwargs):
    db, ev, scope, base = hardened_engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        res = browser.multi_role_check(base + "/items/2", identities,
                                       login_url=base + "/login", **login_kwargs)
    observed = {r["username"]: r for r in res["results"]}
    assert observed["alice"]["observed"] == "denied"
    assert observed["alice"]["status"] == 403
    assert observed["bob"]["observed"] == "allow"
    assert res["unexpected_access"] == [] and res["consistent"] is True


def test_multi_role_workflow_cross_user_transfer(engine, hardened_engine, identities, login_kwargs):
    """The same scripted flow replayed per identity: vuln lets alice act on bob's item."""
    steps = [{"action": "navigate", "value": "/items/2"},
             {"action": "click", "selector": "form[action='/items/2/transfer'] button[type=submit]"}]
    out = {}
    for name, eng in (("vuln", engine), ("hardened", hardened_engine)):
        db, ev, scope, base = eng
        with AuthBrowser(db, ev, scope, "eng_auth") as browser:
            out[name] = browser.multi_role_check(
                [{**s, "value": base + s["value"]} if s["action"] == "navigate" else s
                 for s in steps], identities, login_url=base + "/login", **login_kwargs)
    assert {r["username"]: r["observed"] for r in out["vuln"]["results"]} == {
        "alice": "allow", "bob": "allow"}
    assert out["vuln"]["unexpected_access"] == ["alice"]
    observed = {r["username"]: r for r in out["hardened"]["results"]}
    assert observed["alice"]["observed"] == "denied"
    assert out["hardened"]["unexpected_access"] == []


def test_cross_origin_navigation_refused(engine, sink):
    db, ev, scope, base = engine
    with AuthBrowser(db, ev, scope, "eng_auth") as browser:
        run = browser.run_workflow([{"action": "navigate", "value": sink.base + "/steal"},
                                    {"action": "assert", "selector": "#dashboard"}])
    assert run["ok"] is False
    assert "out of scope" in run["steps"][0]["reason"]
    assert sink.hits == [], "out-of-scope navigation was actually sent"
    refusals = [json.loads(e["payload_json"]) for e in db.query(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind='scope_refusal'",
        ("eng_auth",))]
    assert any(sink.base in r["url"] for r in refusals), refusals
