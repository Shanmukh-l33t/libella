"""Expected-authorization model + oracle: provenance, persistence, content-not-status judging."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.authorization import (PolicyModel, Rule, access_of, body_kind, evaluate,  # noqa: E402
                                   from_openapi, from_operator, infer, served_owner)
from libella.db import DB  # noqa: E402


def obs(identity, relation, status=200, body='{"owner":"alice","note":"x"}', **kw):
    return {"identity": identity, "relation": relation, "role": kw.pop("role", "user"),
            "status": status, "body": body, **kw}


OWNER = Rule("GET", "/n/{id}", "owner_only", "operator")


def test_rule_rejects_unknown_class_and_source():
    with pytest.raises(ValueError):
        Rule("GET", "/x", "everyone", "operator")
    with pytest.raises(ValueError):
        Rule("GET", "/x", "public", "guess")
    assert Rule("GET", "/x", "role:manager", "analyst").access == "role:manager"


def test_merge_precedence_and_persistence(tmp_path):
    m = PolicyModel([infer("GET", "/n/{id}")])
    assert m.get("GET", "/n/<x>").source == "inferred"  # placeholder styles normalise
    m.add(OWNER)
    m.add(Rule("GET", "/n/{id}", "public", "inferred"))  # weaker source cannot override
    assert m.get("GET", "/n/1".replace("1", "{id}")).access == "owner_only"
    db = DB(tmp_path / "p.db")
    m.save(db, "e1")
    back = PolicyModel.load(db, "e1")
    assert back.to_data() == m.to_data() and PolicyModel.load(db, "other").to_data() == []


def test_openapi_security_and_operator_file(tmp_path):
    spec = {"security": [{"bearer": []}], "paths": {
        "/a": {"get": {}}, "/pub": {"get": {"security": []}}, "/b": {"post": {"security": [{"k": []}]}}}}
    got = {(r.method, r.path): (r.access, r.source) for r in from_openapi(spec)}
    assert got[("GET", "/a")] == ("authenticated", "openapi_security")
    assert got[("GET", "/pub")] == ("public", "openapi_security")
    assert from_openapi({"paths": {"/z": {"get": {}}}}) == []  # silence is not a policy
    f = tmp_path / "policy.json"
    f.write_text(json.dumps([{"path": "/n/{id}", "access": "owner_only", "allow_roles": ["Admin"]}]))
    r = from_operator(str(f))[0]
    assert (r.source, r.allow_roles) == ("operator", ("admin",))


def test_unknown_policy():
    assert evaluate(None, [obs("a", "owner")])["verdict"] == "unknown_policy"
    assert evaluate(Rule("GET", "/x", "unknown", "analyst"), [])["verdict"] == "unknown_policy"


def test_everyone_reads_private_record_is_violation_despite_agreement():
    v = evaluate(OWNER, [obs("alice", "owner"), obs("bob", "other_user"), obs("anonymous", "anonymous")])
    assert v["verdict"] == "violation" and v["confirmable"]
    assert v["violations"] == ["bob", "anonymous"] and v["controls"] == ["alice"]


def test_public_with_identical_responses_is_compliant():
    rule = Rule("GET", "/p", "public", "operator")
    assert evaluate(rule, [obs("alice", "owner"), obs("bob", "other_user"),
                           obs("anonymous", "anonymous")])["verdict"] == "compliant"


def test_hardened_owner_only_is_compliant():
    v = evaluate(OWNER, [obs("alice", "owner"), obs("bob", "other_user", 403, '{"error":"forbidden"}'),
                         obs("anonymous", "anonymous", 401, "")])
    assert v["verdict"] == "compliant"


def test_login_page_and_error_with_200_are_not_access():
    login = '<form action="/login"><input type="password"></form>'
    assert access_of(obs("a", "anonymous", 200, login)) == "denied"
    assert access_of(obs("a", "anonymous", 200, '{"error":"no session"}')) == "denied"
    assert access_of(obs("a", "anonymous", 200, "")) == "unusable"
    assert body_kind(200, '{"authenticated": false}') == "error"
    v = evaluate(OWNER, [obs("alice", "owner"), obs("anonymous", "anonymous", 200, login)])
    assert v["verdict"] == "compliant"


def test_waf_block_is_not_a_clean_denial():
    waf = obs("bob", "other_user", 403, "blocked", mitigated="cloudflare:challenge")
    assert access_of(waf) == "unusable"
    v = evaluate(OWNER, [obs("alice", "owner"), waf])
    assert v["verdict"] == "inconclusive"  # no genuine refusal was observed: not "compliant"


def test_inferred_rule_never_confirms():
    rule = infer("GET", "/n/{id}")
    v = evaluate(rule, [obs("alice", "owner"), obs("bob", "other_user")])
    assert v["verdict"] == "violation" and v["confirmable"] is False


def test_violation_without_permitted_control_is_not_confirmable():
    v = evaluate(OWNER, [obs("bob", "other_user")])
    assert v["verdict"] == "violation" and not v["confirmable"]


def test_served_record_identity_beats_status():
    me, bob = {"username": "alice", "uid": 1}, {"username": "bob", "uid": 2}
    assert served_owner('{"username":"bob"}', me, [bob]) == ("other", "bob")
    assert served_owner('{"id":2,"item":"x"}', me, [bob]) == ("unknown", None)  # bare id is not an owner
    # a non-owner served ITS OWN record (id ignored) leaked nothing
    own = obs("bob", "other_user", served_owner="self")
    assert evaluate(OWNER, [obs("alice", "owner"), own, obs("eve", "other_user", 403, "")])["verdict"] == "compliant"
    # a requester that "owns" the route but is served someone else's record is a violation
    swapped = obs("bob", "owner", served_owner="other", served_owner_of="alice")
    assert evaluate(OWNER, [obs("alice", "owner"), swapped])["verdict"] == "violation"


def test_owner_refused_is_inconclusive_not_violation():
    v = evaluate(OWNER, [obs("alice", "owner", 403, ""), obs("bob", "other_user", 403, "")])
    assert v["verdict"] == "inconclusive" and not v["violations"]


def test_tenant_and_role_classes():
    t = Rule("GET", "/t", "tenant:acme", "operator")
    ok = obs("alice", "owner", tenant="acme")
    assert evaluate(t, [ok, obs("eve", "other_tenant", tenant="globex")])["verdict"] == "violation"
    assert evaluate(t, [ok, obs("eve", "other_tenant", 403, "", tenant="globex")])["verdict"] == "compliant"
    r = Rule("GET", "/r", "role:manager", "operator")
    assert evaluate(r, [obs("c", "owner", role="manager"), obs("u", "owner", role="user")])["verdict"] == "violation"
