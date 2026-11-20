"""Scope is the boundary: a refused login stops the audit before any check."""
from libella.scope import Scope


def _scope(**target):
    spec = {"targets": [{"kind": "url", "value": target.pop("value")}],
            "categories": target.pop("categories", ["api", "web"]),
            "rate_limit_rps": 1000}
    spec.update(target)
    return Scope(spec)


def test_out_of_scope_endpoint_is_blocked_before_any_check(engine):
    res = engine.assess(scope=_scope(value="http://127.0.0.2:9"))
    assert res["status"] == "blocked"
    assert res["candidates"] == [] and engine.findings() == []
    assert res["observations"] == []
    assert any("out_of_scope" in e for e in res["errors"]), res["errors"]


def test_category_must_be_permitted_by_the_engagement(engine):
    res = engine.assess(scope=_scope(value=engine.base, categories=["web"]))
    assert res["status"] == "blocked"
    assert res["candidates"] == [] and engine.findings() == []
    assert any("category" in e for e in res["errors"]), res["errors"]


def test_scope_refusal_is_audited(engine):
    engine.assess(scope=_scope(value="http://127.0.0.2:9"))
    rows = engine.app.db.query(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind='scope_refusal'",
        (engine.eid,))
    assert rows, "a refused request must leave an audit row"
