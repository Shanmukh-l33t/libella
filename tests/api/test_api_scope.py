"""Scope is enforced at the probe boundary: an out-of-scope base stops the audit."""
import json
from pathlib import Path

from libella.api_audit import assess_api
from libella.scope import Scope

ROOT = Path(__file__).resolve().parents[2]
OPENAPI = ROOT / "labs/apilab/openapi.json"
IDENTITIES = json.loads((ROOT / "labs/apilab/ground_truth.json").read_text())["identities"]
OUT = "http://127.0.0.1:1"  # a port the lab never listens on


def _scope(base, categories=("api", "web")):
    return Scope({"targets": [{"kind": "url", "value": base}], "categories": list(categories),
                  "rate_limit_rps": 1000})


def _run(eng, scope):
    return assess_api(eng.base, OPENAPI, IDENTITIES, eng.app.db, eng.app.evidence,
                      eng.app.pipeline, eng.app.probe, scope, eng.eid)


def test_out_of_scope_base_is_refused(engine):
    eng = engine
    res = _run(eng, _scope(OUT))
    assert res["status"] == "blocked"
    assert res["candidates"] == [] and res["logins"] == {}
    assert res["errors"] and "out_of_scope" in res["errors"][0]
    assert eng.findings() == []  # nothing is claimed from a refused request


def test_scope_refusal_is_audited(engine):
    eng = engine
    _run(eng, _scope(OUT))
    events = eng.app.db.query("SELECT payload_json FROM events WHERE engagement_id=? "
                              "AND kind='scope_refusal'", (eng.eid,))
    assert events and "not in engagement scope" in events[0]["payload_json"]


def test_category_not_permitted_blocks_the_audit(engine):
    eng = engine
    res = _run(eng, _scope(eng.base, ("recon",)))
    assert res["status"] == "blocked"
    assert res["candidates"] == []


def test_in_scope_audit_still_runs(engine):
    eng = engine
    res = _run(eng, _scope(eng.base))
    assert res["status"] == "assessed" and res["candidates"]
