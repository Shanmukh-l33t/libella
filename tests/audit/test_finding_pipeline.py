"""Finding pipeline: state machine, verification gate, dedup, provenance."""
import json

import pytest

from libella.findings import FindingPipeline
from libella.scope import Scope


def _scope(lab):
    return Scope({"targets": [{"kind": "url", "value": lab.base}],
                  "categories": ["recon", "web", "api", "infra"], "rate_limit_rps": 1000})


def _finding(app, eid, lab, **over):
    ev = app.evidence.put_json(eid, {"request": {"url": lab.base + "/ok"}}, "http_exchange")
    cand = {"title": "t", "cwe": "CWE-79", "severity": "low", "endpoint": lab.base + "/ok",
            "evidence_ids": [ev["id"]], "quote": "hello libella",
            "proof_request": {"method": "GET", "url": lab.base + "/ok"}, "dedup_key": "k"}
    cand.update(over)
    return app.pipeline.submit_candidate(eid, cand)["id"]


def test_unverified_finding_cannot_be_reported(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    fid = _finding(app, eid, lab)
    for state in ("reported", "remediated", "retested_fixed", "retested_persists", "validated"):
        with pytest.raises(ValueError):
            app.pipeline.transition(fid, state)
    assert app.pipeline.list(eid)[0]["state"] == "observed"


def test_verified_finding_can_be_reported(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    fid = _finding(app, eid, lab)
    assert app.verifier.verify(eid, _scope(lab), fid)["verdict"] == "reproduced"
    app.pipeline.transition(fid, "reported")
    assert app.pipeline.list(eid)[0]["state"] == "reported"


def test_retested_states_require_a_real_retest(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    fid = _finding(app, eid, lab)
    app.verifier.verify(eid, _scope(lab), fid)
    with pytest.raises(ValueError):
        app.pipeline.transition(fid, "retested_fixed")
    app.db.execute("INSERT INTO retests(id, finding_id, exchange_id, verdict, detail, created_at) "
                   "VALUES('rt1', ?, NULL, 'fixed', 'ok', 0)", (fid,))
    app.pipeline.transition(fid, "retested_fixed")


def test_empty_quote_cannot_verify_a_finding(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    fid = _finding(app, eid, lab, quote="")
    res = app.verifier.verify(eid, _scope(lab), fid)
    assert res["verdict"] != "reproduced", res
    assert app.pipeline.list(eid)[0]["state"] != "validated"


def test_tampered_proof_spec_is_inconclusive_not_a_crash(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    fid = _finding(app, eid, lab)
    row = app.db.one("SELECT evidence_ids_json FROM findings WHERE id=?", (fid,))
    proof_id = json.loads(row["evidence_ids_json"])[-1]
    ev_row = app.db.one("SELECT * FROM evidence WHERE id=?", (proof_id,))
    (app.evidence.root / ev_row["path"]).write_bytes(b"forged")
    res = app.verifier.verify(eid, _scope(lab), fid)
    assert res["verdict"] == "inconclusive", res


def test_evidence_from_another_engagement_is_not_a_binding(app, mk_eng, lab):
    other = mk_eng(lab.base)
    foreign = app.evidence.put_json(other, {"request": {}}, "http_exchange")
    eid = mk_eng(lab.base)
    r = app.pipeline.submit_candidate(eid, {"title": "x", "severity": "high",
                                            "endpoint": lab.base, "evidence_ids": [foreign["id"]],
                                            "dedup_key": "cross"})
    assert r["state"] == "suspected"


def test_dedup_is_per_engagement_and_does_not_overwrite(app, mk_eng, lab):
    a, b = mk_eng(lab.base), mk_eng(lab.base)
    fa = _finding(app, a, lab, dedup_key="same", severity="critical")
    fb = _finding(app, b, lab, dedup_key="same", severity="critical")
    assert fa != fb
    # duplicate candidate in the same engagement merges evidence, not severity/title
    again = _finding(app, a, lab, dedup_key="same", severity="info", title="downgraded")
    assert again == fa
    row = app.db.one("SELECT severity, title FROM findings WHERE id=?", (fa,))
    assert row["severity"] == "critical" and row["title"] == "t"


def test_transition_rejects_unknown_state(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    fid = _finding(app, eid, lab)
    with pytest.raises(ValueError):
        app.pipeline.transition(fid, "totally_verified")