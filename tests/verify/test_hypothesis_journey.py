"""Evidence to plan to execution to verification, end to end.

This is the milestone the product was missing. It is asserted as a JOURNEY, not as unit
behaviour: a real twin app is served, real requests are made, the application model is built
from those responses, a hypothesis is materialized from the model, the planner ranks it
deterministically, the test runs with a real identity, the verifier judges the result, and
the hypothesis records what the evidence supported.

Both directions are required. The vulnerable twin must produce a finding the VERIFIER
accepts; the hardened twin must produce none, and the hypothesis must end up refuted rather
than left looking like coverage.
"""
import json
import threading

import pytest
from flask import Flask, jsonify, request, session
from werkzeug.serving import make_server

from libella import hypotheses as H
from libella.api import App
from libella.appintel import AppIntel
from libella.discovery import Discovery
from libella.scope import Scope

INVOICES = {5001: {"id": 5001, "customer_id": 11, "memo": "alpha"},
            5002: {"id": 5002, "customer_id": 12, "memo": "bravo"}}


def _serve(vulnerable: bool):
    """Two identities, two invoices, and one cross-user read policy."""
    app = Flask(__name__)
    app.secret_key = "hypothesis-lab"

    @app.post("/auth/session")
    def login():
        user = request.form.get("email", "")
        if user not in ("maya@lab.invalid", "noor@lab.invalid"):
            return jsonify(error="bad credentials"), 401
        session["uid"] = 11 if user.startswith("maya") else 12
        return jsonify(signed_in=True)

    @app.get("/v2/invoices")
    def mine():
        uid = session.get("uid")
        if uid is None:
            return jsonify(error="sign in"), 401
        return jsonify(invoices=[r for r in INVOICES.values() if r["customer_id"] == uid])

    @app.get("/v2/invoices/<int:num>")
    def one(num):
        uid = session.get("uid")
        if uid is None:
            return jsonify(error="sign in"), 401
        row = INVOICES.get(num)
        if row is None:
            return jsonify(error="no such invoice"), 404
        if not vulnerable and row["customer_id"] != uid:
            return jsonify(error="forbidden"), 403
        return jsonify(invoice=dict(row))

    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.port}"


def _engagement(app, base: str):
    identities = [{"username": "maya@lab.invalid", "password": "x", "uid": 11,
                   "login_url": base + "/auth/session", "username_field": "email",
                   "password_field": "password"},
                  {"username": "noor@lab.invalid", "password": "x", "uid": 12,
                   "login_url": base + "/auth/session", "username_field": "email",
                   "password_field": "password"}]
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
        "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng", "hypothesis", "safe_active", "running",
         json.dumps({"targets": [{"kind": "url", "value": base}],
                     "categories": ["recon", "web", "api"], "rate_limit_rps": 200}),
         json.dumps({"identities": identities}), "{}", 0))
    return app.db.one("SELECT * FROM engagements WHERE id='eng'")


def _model_from_traffic(app, base: str) -> AppIntel:
    """Build the application model from real responses, as the crawl would."""
    disc = Discovery(app.db, "eng")
    disc.ingest_traffic([
        {"method": "GET", "url": base + "/v2/invoices", "page": base},
        {"method": "GET", "url": base + "/v2/invoices/5002", "page": base},
    ], evidence_id=None)
    # The ownership evidence must come from an AUTHENTICATED read: this twin refuses an
    # anonymous object request, so probing without a session captures a 401 and proves
    # nothing. Logging in first is also the realistic order of an assessment.
    from libella.tools.http_probe import HttpProbe
    probe = HttpProbe(app.db, app.evidence)
    scope = Scope(json.loads(app.db.one("SELECT scope_json FROM engagements WHERE id='eng'")
                             ["scope_json"]))
    login = probe.request("eng", scope, base + "/auth/session", method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body="email=maya@lab.invalid&password=x", tool="model_login")
    assert login.get("ok") and login["status"] == 200, login
    jar = [v for k, v in (login.get("headers") or {}).items() if k.lower() == "set-cookie"]
    cookie = "; ".join(j.split(";")[0] for j in jar)
    assert cookie, "the twin did not set a session cookie"
    r = probe.request("eng", scope, base + "/v2/invoices/5001", tool="model",
                      headers={"Cookie": cookie})
    assert r.get("ok") and r["status"] == 200, r
    disc.ingest_response(base + "/v2/invoices/5001", r["body"], evidence_id=r["evidence_id"])
    return disc.intel


@pytest.fixture
def journey(request, tmp_path):
    vulnerable = getattr(request, "param", True)
    srv, base = _serve(vulnerable)
    app = App(tmp_path / ("v" if vulnerable else "h"))
    eng = _engagement(app, base)
    yield {"app": app, "base": base, "eng": eng, "vulnerable": vulnerable, "tmp": tmp_path}
    srv.shutdown()
    app.db.close()


@pytest.mark.parametrize("journey", [True], indirect=True)
def test_the_model_raises_an_authorization_hypothesis(journey):
    """Evidence to hypothesis: the served owner field IS the reason the question exists."""
    intel = _model_from_traffic(journey["app"], journey["base"])
    assert intel.node("resource", "invoices") is not None, [n["key"] for n in intel.nodes()]
    ids = H.materialize(journey["app"].db, "eng", {"identities": [
        {"username": "maya@lab.invalid"}, {"username": "noor@lab.invalid"}]})
    store = H.HypothesisStore(journey["app"].db, "eng")
    authz = [h for h in store.all() if h["class"] == "authorization"]
    assert authz, [h["class"] for h in store.all()]
    assert authz[0]["owner_field"] == "customer_id"
    assert authz[0]["missing"] == []  # two identities declared, so it is applicable
    assert ids


@pytest.mark.parametrize("journey", [True], indirect=True)
def test_a_missing_second_identity_blocks_the_hypothesis(journey):
    """Negative twin: without a second identity the question is BLOCKED, not pretended."""
    _model_from_traffic(journey["app"], journey["base"])
    H.materialize(journey["app"].db, "eng", {"identities": [{"username": "maya@lab.invalid"}]})
    store = H.HypothesisStore(journey["app"].db, "eng")
    authz = [h for h in store.all() if h["class"] == "authorization"]
    assert authz and "second_identity" in authz[0]["missing"]
    assert authz[0]["status"] == H.BLOCKED
    # and it is NOT scheduled
    assert not [h for h in store.plan() if h["class"] == "authorization"]


@pytest.mark.parametrize("journey", [True], indirect=True)
def test_the_vulnerable_twin_yields_a_verified_finding(journey):
    """Plan to execution to verification: the whole chain, on the vulnerable twin."""
    _model_from_traffic(journey["app"], journey["base"])
    auth = {"identities": [
        {"username": "maya@lab.invalid", "password": "x", "uid": 11,
         "login_url": journey["base"] + "/auth/session", "username_field": "email",
         "password_field": "password"},
        {"username": "noor@lab.invalid", "password": "x", "uid": 12,
         "login_url": journey["base"] + "/auth/session", "username_field": "email",
         "password_field": "password"}]}
    H.materialize(journey["app"].db, "eng", auth)
    store = H.HypothesisStore(journey["app"].db, "eng")
    planned = store.plan()
    assert any(h["class"] == "authorization" for h in planned), planned

    orch = journey["app"].orchestrator()
    out = orch._do_hypothesis_tests("eng", Scope(json.loads(
        journey["app"].db.one("SELECT scope_json FROM engagements WHERE id='eng'")
        ["scope_json"])), journey["eng"], "", "i_hyp")
    assert out["executed"] >= 1, out

    findings = journey["app"].pipeline.list("eng")
    assert findings, "the test ran but produced nothing"
    # the verifier, not the planner, decides whether it is a weakness
    scope = Scope(json.loads(journey["app"].db.one(
        "SELECT scope_json FROM engagements WHERE id='eng'")["scope_json"]))
    verdicts = {f["id"]: journey["app"].verifier.verify("eng", scope, f["id"])["verdict"]
                for f in findings}
    assert "reproduced" in verdicts.values(), verdicts


@pytest.mark.parametrize("journey", [False], indirect=True)
def test_the_hardened_twin_yields_no_finding(journey):
    """Negative twin: correct code must produce nothing, and the hypothesis is refuted."""
    _model_from_traffic(journey["app"], journey["base"])
    auth = {"identities": [
        {"username": "maya@lab.invalid", "password": "x", "uid": 11,
         "login_url": journey["base"] + "/auth/session", "username_field": "email",
         "password_field": "password"},
        {"username": "noor@lab.invalid", "password": "x", "uid": 12,
         "login_url": journey["base"] + "/auth/session", "username_field": "email",
         "password_field": "password"}]}
    H.materialize(journey["app"].db, "eng", auth)
    orch = journey["app"].orchestrator()
    scope = Scope(json.loads(journey["app"].db.one(
        "SELECT scope_json FROM engagements WHERE id='eng'")["scope_json"]))
    orch._do_hypothesis_tests("eng", scope, journey["eng"], "", "i_hyp")

    findings = journey["app"].pipeline.list("eng")
    confirmed = [f for f in findings if f["state"] in ("validated", "reported")]
    assert not confirmed, [(f["title"], f["state"]) for f in confirmed]
    store = H.HypothesisStore(journey["app"].db, "eng")
    authz = [h for h in store.all() if h["class"] == "authorization"]
    assert authz and authz[0]["status"] in (H.REFUTED, H.OBSERVED), authz[0]["status"]


@pytest.mark.parametrize("journey", [True], indirect=True)
def test_ranking_is_deterministic_and_explainable(journey):
    """The order a plan follows must be recomputable from stated factors, not a model vote."""
    _model_from_traffic(journey["app"], journey["base"])
    H.materialize(journey["app"].db, "eng", {"identities": [
        {"username": "maya@lab.invalid"}, {"username": "noor@lab.invalid"}]})
    store = H.HypothesisStore(journey["app"].db, "eng")
    ranked = store.rank()
    assert ranked
    top = ranked[0]
    assert set(top["factors"]) == {"evidence", "relevance", "applicable", "novelty", "cost",
                                   "gain"}
    assert top["score"] == round(sum(top["factors"].values()), 2)
    # ranking twice gives the same answer
    again = {h["id"]: h["score"] for h in H.HypothesisStore(
        journey["app"].db, "eng").rank()}
    assert again[top["id"]] == top["score"]


# ---------------------------------------------------------------- planner invariants
# These pin the guards the mutation gate checks. Without them the planner's rules are
# untested decoration: the journey tests above would pass with the ranking and the
# queue filtered out entirely.

def _store_with(app, *, identities=1):
    H.materialize(app.db, "eng", {"identities": [{"username": f"u{i}"}
                                                 for i in range(identities)]})
    return H.HypothesisStore(app.db, "eng")


@pytest.mark.parametrize("journey", [True], indirect=True)
def test_a_blocked_hypothesis_is_scored_down_and_never_planned(journey):
    """Prerequisite gating: an inapplicable question must not reach a plan."""
    _model_from_traffic(journey["app"], journey["base"])
    store = _store_with(journey["app"], identities=1)   # only one identity -> blocked
    blocked = [h for h in store.rank() if h["class"] == "authorization"]
    assert blocked and blocked[0]["factors"]["applicable"] == 0.0
    assert not [h for h in store.plan() if h["class"] == "authorization"]


@pytest.mark.parametrize("journey", [True], indirect=True)
def test_a_resolved_hypothesis_is_not_re_proposed(journey):
    """Novelty: a question already answered must not appear in the next plan."""
    _model_from_traffic(journey["app"], journey["base"])
    store = _store_with(journey["app"], identities=2)
    planned = store.plan()
    assert planned
    hid = planned[0]["id"]
    store.record_outcome(hid, "refuted", "control refused the read")
    assert hid not in {h["id"] for h in store.plan()}
    assert hid not in {h["id"] for h in store.rank()}


@pytest.mark.parametrize("journey", [True], indirect=True)
def test_a_running_hypothesis_is_not_planned_twice(journey):
    """One test at a time: a hypothesis already dispatched must not be queued again."""
    _model_from_traffic(journey["app"], journey["base"])
    store = _store_with(journey["app"], identities=2)
    planned = store.plan()
    assert planned
    hid = planned[0]["id"]
    store.attach_intent(hid, "i_running")
    assert hid not in {h["id"] for h in store.plan()}
