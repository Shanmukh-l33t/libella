"""Application intelligence: what the engine knows, and HOW it knows it.

The failure this guards against is a model-confident guess becoming an established fact.
Measured motivation: the agents matched the deterministic engine at 10 to 20 times the cost
because they had no application context and re-derived what was already known. A graph does
not fix that by existing; it fixes it only if a claim carries its provenance and an
unsupported claim cannot be promoted.

Every positive assertion here has a negative twin: an inferred node is not observed, a
promotion without evidence is refused, and a route whose name is unfamiliar is still found
because a request carried it rather than because a list named it.
"""
import json

import pytest

from libella.appintel import AppIntel
from libella.db import DB
from libella.discovery import Discovery


@pytest.fixture
def intel(tmp_path):
    db = DB(tmp_path / "d.sqlite")
    db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
               "VALUES('eng','e','safe_active','running','{}',0)")
    yield {"db": db, "intel": AppIntel(db, "eng"), "disc": Discovery(db, "eng")}
    db.close()


# ---------------------------------------------------------------- provenance rules

def test_a_guess_is_not_an_observation(intel):
    """An agent-proposed route stays hypothesized until evidence promotes it."""
    intel["intel"].add("endpoint", "GET /maybe", "/maybe", provenance="hypothesized")
    node = intel["intel"].node("endpoint", "GET /maybe")
    assert node["provenance"] == "hypothesized"
    assert intel["intel"].summary()["supported"] == 0
    assert intel["intel"].summary()["hypothesized"] == 1


def test_promotion_without_evidence_is_refused(intel):
    """The whole point: 'I am confident' is not evidence, so the store rejects it."""
    intel["intel"].add("endpoint", "GET /maybe", "/maybe", provenance="hypothesized")
    with pytest.raises(ValueError):
        intel["intel"].promote("endpoint", "GET /maybe", "observed", "")
    assert intel["intel"].node("endpoint", "GET /maybe")["provenance"] == "hypothesized"


def test_promotion_with_evidence_succeeds(intel):
    intel["intel"].add("endpoint", "GET /real", "/real", provenance="hypothesized")
    intel["intel"].promote("endpoint", "GET /real", "observed", "ev_1")
    assert intel["intel"].node("endpoint", "GET /real")["provenance"] == "observed"


def test_a_later_weaker_sighting_does_not_downgrade_a_node(intel):
    """Re-seeing an observed route through an inference must not weaken the record."""
    intel["intel"].add("route", "/orders", "/orders", provenance="observed", evidence_id="ev_1")
    intel["intel"].add("route", "/orders", "/orders", provenance="inferred")
    assert intel["intel"].node("route", "/orders")["provenance"] == "observed"


# ---------------------------------------------------------------- discovery from traffic

def test_discovery_records_routes_endpoints_and_parameters(intel):
    """Evidence: requests the application itself made, with unfamiliar names."""
    requests = [
        {"method": "GET", "url": "http://h/catalog/items?kind=hardware", "page": "http://h/"},
        {"method": "POST", "url": "http://h/tools/link-preview?target=x", "page": "http://h/"},
        {"method": "GET", "url": "http://h/v2/invoices/5002", "page": "http://h/bills"},
    ]
    out = intel["disc"].ingest_traffic(requests, evidence_id="ev_tr")
    assert out["routes"] == 3 and out["endpoints"] == 3
    # the numeric id is normalised so /5002 and /5003 are one route, not two
    assert intel["intel"].node("route", "/v2/invoices/{id}") is not None
    params = {p["key"] for p in intel["intel"].nodes("param")}
    assert params == {"kind", "target"}
    # every node came from a captured request, so all are observed
    assert all(n["provenance"] == "observed" for n in intel["intel"].nodes("endpoint"))


def test_a_destination_parameter_raises_a_server_side_fetch_question(intel):
    """The SSRF question comes from the app's own input surface, not a path list."""
    intel["disc"].ingest_traffic(
        [{"method": "GET", "url": "http://h/preview?where=http://x", "page": "http://h/"}],
        evidence_id="ev_1")
    features = intel["disc"].candidate_features()
    assert any(f["feature"] == "server-side fetch" for f in features)
    fetch = next(f for f in features if f["feature"] == "server-side fetch")
    assert "must not fetch arbitrary" in fetch["property"]
    assert fetch["provenance"] in ("inferred", "observed")


def test_a_place_valued_parameter_is_marked_whatever_its_name(intel):
    """`q` carrying a URL raises the fetch question: the VALUE is the evidence, not a list."""
    intel["disc"].ingest_traffic(
        [{"method": "GET", "url": "http://h/fetch?q=http://169.254.169.254/", "page": "http://h/"}],
        evidence_id="ev_1")
    param = intel["intel"].node("param", "q")
    assert param["data"]["destination_shaped"] is True
    assert param["data"]["because"] == "value"
    assert any(f["feature"] == "server-side fetch" for f in intel["disc"].candidate_features())


def test_a_word_valued_parameter_raises_nothing(intel):
    """Negative twin: `q=hello` is not a place, so no fetch question is invented."""
    intel["disc"].ingest_traffic(
        [{"method": "GET", "url": "http://h/search?q=hello", "page": "http://h/"}],
        evidence_id="ev_1")
    assert intel["intel"].node("param", "q")["data"]["destination_shaped"] is False
    assert not [f for f in intel["disc"].candidate_features() if f["feature"] == "server-side fetch"]


# ---------------------------------------------------------------- resource and owner

def test_a_served_record_yields_the_resource_and_its_owner(intel):
    """Ownership comes from the record the app published, not from a guess about ids."""
    body = json.dumps({"invoice": {"id": 5002, "customer_id": 12, "memo": "x"},
                       "links": {"self": "/v2/invoices/5002"}})
    out = intel["disc"].ingest_response("http://h/v2/invoices/5002", body, evidence_id="ev_2")
    assert out["resource"] == "invoices"
    assert out["owner_field"] == "customer_id" and out["owner_value"] == 12
    res = intel["intel"].node("resource", "invoices")
    owners = [e for e in intel["intel"].edges(res["id"]) if e["kind"] == "owned_by"]
    assert owners and owners[0]["other"]["label"] == "customer_id"


def test_an_unfamiliar_owner_field_is_still_found_by_shape(intel):
    """`ownerId` is not in the vocabulary: a record naming an owner is enough."""
    out = intel["disc"].ingest_response(
        "http://h/v2/invoices/9", json.dumps({"data": {"id": 9, "ownerId": 7}}), evidence_id="e")
    assert out["owner_field"] == "ownerId"


def test_an_ownership_question_requires_an_owner(intel):
    """No owner field means no authorization question: silence, not a fabricated one."""
    intel["disc"].ingest_response("http://h/v2/notes/1",
                                 json.dumps({"id": 1, "text": "hi"}), evidence_id="e")
    assert not [f for f in intel["disc"].candidate_features() if "ownership" in f["feature"]]


# ---------------------------------------------------------------- bundles and specs

def test_bundle_strings_are_source_provenance_not_observation(intel):
    """Code says a route exists; that is weaker than a request having used it."""
    out = intel["disc"].ingest_bundle(
        'fetch("/api/admin/stats"); client.get("/rest/wallet")', source_ref="main.js")
    assert out["routes"] == 2
    node = intel["intel"].node("route", "/api/admin/stats")
    assert node["provenance"] == "source" and node["source_ref"] == "main.js"


def test_openapi_is_spec_provenance_and_names_its_parameters(intel):
    spec = {"paths": {"/api/hop": {"get": {"parameters": [
        {"name": "where", "in": "query", "schema": {"type": "string", "format": "uri"}}]}}}}
    out = intel["disc"].ingest_openapi(spec, base="http://h", source_ref="/openapi.json")
    assert out["endpoints"] == 1
    assert intel["intel"].node("route", "/api/hop")["provenance"] == "spec"
    assert intel["intel"].node("param", "where")["data"]["destination_shaped"] is True


# ---------------------------------------------------------------- retrieval and gaps

def test_context_is_relevant_and_reports_what_it_left_out(intel):
    """Retrieval must not be a dump: it names the focus, the totals and the truncation."""
    for i in range(30):
        intel["disc"].ingest_traffic(
            [{"method": "GET", "url": f"http://h/api/thing{i}?q=1", "page": "http://h/"}],
            evidence_id=f"ev{i}")
    ctx = intel["intel"].context("/api/thing7", limit=5)
    assert ctx["focus"] == "/api/thing7"
    # the totals state the whole application even when the focus narrows the answer, so an
    # agent can see it is working from one endpoint out of thirty
    assert ctx["totals"]["endpoint"] == 30
    # the answer is the neighbourhood, not just the match: the endpoint, its parameter and
    # the route it belongs to are exactly what an agent needs to frame a test
    keys = [i["key"] for i in ctx["items"]]
    assert any(k.endswith("/api/thing7") for k in keys)
    assert any(i["kind"] == "route" for i in ctx["items"])
    assert all("thing" in k or k == "q" for k in keys)
    # nothing was dropped for this focus, so truncation is honestly False ...
    assert ctx["truncated"] is False
    # ... while a focus that matches everything reports it
    wide = intel["intel"].context("/api/thing", limit=5)
    assert wide["truncated"] is True and len(wide["items"]) <= 5


def test_gaps_are_stated_rather_than_silent(intel):
    """An agent must know where its knowledge stops, or it re-tests and invents."""
    intel["disc"].ingest_traffic(
        [{"method": "GET", "url": "http://h/api/orders", "page": "http://h/"}],
        evidence_id="ev")
    gaps = {g["gap"] for g in intel["intel"].gaps()}
    assert "no_roles" in gaps and "no_workflows" in gaps
    assert "unknown_parameters" in gaps
