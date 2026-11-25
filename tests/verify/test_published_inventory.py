"""Discovery must come from the application's own published description, not a name list.

SSRF and parameter probing were driven by fixed path lists: `COMMON_FETCH_PATHS` named
`/fetch`, `/proxy` and friends until someone thought of them. That is tuning, not
discovery: an unfamiliar app whose fetcher is called `/link-preview` is invisible to it.

A JSON API that publishes OpenAPI states its own paths and parameter names, so the engine
can read the inventory with evidence instead. Both directions are asserted here: a
published document yields its endpoints, and an app that publishes nothing yields none (so
the fixed lists remain the fallback rather than being silently replaced).
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from libella.checks import WebChecks
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.scope import Scope
from libella.tools.http_probe import HttpProbe

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "holdlab-api", "version": "1"},
    "paths": {
        "/catalog/search": {"get": {"parameters": [
            {"name": "kind", "in": "query", "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}}},
        "/tools/link-preview": {"get": {"parameters": [
            {"name": "target", "in": "query", "schema": {"type": "string", "format": "uri"}}],
            "responses": {"200": {"description": "ok"}}}},
        # a name that is NOT destination-shaped: the only signal is schema format uri
        "/api/hop": {"get": {"parameters": [
            {"name": "where", "in": "query", "schema": {"type": "string", "format": "uri"}}],
            "responses": {"200": {"description": "ok"}}}},
        "/api/picture": {"get": {"parameters": [
            {"name": "src", "in": "query", "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}}},
        "/api/items/{id}": {"get": {"parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "responses": {"200": {"description": "ok"}}}},
    },
}


def _serve(document: dict | None, path: str = "/openapi.json"):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib signature
            if document is not None and self.path.split("?")[0] == path:
                body = json.dumps(document).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):  # noqa: A002 - stdlib signature
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def checks_for(request, tmp_path):
    document, path = request.param if isinstance(request.param, tuple) else (request.param, "/openapi.json")
    srv = _serve(document, path)
    base = f"http://127.0.0.1:{srv.server_port}"
    db = DB(tmp_path / "d.sqlite")
    evidence = EvidenceStore(db, tmp_path / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": base}], "categories": ["web", "api"],
                   "rate_limit_rps": 200})
    yield {"checks": WebChecks(HttpProbe(db, evidence), "eng", scope, db), "base": base}
    srv.shutdown()
    db.close()


@pytest.mark.parametrize("checks_for", [SPEC], indirect=True)
def test_a_published_document_supplies_the_inventory(checks_for):
    out = checks_for["checks"].published_endpoints(checks_for["base"])
    assert out["source"] == "/openapi.json"
    urls = {e["url"].rsplit("/", 1)[-1]: e for e in out["endpoints"]}
    assert "search" in urls and urls["search"]["params"] == ["kind"]
    # a url-formatted parameter marks the endpoint as one that fetches
    assert "link-preview" in urls and urls["link-preview"]["takes_url"] is True
    # so does a destination-shaped name even without the format
    assert "picture" in urls and urls["picture"]["takes_url"] is True
    # format uri marks it even when the name says nothing
    assert "hop" in urls and urls["hop"]["takes_url"] is True
    # a plain id parameter does not
    assert "items" in urls and urls["items"]["takes_url"] is False


@pytest.mark.parametrize("checks_for", [(SPEC, "/v3/api-docs")], indirect=True)
def test_an_alternate_published_location_is_found(checks_for):
    """Not every app publishes at /openapi.json; springdoc uses /v3/api-docs."""
    out = checks_for["checks"].published_endpoints(checks_for["base"])
    assert out["source"] == "/v3/api-docs"
    assert len(out["endpoints"]) == 5


@pytest.mark.parametrize("checks_for", [None], indirect=True)
def test_an_app_that_publishes_nothing_yields_nothing(checks_for):
    """Negative control: the fallback lists must still be usable, so this returns empty."""
    out = checks_for["checks"].published_endpoints(checks_for["base"])
    assert out["source"] is None
    assert out["endpoints"] == []


@pytest.mark.parametrize("checks_for", [{"paths": "not a dict"}], indirect=True)
def test_a_malformed_document_is_refused(checks_for):
    """A body that is not OpenAPI must not be mined for endpoint names."""
    out = checks_for["checks"].published_endpoints(checks_for["base"])
    assert out["endpoints"] == []
