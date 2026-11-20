"""Audit-2: a technology finding needs a signal, not just a 404.

The IIS short-name row has no body signature, so every IIS target whose 404 page
has any content "confirmed" short-name enumeration. That candidate carries a
reproducible proof request, so independent replay marked it validated: a false
positive that survives the platform's own gate.
"""
import threading

import pytest
from flask import Flask, Response
from werkzeug.serving import make_server

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.scope import Scope
from libella.tech_modules import TechAssess
from libella.tools.http_probe import HttpProbe


@pytest.fixture
def lab():
    servers = []

    def start(mode):
        app = Flask(f"audit2-tech-{mode}")

        @app.get("/")
        def home():
            return Response("<html><body>home</body></html>", status=200,
                            headers={"Server": "Microsoft-IIS/10.0"})

        @app.get("/<path:any>")
        def everything(any):
            if mode == "uniform":
                return Response("<html><body>404 - page not found</body></html>", status=404)
            # real IIS tilde behaviour: the 8.3 form is rejected differently
            if "~1." in any:
                return Response("<html><body>400 - bad request</body></html>", status=404)
            return Response("<html><body>404 - page not found</body></html>", status=404)

        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_port}"

    yield start
    for srv in servers:
        srv.shutdown()


def _assess(tmp_path, base, eid):
    db = DB(tmp_path / f"{eid}.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": base}], "categories": ["web"],
                   "rate_limit_rps": 1000})
    db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
               "VALUES(?, 'tech', 'safe_active', 'draft', ?, 0)", (eid, "{}"))
    return TechAssess(HttpProbe(db, ev), eid, scope)


def _titles(res):
    return [c["title"] for c in res["candidates"]]


def test_uniform_404_is_not_short_name_enumeration(tmp_path, lab):
    base = lab("uniform")
    res = _assess(tmp_path, base, "uniform").assess(base, ["iis"])
    hits = [t for t in _titles(res) if "short-name" in t]
    assert hits == [], f"false positive without a differential signal: {hits}"


def test_real_tilde_difference_is_still_reported(tmp_path, lab):
    base = lab("tilde")
    res = _assess(tmp_path, base, "tilde").assess(base, ["iis"])
    hits = [t for t in _titles(res) if "short-name" in t]
    assert hits, _titles(res)
