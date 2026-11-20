"""Audit-2: a workflow must not be able to navigate the browser out of scope
through a popup.

`page.route(...)` is registered per page; a `window.open()` creates a new page
in the same persistent context, which inherits the cookies but carried no
request guard. A target page could therefore make the agent's browser fetch any
out-of-scope origin (and the request is logged as "the agent did it").
"""
import threading
import time

import pytest
from flask import Flask
from werkzeug.serving import make_server

from libella.auth_browser import AuthBrowser
from libella.browser_crawl import browser_available
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.scope import Scope

pytestmark = pytest.mark.skipif(not browser_available(), reason="playwright/chromium absent")


class Sink:
    def __init__(self):
        self.hits: list[str] = []
        sink = self
        app = Flask("audit2-sink")

        @app.get("/steal")
        def steal():
            sink.hits.append("steal")
            return "secret"

        self.srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_port}"


@pytest.fixture(scope="module")
def sink():
    s = Sink()
    yield s
    s.srv.shutdown()


@pytest.fixture(scope="module")
def target(sink):
    app = Flask("audit2-target")

    @app.get("/")
    def home():
        return ("<html><body><h1>home</h1>"
                "<button id='go' onclick=\"window.open('%s/steal')\">go</button>"
                "</body></html>" % sink.base)

    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_popup_cannot_reach_out_of_scope_origin(tmp_path, target, sink):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": target}], "categories": ["web"],
                   "rate_limit_rps": 1000})
    with AuthBrowser(db, ev, scope, "eng") as browser:
        res = browser.run_workflow([
            {"action": "navigate", "value": target + "/"},
            {"action": "click", "selector": "#go"},
        ])
    time.sleep(0.5)  # let any popup request land
    assert sink.hits == [], f"popup escaped scope: {sink.hits}"
    assert res["evidence_id"]
