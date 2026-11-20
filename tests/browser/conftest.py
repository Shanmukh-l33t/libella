"""Browser-module fixtures: a tiny Flask SPA and an external "third party" sink.

Both run on ephemeral 127.0.0.1 ports, so the cross-origin test is a real
different origin (port) without any external egress.
"""
import sys
import threading
from pathlib import Path

import pytest
from flask import Flask, jsonify
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.scope import Scope  # noqa: E402

SHELL = """<!doctype html><html><head><title>Libella SPA</title></head><body>
<div id="app">loading</div>
<script>
fetch('/api/data').then(r => r.json()).then(d => {
  const root = document.getElementById('app');
  root.textContent = 'ready: ' + d.items.join(',');
  const admin = document.createElement('a');
  admin.href = '/admin';
  admin.textContent = 'Admin panel';
  root.appendChild(admin);
  const cross = document.createElement('a');
  cross.href = '/cross';
  cross.textContent = 'Third party';
  root.appendChild(cross);
});
</script></body></html>"""

ADMIN = """<!doctype html><html><head><title>Admin</title></head><body>
<h1>Admin</h1><a href="/">home</a>
<script>fetch('/api/admin/stats').then(r => r.json());</script></body></html>"""

CROSS = """<!doctype html><html><head><title>Cross</title></head><body>
<script>
fetch('http://127.0.0.1:%d/steal').then(r => r.text()).catch(() => {});
</script></body></html>"""


def _serve(app) -> tuple:
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


class Spa:
    def __init__(self):
        self.sink_hits: list[str] = []
        self.sink_srv, self.sink_base = self._sink()
        app = Flask("spa-fixture")

        @app.get("/")
        def index():
            return SHELL

        @app.get("/admin")
        def admin():
            return ADMIN

        @app.get("/cross")
        def cross():
            return CROSS % int(self.sink_base.rsplit(":", 1)[1])

        @app.get("/api/data")
        def data():
            return jsonify({"items": ["a", "b"]})

        @app.get("/api/admin/stats")
        def stats():
            return jsonify({"users": 3})

        self.srv, self.base = _serve(app)

    def _sink(self):
        app = Flask("sink")

        @app.get("/steal")
        def steal():
            self.sink_hits.append("steal")
            return "secret"

        return _serve(app)

    def close(self):
        self.srv.shutdown()
        self.sink_srv.shutdown()


@pytest.fixture(scope="session")
def spa():
    s = Spa()
    yield s
    s.close()


@pytest.fixture
def engine(tmp_path, spa):
    db = DB(tmp_path / "browser.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": spa.base}],
                   "categories": ["recon", "web", "api"], "rate_limit_rps": 50})
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        ("eng_browser", "browser fixture", "safe_active", "draft", "{}", "{}", "{}", 0.0))
    return db, ev, scope
