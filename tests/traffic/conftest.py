"""Fixtures for the traffic workspace: in-process HTTP lab + App/TestClient.

Localhost only; the lab never reaches outside 127.0.0.1.
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.api import App, create_api  # noqa: E402
from libella.scope import Scope  # noqa: E402


class _Lab:
    def __init__(self):
        self.hits: list[str] = []
        self.bodies: list[bytes] = []
        self.headers: list[dict] = []  # request headers per hit (replay fidelity)
        self.cookie = "lab-session-cookie"  # value /login sends back as Set-Cookie
        self.out_url = "http://127.0.0.1:1/never"
        lab = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status, body: bytes, headers: dict | None = None):
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            def do_GET(self):
                lab.hits.append(self.path)
                lab.headers.append({k.lower(): v for k, v in self.headers.items()})
                path = self.path.split("?")[0]
                if path == "/login":
                    return self._send(200, b"ok", {"Set-Cookie": f"session={lab.cookie}; HttpOnly"})
                if path == "/redir-out":
                    return self._send(302, b"", {"Location": lab.out_url})
                if path == "/404":
                    return self._send(404, b"missing")
                self._send(200, b"static-lab-marker")

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                lab.hits.append(self.path)
                lab.bodies.append(body)
                self._send(200, body + b"|echo|" + self.headers.get("x-label", "").encode())

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def lab():
    s = _Lab()
    yield s
    s.close()


@pytest.fixture
def app(tmp_path):
    return App(tmp_path / "data")


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    return TestClient(create_api(app))


@pytest.fixture
def scope_for():
    def make(base: str, **over):
        spec = {"targets": [{"kind": "url", "value": base}],
                "categories": ["recon", "web", "api", "infra"],
                "rate_limit_rps": 1000, "max_concurrency": 2}
        spec.update(over)
        return Scope(spec)
    return make


@pytest.fixture
def mk_eng(app):
    def make(base: str, **over):
        spec = {"targets": [{"kind": "url", "value": base}],
                "categories": ["recon", "web", "api", "infra"]}
        spec.update(over.pop("scope", {}))
        eid = f"eng_test_{int(time.time() * 1e6)}"
        app.db.execute(
            "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
            "budgets_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (eid, over.pop("name", "traffic"), "safe_active", "draft", json.dumps(spec),
             json.dumps(over.pop("auth", {})), json.dumps(over.pop("budgets", {})), time.time()))
        return eid
    return make
