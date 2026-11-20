"""Fixtures for the platform audit: an in-process HTTP lab + App/TestClient.

Everything here is localhost-only; no external egress is ever attempted.
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
        self.huge_bytes = 32 * 1024 * 1024
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
                path = self.path.split("?")[0]
                if path == "/huge":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(lab.huge_bytes))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    try:
                        self.wfile.write(b"A" * lab.huge_bytes)
                    except Exception:
                        pass
                    return
                if path == "/redir-out":
                    self._send(302, b"", {"Location": lab.out_url})
                    return
                if path == "/redir-loop":
                    self._send(302, b"", {"Location": "/redir-loop"})
                    return
                if path == "/links":
                    body = "".join(f'<a href="/n{i}">x</a>' for i in range(2000))
                    self._send(200, body.encode())
                    return
                if path.startswith("/n") and path[2:].isdigit():
                    n = path[2:]
                    body = "".join(f'<a href="/n{n}{i}">y</a>' for i in range(2000))
                    self._send(200, f"<html><title>n{n}</title>{body}</html>".encode())
                    return
                self._send(200, b"<html><title>ok</title>hello libella</html>")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def lab():
    s = _Lab()
    yield s
    s.close()


@pytest.fixture
def other_lab():
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
            (eid, over.pop("name", "audit"), "safe_active", "draft", json.dumps(spec),
             json.dumps(over.pop("auth", {})), json.dumps(over.pop("budgets", {})), time.time()))
        return eid
    return make