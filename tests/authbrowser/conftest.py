"""Fixtures: real AuthLab twins on 127.0.0.1, an out-of-scope sink, an engagement.

Both lab modes run in-process on ephemeral ports, so vuln and hardened are real
different origins (ports) without any external egress.
"""
import importlib.util
import json
import sys
import threading
from pathlib import Path

import pytest
from flask import Flask
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.scope import Scope  # noqa: E402


def _load(name: str, rel: str):
    """Private module load: tests/api and tests/cloud also own a module named labctl."""
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


labctl = _load("authlab_labctl", "labs/authlab/labctl.py")
GT = json.loads((ROOT / "labs/authlab/ground_truth.json").read_text())
IDENT = {i["username"]: i for i in GT["identities"]}
LOGIN = GT["login"]


@pytest.fixture(scope="session")
def lab_checks():
    return _load("authlab_ground_truth", "labs/authlab/verify_ground_truth.py").checks


@pytest.fixture(scope="session")
def labs():
    started = {m: labctl.start_lab(m) for m in ("vuln", "hardened")}
    yield {m: base for m, (base, _) in started.items()}
    for _, srv in started.values():
        srv.shutdown()


class Sink:
    """Out-of-scope origin: any hit here means a scope check failed."""

    def __init__(self):
        self.hits: list[str] = []
        app = Flask("authlab-sink")

        @app.get("/steal")
        def steal():
            self.hits.append("steal")
            return "secret"

        self.srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_port}"


@pytest.fixture(scope="session")
def sink():
    s = Sink()
    yield s
    s.srv.shutdown()


def _engine(tmp: Path, base: str):
    db = DB(tmp / "auth.db")
    ev = EvidenceStore(db, tmp / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": base}],
                   "categories": ["recon", "web", "api"], "rate_limit_rps": 1000})
    db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("eng_auth", "authlab", "safe_active", "draft", json.dumps({"targets": [
            {"kind": "url", "value": base}]}), "{}", "{}", 0.0))
    return db, ev, scope, base


@pytest.fixture
def engine(tmp_path, labs):
    return _engine(tmp_path / "vuln", labs["vuln"])


@pytest.fixture
def hardened_engine(tmp_path, labs):
    return _engine(tmp_path / "hardened", labs["hardened"])


@pytest.fixture
def do_login():
    """Form login through the lab's real login page -> auth_contexts row."""

    def _login(browser, base, username, password=None, assertion=None):
        return browser.login_flow(
            base, base + LOGIN["url"], username,
            IDENT[username]["password"] if password is None else password,
            LOGIN["selectors"],
            LOGIN["success_assertion"] if assertion is None else assertion)

    return _login


@pytest.fixture
def identities():
    return [{"username": "alice", "password": IDENT["alice"]["password"], "expected": "deny"},
            {"username": "bob", "password": IDENT["bob"]["password"], "expected": "allow"}]


@pytest.fixture
def login_kwargs():
    return {"selectors": LOGIN["selectors"], "success_assertion": LOGIN["success_assertion"]}
