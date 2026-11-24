"""Authenticated role matrix: the seeded leaks are found, the correct checks stay silent.

RoleLab (labs/rolelab) has two planted bugs — /reports-all serving anonymous
callers and /api/users/<id> reading anyone — and a /hard/* mirror of every
route done correctly. A finding needs a differential control, so the controls
are asserted as hard as the findings: no candidate may come out of the
owner-only order route, the admin-only note, or any /hard/* route.
"""
import importlib.util
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402
from libella.privesc_audit import _crossings, audit_role_matrix  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402

ENDPOINTS = [
    {"method": "GET", "path": "/api/me"},
    {"method": "GET", "path": "/api/orders/{id}"},
    {"method": "GET", "path": "/api/orders/{id}/admin-note"},
    {"method": "GET", "path": "/api/reports"},
    {"method": "GET", "path": "/reports-all"},
    {"method": "GET", "path": "/api/users/{id}"},
    {"method": "POST", "path": "/api/reports/create"},
]
HARD = [{"method": e["method"], "path": "/hard" + e["path"]} for e in ENDPOINTS]


def _rolelab():
    spec = importlib.util.spec_from_file_location("rolelab_app", ROOT / "labs/rolelab/app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ROLELAB = _rolelab()


@pytest.fixture(scope="module")
def lab():
    srv = make_server("127.0.0.1", 0, ROLELAB.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


class Engine:
    def __init__(self, tmp_path, base):
        self.base = base
        self.db = DB(tmp_path / "privesc.db")
        self.ev = EvidenceStore(self.db, tmp_path / "ev")
        self.probe = HttpProbe(self.db, self.ev)
        self.pipe = FindingPipeline(self.db, self.ev)
        self.scope = Scope({"targets": [{"kind": "url", "value": base}],
                            "categories": ["web", "api"], "rate_limit_rps": 1000})

    def auth(self, identities=("alice", "bob"), **hints):
        return {"base_url": self.base,
                "identities": [{"username": u, "password": ROLELAB.USERS[u][1],
                                "role": ROLELAB.USERS[u][2],
                                "login_url": self.base + "/api/login"} for u in identities],
                "test_hints": hints}

    def run(self, auth, endpoints):
        return audit_role_matrix(self.db, self.ev, self.probe, self.scope, "eng", auth,
                                 self.pipe, endpoints=endpoints)


def _run(tmp_path, lab, endpoints=ENDPOINTS, identities=("alice", "bob"), **hints):
    e = Engine(tmp_path, lab)
    return e, e.run(e.auth(identities, **hints), endpoints)


def test_seeded_leaks_are_found_and_correct_controls_are_silent(tmp_path, lab):
    _, out = _run(tmp_path, lab)
    assert out["status"] == "assessed", out["limitations"]
    found = {(c["cwe"], urlparse(c["endpoint"]).path) for c in out["candidates"]}
    assert found == {("CWE-306", "/reports-all"), ("CWE-639", "/api/users/2")}, found
    bola = next(c for c in out["candidates"] if c["cwe"] == "CWE-639")
    assert "bob" in bola["quote"], bola["quote"]  # bob's record, verbatim
    assert all("role_pair" in c["description"] for c in out["candidates"])
    # the correctly enforced admin route, the owner-only order and the manager
    # collection produced no candidate: only the two planted bugs did
    assert not [c for c in out["candidates"] if "admin-note" in c["endpoint"]]


def test_hardened_controls_yield_no_candidates(tmp_path, lab):
    _, out = _run(tmp_path, lab, endpoints=HARD)
    assert out["candidates"] == []
    gets = [r for r in out["matrix"] if r["method"] == "GET"]
    assert gets and all(r["class"] in ("ALLOWED", "DENIED") for r in gets)


def test_matrix_covers_every_pair_and_writes_are_never_sent(tmp_path, lab):
    e, out = _run(tmp_path, lab)
    assert len(out["matrix"]) == len(ENDPOINTS) * 2
    assert {(r["identity"], r["method"], r["path"]) for r in out["matrix"]} == {
        (u, ep["method"], ep["path"]) for u in ("alice", "bob") for ep in ENDPOINTS}
    assert all(r["class"] == "UNEXERCISED" for r in out["matrix"]
               if r["path"] == "/api/reports/create")
    # one login per identity, and no write reached the wire without a declaration
    assert len(e.db.query("SELECT id FROM exchanges WHERE tool='role_login'")) == 2
    assert e.db.query("SELECT id FROM exchanges WHERE tool<>'role_login' "
                      "AND method IN ('POST','PUT','PATCH','DELETE')") == []


def test_operator_declared_write_is_exercised(tmp_path, lab):
    e, out = _run(tmp_path, lab, allow_writes=["POST /api/reports/create"])
    rows = [r for r in out["matrix"] if r["path"] == "/api/reports/create"]
    assert rows and all(r["class"] == "DENIED" for r in rows)  # alice/bob are users
    assert len(e.db.query("SELECT id FROM exchanges WHERE tool='role_matrix' AND method='POST'")) == 2


def test_two_identities_are_required(tmp_path, lab):
    e, out = _run(tmp_path, lab, identities=("alice",))
    assert out["matrix"] == [] and out["limitations"]
    assert e.db.query("SELECT id FROM exchanges") == []


def test_identity_that_cannot_log_in_is_a_limitation(tmp_path, lab):
    e = Engine(tmp_path, lab)
    auth = e.auth()
    auth["identities"][1]["password"] = "wrong-password"
    out = audit_role_matrix(e.db, e.ev, e.probe, e.scope, "eng", auth, e.pipe, endpoints=ENDPOINTS)
    assert any("bob" in reason for reason in out["limitations"])
    assert all(row["identity"] == "alice" for row in out["matrix"])


def test_cross_role_contradictions_are_pairwise():
    def row(user, role, cls, path="/api/reports"):
        return {"identity": user, "role": role, "method": "GET", "path": path, "class": cls}

    same = [row("alice", "user", "ALLOWED"), row("bob", "user", "DENIED"),
            row("carol", "manager", "ALLOWED")]
    assert [k for *_, k in _crossings(same)] == ["same_role"]
    inverted = [row("alice", "user", "ALLOWED"), row("carol", "manager", "DENIED")]
    assert [k for *_, k in _crossings(inverted)] == ["inverted"]
    correct = [row("alice", "user", "DENIED"), row("carol", "manager", "ALLOWED")]
    assert _crossings(correct) == []
    # an object route is BOLA's business, never a role contradiction
    assert _crossings([row("alice", "user", "ALLOWED", "/api/users/{id}"),
                       row("bob", "user", "DENIED", "/api/users/{id}")]) == []
