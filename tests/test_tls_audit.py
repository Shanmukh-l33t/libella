"""TLS audit tests: positive (expired/mismatch/weak) + negative (valid) controls."""
import ssl
import threading
import time
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.scope import Scope
from libella.tls_audit import audit_tls, scan_tls
from libella.verifier import Verifier
from libella.tools.http_probe import HttpProbe

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "tlslab"))
from app import ensure_certs, CERTS, app as lab_app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def certs():
    ensure_certs()


def serve(cert_tag: str, min_tls, port_holder: dict):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERTS / f"{cert_tag}.crt", CERTS / f"{cert_tag}.key")
    ctx.minimum_version = min_tls
    if min_tls == ssl.TLSVersion.TLSv1:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    srv = make_server("127.0.0.1", 0, lab_app, ssl_context=ctx)
    port_holder["port"] = srv.port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    return srv


@pytest.fixture
def platform(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    probe = HttpProbe(db, ev)
    pipe = FindingPipeline(db, ev)
    ver = Verifier(db, ev, probe, pipe)
    return db, ev, pipe, ver


def _scope(port):
    return Scope({"targets": [{"kind": "url", "value": f"https://127.0.0.1:{port}"}],
                  "categories": ["infra", "web"]})


def test_expired_and_weak_detected_and_validated(platform):
    db, ev, pipe, ver = platform
    holder = {}
    srv = serve("expired", ssl.TLSVersion.TLSv1, holder)
    port = holder["port"]
    try:
        scope = _scope(port)
        res = audit_tls("127.0.0.1", port, db, ev, pipe, scope, "eng")
        titles = [db.one("SELECT title FROM findings WHERE id=?", (r["id"],))["title"] for r in res]
        assert any("Expired" in t for t in titles), titles
        assert any("Weak TLS" in t for t in titles), titles
        for r in res:
            v = ver.verify("eng", scope, r["id"])
            assert v["verdict"] == "reproduced", v
            assert db.one("SELECT state FROM findings WHERE id=?", (r["id"],))["state"] == "validated"
    finally:
        srv.shutdown()


def test_hostname_mismatch_detected(platform):
    db, ev, pipe, ver = platform
    holder = {}
    srv = serve("mismatch", ssl.TLSVersion.TLSv1_2, holder)
    port = holder["port"]
    try:
        scope = _scope(port)
        res = audit_tls("127.0.0.1", port, db, ev, pipe, scope, "eng")
        titles = [db.one("SELECT title FROM findings WHERE id=?", (r["id"],))["title"] for r in res]
        assert any("hostname mismatch" in t for t in titles), titles
    finally:
        srv.shutdown()


def test_valid_server_zero_findings(platform):
    db, ev, pipe, ver = platform
    holder = {}
    srv = serve("valid", ssl.TLSVersion.TLSv1_2, holder)
    port = holder["port"]
    try:
        scope = _scope(port)
        res = audit_tls("127.0.0.1", port, db, ev, pipe, scope, "eng")
        assert res == [], res
        facts = scan_tls("127.0.0.1", port)
        assert facts["expired"] is False
        assert facts["hostname_match"] is True
        assert facts["weak_protocols"] == []
    finally:
        srv.shutdown()


def test_out_of_scope_refused(platform):
    db, ev, pipe, ver = platform
    holder = {}
    srv = serve("valid", ssl.TLSVersion.TLSv1_2, holder)
    port = holder["port"]
    try:
        scope = Scope({"targets": [{"kind": "url", "value": "https://other.invalid:443"}],
                       "categories": ["infra"]})
        res = audit_tls("127.0.0.1", port, db, ev, pipe, scope, "eng")
        assert res == []
        assert db.one("SELECT COUNT(*) n FROM events WHERE kind='scope_refusal'")["n"] == 1
    finally:
        srv.shutdown()
