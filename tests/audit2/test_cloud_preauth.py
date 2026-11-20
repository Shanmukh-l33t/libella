"""Audit-2: cloud audit must authorize BEFORE it dials, and must not let the
target declare its own identity.

Attacks under test:
  1. an account the engagement does not own must not even be contacted
     (GetCallerIdentity was issued with the caller's creds before the scope
     decision, so the platform was an SSRF primitive).
  2. a target endpoint cannot self-report the authorized account id to pass the
     check while being a different account.
  3. a *hostname* resolving to the metadata IP must be refused, not just a
     literal 169.254.169.254 (boto3 would happily dial it).
"""
import threading

import pytest
from flask import Flask

from libella.cloud_audit import _validate_inputs, assess_cloud
from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.scope import Scope
from werkzeug.serving import make_server

STS_XML = """<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult><Account>{account}</Account>
  <Arn>arn:aws:iam::{account}:user/lab</Arn><UserId>AIDAEXAMPLE</UserId>
  </GetCallerIdentityResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"""


class FakeCloud:
    """Minimal STS responder: reports whatever account the test tells it to."""

    def __init__(self, account):
        self.account = account
        self.hits = 0
        app = Flask("audit2-cloud")

        @app.post("/")
        def sts():
            self.hits += 1
            body = STS_XML.format(account=self.account)
            return body, 200, {"Content-Type": "text/xml"}

        @app.get("/")
        def get():
            self.hits += 1
            return STS_XML.format(account=self.account), 200, {"Content-Type": "text/xml"}

        self.srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.endpoint = f"http://127.0.0.1:{self.srv.server_port}"

    def close(self):
        self.srv.shutdown()


def _env(tmp_path, scope_value, eid="eng_cloud"):
    db = DB(tmp_path / f"{eid}.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    spec = {"targets": [{"kind": "cloud", "value": scope_value}], "categories": ["cloud"]}
    return db, ev, FindingPipeline(db, ev), Scope(spec)


CREDS = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret"}


def test_out_of_scope_account_is_never_contacted(tmp_path):
    cloud = FakeCloud("123456789012")
    try:
        db, ev, pipe, scope = _env(tmp_path, "999999999999")
        res = assess_cloud(cloud.endpoint, "us-east-1", CREDS, db, ev, pipe, scope, "eng_cloud")
        assert res["refused"] is True, res
        assert cloud.hits == 0, "authorization must be decided before any request leaves"
        assert db.one("SELECT COUNT(*) n FROM evidence")["n"] == 0
    finally:
        cloud.close()


def test_declared_account_must_match_the_target(tmp_path):
    """The endpoint cannot self-report the authorized account id."""
    cloud = FakeCloud("999999999999")
    try:
        db, ev, pipe, scope = _env(tmp_path, "123456789012")
        res = assess_cloud(cloud.endpoint, "us-east-1", CREDS, db, ev, pipe, scope, "eng_cloud",
                           account_id="123456789012")
        assert res["refused"] is True, res
        assert "identity" in res["reason"] or "account" in res["reason"]
    finally:
        cloud.close()


def test_declared_account_match_proceeds(tmp_path):
    cloud = FakeCloud("123456789012")
    try:
        db, ev, pipe, scope = _env(tmp_path, "123456789012")
        res = assess_cloud(cloud.endpoint, "us-east-1", CREDS, db, ev, pipe, scope, "eng_cloud",
                           account_id="123456789012")
        # the fake endpoint answers only STS, so every profile check degrades on its own
        # (an unparseable response must never abort the run); the authorized dial happened.
        assert res.get("refused") is not True, res
        assert res["ok"] is False and res["errors"], res
        assert cloud.hits >= 1
    finally:
        cloud.close()


def test_hostname_resolving_to_metadata_is_refused(monkeypatch):
    import socket as _socket
    real = _socket.getaddrinfo

    def fake(host, *a, **kw):
        if host == "metadata.internal.test":
            return [(2, 1, 6, "", ("169.254.169.254", 0))]
        return real(host, *a, **kw)

    monkeypatch.setattr(_socket, "getaddrinfo", fake)
    with pytest.raises(ValueError, match="metadata|link-local"):
        _validate_inputs("http://metadata.internal.test:5000", "us-east-1", CREDS)
