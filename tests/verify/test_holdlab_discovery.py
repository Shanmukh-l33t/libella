"""Discovery against the holdout lab: envelope reading and the object-enumeration branches.

The holdout twin exists because the PairLab fixture could not tell a general fix from a
tuned one: its endpoints are named plainly and its rows start at 1. Here the record is
wrapped in a named envelope, the owner column is `customer_id`, the collection requires a
session, and the ids start at 5001.

Two guards are pinned here because nothing else exercised them:
  * the record must be unwrapped from its envelope before an owner is read, otherwise the
    ownership check sees a wrapper and reports "ownership unshown";
  * an object readable with NO credential is a missing-authentication finding (CWE-306),
    not an ownership finding, and certainly not a silent skip.
"""
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
HOLDLAB = ROOT / "labs" / "holdlab"

from libella.checks import WebChecks  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402


def _serve(mode: str):
    """Start the holdout lab in-process on an ephemeral port, in the requested mode."""
    os.environ["LAB_MODE"] = mode
    os.environ["LAB_PORT"] = "0"
    import importlib.util

    for name in [n for n in list(sys.modules) if n.startswith("holdlab_")]:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(f"holdlab_{mode}", HOLDLAB / "app.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"holdlab_{mode}"] = module
    spec.loader.exec_module(module)
    # the lab reads PORT at import time; werkzeug binds the real port, so the SSRF allowlist
    # inside the app does not matter for these checks
    srv = make_server("127.0.0.1", 0, module.app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return module, srv


@pytest.fixture
def hold(request, tmp_path):
    mode = getattr(request, "param", "vuln")
    module, srv = _serve(mode)
    base = f"http://127.0.0.1:{srv.server_port}"
    db = DB(tmp_path / f"{mode}.sqlite")
    evidence = EvidenceStore(db, tmp_path / f"ev-{mode}")
    scope = Scope({"targets": [{"kind": "url", "value": base}], "categories": ["web"],
                   "rate_limit_rps": 200})
    probe = HttpProbe(db, evidence)
    yield {"base": base, "db": db, "probe": probe, "scope": scope,
           "checks": WebChecks(probe, "eng", scope, db), "module": module}
    srv.shutdown()
    db.close()


def _login(env) -> tuple[str, int]:
    """Sign in as maya through the scoped probe and return her cookie header."""
    r = env["probe"].request("eng", env["scope"], env["base"] + "/auth/session", method="POST",
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             body="email=maya@holdlab.invalid&passcode=maya-pass-9921",
                             tool="login")
    assert r["ok"] and r["status"] == 200, r
    jar = [v for k, v in r["headers"].items() if k.lower() == "set-cookie"]
    cookie = "; ".join(j.split(";")[0] for j in jar)
    assert cookie, "the lab did not set a session cookie"
    return cookie, 11


def test_a_named_envelope_does_not_hide_the_owner(hold):
    """The record, not its wrapper, must be read: {"invoice": {...}} carries the owner."""
    from libella.checks import _owner_of
    body = json.dumps({"invoice": {"id": 5002, "customer_id": 12, "memo": "Canvas x2"},
                       "links": {"self": "/v2/invoices/5002"}})
    assert _owner_of(body) == ("customer_id", 12)


def test_enumeration_finds_another_users_record_in_an_envelope(hold):
    """End to end: maya reads noor's invoice, which an anonymous caller is refused."""
    cookie, uid = _login(hold)
    found = hold["checks"].object_enumeration(hold["base"] + "/v2/invoices", cookie,
                                              "maya@holdlab.invalid", uid)
    assert len(found) == 1, found
    cand = found[0]
    assert cand["cwe"] == "CWE-639"
    assert cand["proof"]["owner_field"] == "customer_id"
    assert cand["proof"]["owner_value"] == 12


def test_an_unauthenticated_object_read_is_missing_authentication(tmp_path):
    """When no credential is needed at all, the claim is CWE-306, not ownership.

    A dedicated app is used because the holdout lab correctly requires a session: the
    distinguishing property is that this route serves the record to an anonymous caller.
    """
    class Anon:
        def __call__(self, environ, start_response):
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps({"record": {"id": 7, "customer_id": 12}}).encode()]

    srv = make_server("127.0.0.1", 0, Anon())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{srv.server_port}"
    db = DB(tmp_path / "anon.sqlite")
    evidence = EvidenceStore(db, tmp_path / "ev-anon")
    scope = Scope({"targets": [{"kind": "url", "value": base}], "categories": ["web"],
                   "rate_limit_rps": 200})
    checks = WebChecks(HttpProbe(db, evidence), "eng", scope, db)
    try:
        found = checks.object_enumeration(base + "/records", "session=maya", "maya", 11,
                                          ids=[7])
        assert len(found) == 1, found
        assert found[0]["cwe"] == "CWE-306", found[0]["cwe"]
        assert "without authentication" in found[0]["title"]
    finally:
        srv.shutdown()
        db.close()


def test_collection_ids_come_from_the_listing_not_from_one(hold):
    """Ids start at 5001; guessing 1..3 would report an empty collection."""
    cookie, _ = _login(hold)
    ids = hold["checks"].collection_ids(hold["base"] + "/v2/invoices", cookie)
    assert ids and min(ids) > 1000, ids
    # the neighbour of a known id must be reachable, because a listing shows only your own
    assert len(ids) > 1


@pytest.mark.parametrize("hold", ["hardened"], indirect=True)
def test_the_hardened_twin_yields_nothing(hold):
    """Negative control: the same discovery against correct code must find no object."""
    cookie, uid = _login(hold)
    found = hold["checks"].object_enumeration(hold["base"] + "/v2/invoices", cookie,
                                              "maya@holdlab.invalid", uid)
    assert found == [], [c["title"] for c in found]
