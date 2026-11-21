"""Captured session credentials: ciphertext in SQLite, absent from traffic/report/PDF.

Loopback fixture only. Sentinels are built by concatenation so no scanner sees a
literal credential, and every assertion reconstructs the same bytes.
"""
import io
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from libella.db import DB
from libella.secrets import SecretError, is_encrypted
from libella.traffic import replay

COOKIE = "SI_SEC" + "RET_" + "COOKIE_CAP_8K2P4M"
AUTH = "Bearer " + "SI_SEC" + "RET_" + "TOKEN_CAP_6T9Q1Z"


def _disk_bytes(path):
    path = Path(path)
    return b"".join(p.read_bytes() for p in
                    (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm"))
                    if p.exists())


def _capture(app, eid, scope, lab, path="/static", **kw):
    r = app.probe.request(eid, scope, lab.base + path, tool="test", **kw)
    assert r["ok"], r
    return r


def _raw(db_path, sql):
    con = sqlite3.connect(db_path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_captured_request_and_response_headers_are_ciphertext(app, mk_eng, lab, scope_for):
    lab.cookie = COOKIE
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    req = _capture(app, eid, scope, lab, headers={"Cookie": f"session={COOKIE}",
                                                  "Authorization": AUTH, "X-Trace": "keep-me-41"})
    login = _capture(app, eid, scope, lab, "/login")
    db_path = app.db.path

    raw_req = _raw(db_path, f"SELECT req_headers_json FROM exchanges WHERE id='{req['exchange_id']}'")[0][0]
    raw_resp = _raw(db_path, f"SELECT resp_headers_json FROM exchanges WHERE id='{login['exchange_id']}'")[0][0]
    assert is_encrypted(raw_req) and is_encrypted(raw_resp)
    for raw in (raw_req, raw_resp):
        assert COOKIE not in raw and AUTH not in raw
    assert COOKIE.encode() not in _disk_bytes(db_path) and AUTH.encode() not in _disk_bytes(db_path)

    # a non-secret control header must survive, and the credential stays usable through DB
    seen = json.loads(app.db.one("SELECT req_headers_json FROM exchanges WHERE id=?",
                                 (req["exchange_id"],))["req_headers_json"])
    assert seen["X-Trace"] == "keep-me-41"
    assert seen["Cookie"] == f"session={COOKIE}" and seen["Authorization"] == AUTH
    resp_h = json.loads(app.db.one("SELECT resp_headers_json FROM exchanges WHERE id=?",
                                   (login["exchange_id"],))["resp_headers_json"])
    assert any(k.lower() == "set-cookie" and COOKIE in v for k, v in resp_h.items()), resp_h

    # the on-disk evidence blob carries the control header but no live credential
    blob = app.evidence.read(req["evidence_id"])
    assert b"keep-me-41" in blob and COOKIE.encode() not in blob and AUTH.encode() not in blob
    assert b"[REDACTED]" in blob


def test_captured_credentials_survive_restart(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    req = _capture(app, eid, scope, lab, headers={"Cookie": f"session={COOKIE}"})
    path = app.db.path
    app.db.close()
    reopened = DB(path)
    try:
        headers = json.loads(reopened.one("SELECT req_headers_json FROM exchanges WHERE id=?",
                                          (req["exchange_id"],))["req_headers_json"])
        assert headers["Cookie"] == f"session={COOKIE}"
    finally:
        reopened.close()


def test_legacy_plaintext_header_rows_are_migrated_and_purged(tmp_path, monkeypatch):
    monkeypatch.delenv("LIBELLA_SECRET_KEY", raising=False)
    db_path = tmp_path / "libella.db"
    db = DB(db_path)
    db.execute("INSERT INTO engagements(id,name,status,scope_json,created_at) VALUES('e','n','draft','{}',1)")
    db.execute("INSERT INTO exchanges(id,engagement_id,method,url,status,req_headers_json,"
               "resp_headers_json,created_at) VALUES('x','e','GET','http://127.0.0.1:9/',200,?,?,1)",
               (json.dumps({"Cookie": f"session={COOKIE}", "X-Trace": "keep-me-41"}),
                json.dumps({"Set-Cookie": f"session={COOKIE}"})))
    db.close()
    assert COOKIE.encode() in _disk_bytes(db_path)  # precondition: legacy plaintext

    db = DB(db_path)  # reopen: migrate
    row = db.one("SELECT * FROM exchanges WHERE id='x'")
    assert json.loads(row["req_headers_json"])["X-Trace"] == "keep-me-41"
    assert json.loads(row["resp_headers_json"])["Set-Cookie"] == f"session={COOKIE}"
    db.close()

    assert COOKIE.encode() not in _disk_bytes(db_path)
    raw_req, raw_resp = _raw(db_path, "SELECT req_headers_json, resp_headers_json FROM exchanges")[0]
    assert is_encrypted(raw_req) and is_encrypted(raw_resp)
    DB(db_path).close()  # idempotent


def test_wrong_key_refuses_captured_headers_without_rewriting(tmp_path, monkeypatch):
    monkeypatch.delenv("LIBELLA_SECRET_KEY", raising=False)
    db_path = tmp_path / "libella.db"
    db = DB(db_path)
    db.execute("INSERT INTO engagements(id,name,status,scope_json,created_at) VALUES('e','n','draft','{}',1)")
    db.execute("INSERT INTO exchanges(id,engagement_id,method,url,status,req_headers_json,created_at) "
               "VALUES('x','e','GET','http://127.0.0.1:9/',200,?,1)",
               (db.seal(json.dumps({"Cookie": f"session={COOKIE}"})),))
    db.close()
    before = _raw(db_path, "SELECT req_headers_json FROM exchanges WHERE id='x'")[0][0]

    monkeypatch.setenv("LIBELLA_SECRET_KEY", Fernet.generate_key().decode())
    with pytest.raises(SecretError):
        DB(db_path)
    assert _raw(db_path, "SELECT req_headers_json FROM exchanges WHERE id='x'")[0][0] == before


def test_authenticated_replay_resends_the_sealed_credential(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    original = _capture(app, eid, scope, lab, headers={"Cookie": f"session={COOKIE}"})["exchange_id"]
    res = replay(app.db, app.evidence, app.probe, scope, eid, original)
    assert res["ok"], res
    assert lab.headers[-1].get("cookie") == f"session={COOKIE}"
    assert COOKIE.encode() not in app.evidence.read(res["evidence_id"])


def test_no_surface_returns_the_captured_cookie(client, app, mk_eng, lab, scope_for):
    lab.cookie = COOKIE
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    xid = _capture(app, eid, scope, lab, headers={"Cookie": f"session={COOKIE}",
                                                  "Authorization": AUTH})["exchange_id"]
    _capture(app, eid, scope, lab, "/login")
    h = {"Authorization": f"Bearer {app.token}"}

    detail = client.get(f"/api/exchanges/{xid}", headers=h)
    assert detail.status_code == 200, detail.text
    assert COOKIE not in detail.text and AUTH not in detail.text
    assert detail.json()["req_headers"]["Cookie"] == "[REDACTED]"

    for params in ({"url": "/static"}, {"body_text": "static-lab-marker"}):
        search = client.get(f"/api/engagements/{eid}/traffic", params=params, headers=h)
        assert search.status_code == 200 and COOKIE not in search.text and AUTH not in search.text

    out = {"md": client.get(f"/api/engagements/{eid}/report", params={"format": "md"}, headers=h).text,
           "json": client.get(f"/api/engagements/{eid}/report", params={"format": "json"}, headers=h).text}
    out["sarif"] = (app.evidence.root / eid / "report" / "report.sarif").read_text()
    for name, text in out.items():
        assert COOKIE not in text and AUTH not in text, f"{name} leaked a captured credential"

    pdf = client.get(f"/api/engagements/{eid}/report", params={"format": "pdf"}, headers=h)
    assert pdf.content[:5] == b"%PDF-"
    assert COOKIE.encode() not in pdf.content
    try:
        from pypdf import PdfReader
    except ImportError:
        return
    text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(pdf.content)).pages)
    assert COOKIE not in text and AUTH not in text
