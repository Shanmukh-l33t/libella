"""Engagement auth and stored session cookies: ciphertext at rest, plaintext via DB.

Synthetic secrets only; no scanners, no browser. Covers the production writers
(API engagement create, DB.seal), legacy plaintext migration, raw-disk residue,
and the fail-closed key/token paths.
"""
import json
import sqlite3

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from libella.api import App, create_api
from libella.db import DB
from libella.secrets import SecretBox, SecretError, is_encrypted

PW = "SI_SECRET_PASSWORD_7Q4M2XW9"
COOKIE = "SI_SECRET_COOKIE_3K8N5VZ1"
LEGACY_PW = "SI_SECRET_PASSWORD_LEGACY_9T2B"
LEGACY_COOKIE = "SI_SECRET_COOKIE_LEGACY_4R7C"


def _disk_bytes(path):
    return b"".join(p.read_bytes() for p in
                    (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm"))
                    if p.exists())


def _client(app):
    c = TestClient(create_api(app))
    c.headers["Authorization"] = f"Bearer {app.token}"
    return c


def test_engagement_auth_written_by_api_is_ciphertext(tmp_path):
    app = App(tmp_path)
    scope = {"targets": [{"kind": "url", "value": "http://127.0.0.1:9"}]}
    auth = {"identities": [{"username": "alice", "password": PW}]}
    r = _client(app).post("/api/engagements", json={"name": "n", "scope": scope, "auth": auth})
    assert r.status_code == 200, r.text
    eid = r.json()["id"]
    assert PW not in r.text  # response keeps redacting passwords
    assert json.loads(app.db.one("SELECT auth_json FROM engagements WHERE id=?", (eid,))["auth_json"]) == auth
    db_path = tmp_path / "libella.db"
    raw = sqlite3.connect(db_path).execute(
        "SELECT auth_json FROM engagements WHERE id=?", (eid,)).fetchone()[0]
    assert is_encrypted(raw) and PW not in raw
    assert PW.encode() not in _disk_bytes(db_path)


def test_cookie_values_ciphertext_at_rest(tmp_path):
    db_path = tmp_path / "libella.db"
    db = DB(db_path)
    db.execute("INSERT INTO engagements(id,name,status,scope_json,created_at) VALUES('e','n','draft','{}',1)")
    db.execute("INSERT INTO auth_contexts(id,engagement_id,cookies_json) VALUES('a','e',?)",
               (db.seal(json.dumps([{"name": "session", "value": COOKIE}])),))
    assert json.loads(db.one("SELECT cookies_json FROM auth_contexts WHERE id='a'")["cookies_json"])[0]["value"] == COOKIE
    raw = sqlite3.connect(db_path).execute(
        "SELECT cookies_json FROM auth_contexts WHERE id='a'").fetchone()[0]
    assert is_encrypted(raw) and COOKIE not in raw
    assert COOKIE.encode() not in _disk_bytes(db_path)
    db.close()


def test_legacy_plaintext_migrated_and_purged_from_disk(tmp_path, monkeypatch):
    monkeypatch.delenv("LIBELLA_SECRET_KEY", raising=False)
    db_path = tmp_path / "libella.db"
    db = DB(db_path)
    db.execute("INSERT INTO engagements(id,name,status,scope_json,auth_json,created_at) VALUES('e','n','draft','{}',?,1)",
               (json.dumps({"identities": [{"password": LEGACY_PW}]}),))
    db.execute("INSERT INTO auth_contexts(id,engagement_id,cookies_json) VALUES('a','e',?)",
               (json.dumps([{"name": "session", "value": LEGACY_COOKIE}]),))
    db.close()
    assert LEGACY_PW.encode() in _disk_bytes(db_path)  # precondition

    db = DB(db_path)  # reopen: migrate
    assert LEGACY_PW in db.one("SELECT auth_json FROM engagements WHERE id='e'")["auth_json"]
    assert LEGACY_COOKIE in db.one("SELECT cookies_json FROM auth_contexts WHERE id='a'")["cookies_json"]
    db.close()

    blob = _disk_bytes(db_path)
    assert LEGACY_PW.encode() not in blob and LEGACY_COOKIE.encode() not in blob
    raw = sqlite3.connect(db_path).execute(
        "SELECT auth_json FROM engagements WHERE id='e'").fetchone()[0]
    assert is_encrypted(raw)
    DB(db_path).close()  # second migration is a no-op


def test_wrong_key_raises_without_rewriting_data(tmp_path, monkeypatch):
    monkeypatch.delenv("LIBELLA_SECRET_KEY", raising=False)
    db_path = tmp_path / "libella.db"
    db = DB(db_path)
    db.execute("INSERT INTO engagements(id,name,status,scope_json,auth_json,created_at) VALUES('e','n','draft','{}',?,1)",
               (db.seal(json.dumps({"password": PW})),))
    db.close()
    before = sqlite3.connect(db_path).execute(
        "SELECT auth_json FROM engagements WHERE id='e'").fetchone()[0]

    monkeypatch.setenv("LIBELLA_SECRET_KEY", Fernet.generate_key().decode())
    with pytest.raises(SecretError):
        DB(db_path)
    after = sqlite3.connect(db_path).execute(
        "SELECT auth_json FROM engagements WHERE id='e'").fetchone()[0]
    assert after == before


def test_wrong_key_does_not_wrap_legacy_plaintext(tmp_path, monkeypatch):
    key_a = Fernet.generate_key().decode()
    monkeypatch.setenv("LIBELLA_SECRET_KEY", key_a)
    monkeypatch.setenv("LIBELLA_TOKEN", PW)
    App(tmp_path).db.close()
    db_path = tmp_path / "libella.db"
    con = sqlite3.connect(db_path)
    con.execute("INSERT INTO engagements(id,name,status,scope_json,auth_json,created_at) "
                "VALUES('e','n','draft','{}',?,1)", (json.dumps({"password": LEGACY_PW}),))
    con.commit()
    con.close()

    monkeypatch.setenv("LIBELLA_SECRET_KEY", Fernet.generate_key().decode())
    with pytest.raises(SecretError):
        DB(db_path)  # the encrypted API token proves this key is wrong
    assert sqlite3.connect(db_path).execute(
        "SELECT auth_json FROM engagements WHERE id='e'").fetchone()[0] == \
        json.dumps({"password": LEGACY_PW})


def test_api_token_never_falls_back_to_ciphertext(tmp_path, monkeypatch):
    monkeypatch.setenv("LIBELLA_TOKEN", PW)
    App(tmp_path)
    db_path = tmp_path / "libella.db"
    stored = json.loads(sqlite3.connect(db_path).execute(
        "SELECT value_json FROM settings WHERE key='api_token'").fetchone()[0])
    assert is_encrypted(stored) and stored != PW

    # the value's format is unchanged: JSON-encoded Fernet token
    assert SecretBox(tmp_path).decrypt(stored) == PW

    monkeypatch.setenv("LIBELLA_SECRET_KEY", Fernet.generate_key().decode())
    with pytest.raises(SecretError):
        SecretBox(tmp_path).decrypt(stored)
    with pytest.raises(SecretError):
        App(tmp_path)  # startup fails; ciphertext never becomes a bearer token
    assert json.loads(sqlite3.connect(db_path).execute(
        "SELECT value_json FROM settings WHERE key='api_token'").fetchone()[0]) == stored


def test_token_shaped_value_is_not_treated_as_legacy_plaintext(tmp_path, monkeypatch):
    monkeypatch.delenv("LIBELLA_SECRET_KEY", raising=False)
    app = App(tmp_path)
    app.db.execute("UPDATE settings SET value_json=? WHERE key='api_token'",
                   (json.dumps("gAAAAA-not-a-real-fernet-token"),))
    with pytest.raises(SecretError):
        App(tmp_path)  # ambiguous/truncated ciphertext fails closed, no rewrite
    app.db.close()
    assert json.loads(sqlite3.connect(tmp_path / "libella.db").execute(
        "SELECT value_json FROM settings WHERE key='api_token'").fetchone()[0]) == \
        "gAAAAA-not-a-real-fernet-token"
