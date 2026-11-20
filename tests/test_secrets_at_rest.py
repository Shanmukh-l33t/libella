"""Secrets at rest: settings-held credentials must be ciphertext in SQLite."""
import json
import sqlite3

from libella.api import App


def test_api_token_encrypted_at_rest(tmp_path, monkeypatch):
    monkeypatch.setenv("LIBELLA_TOKEN", "SI_SECRET_TOKEN_2V89X98J")
    app = App(tmp_path)
    raw = sqlite3.connect(tmp_path / "libella.db").execute(
        "SELECT value_json FROM settings WHERE key='api_token'").fetchone()[0]
    assert "super-secret-token" not in raw
    assert app.token == "SI_SECRET_TOKEN_2V89X98J"
    assert (tmp_path / "secret.key").exists()
    assert (tmp_path / "secret.key").stat().st_mode & 0o777 == 0o600


def test_token_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("LIBELLA_TOKEN", "SI_SECRET_TOKEN_2V89X98J")
    App(tmp_path)
    monkeypatch.delenv("LIBELLA_TOKEN")
    app2 = App(tmp_path)  # no env token; must decrypt persisted one
    assert app2.token == "SI_SECRET_TOKEN_2V89X98J"


def test_llm_key_encrypted_and_masked(tmp_path):
    app = App(tmp_path)
    app.db.execute(
        "INSERT INTO settings(key, value_json) VALUES('llm_config', ?)",
        (app.box.encrypt(json.dumps({"base_url": "http://localhost:9/v1",
                                     "api_key": "fake-test-key"})),))
    raw = sqlite3.connect(tmp_path / "libella.db").execute(
        "SELECT value_json FROM settings WHERE key='llm_config'").fetchone()[0]
    assert "fake-test-key" not in raw
    cfg = json.loads(app.box.decrypt_or_plain(raw))
    assert cfg["api_key"] == "fake-test-key"


def test_legacy_plaintext_migrated(tmp_path):
    app = App(tmp_path)
    app.db.execute("UPDATE settings SET value_json=? WHERE key='api_token'",
                   (json.dumps("legacy-plaintext-token"),))
    app2 = App(tmp_path)
    assert app2.token == "legacy-plaintext-token"
    raw = sqlite3.connect(tmp_path / "libella.db").execute(
        "SELECT value_json FROM settings WHERE key='api_token'").fetchone()[0]
    assert "legacy-plaintext-token" not in raw  # re-encrypted on read
