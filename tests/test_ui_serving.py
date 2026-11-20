"""Regression: the built UI must be served in pip-installed (container) layouts.

Bug: webdist was resolved only relative to api.py's __file__; in the image the
package lives in site-packages, so the mount was silently skipped and / 404'd.
"""
from fastapi.testclient import TestClient

from libella.api import App, create_api


def test_ui_served_via_env_override(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html><body>libella-ui</body></html>")
    monkeypatch.setenv("LIBELLA_WEB_DIST", str(dist))
    app = App(tmp_path / "data")
    client = TestClient(create_api(app))
    r = client.get("/")
    assert r.status_code == 200
    assert "libella-ui" in r.text
    assert client.get("/api/health").status_code == 200


def test_ui_absent_is_graceful(tmp_path, monkeypatch):
    monkeypatch.setenv("LIBELLA_WEB_DIST", str(tmp_path / "nope"))
    app = App(tmp_path / "data")
    client = TestClient(create_api(app))
    assert client.get("/api/health").status_code == 200