"""Fixtures for the plugin + MCP extension framework tests."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from libella.api import App  # noqa: E402
from libella.scope import Scope  # noqa: E402
from plugin_fixtures import PLUGIN_CODE, SCOPE_SPEC  # noqa: E402


@pytest.fixture
def app(tmp_path):
    app = App(tmp_path)
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, "
        "budgets_json, objectives_json, window_start, window_end, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("eng_plug", "plugins", "safe_active", "draft", json.dumps(SCOPE_SPEC),
         "{}", "{}", "[]", None, None, 1.0))
    return app


@pytest.fixture
def scope():
    return Scope(SCOPE_SPEC)


@pytest.fixture
def plugin_factory(tmp_path):
    """Write a plugin directory (manifest + module) and return the plugins root."""
    def make(manifest: dict, code: str = PLUGIN_CODE, slug: str = "plug") -> Path:
        d = tmp_path / "plugins" / slug
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text(json.dumps(manifest))
        (d / "plugin.py").write_text(code)
        return tmp_path / "plugins"
    return make
