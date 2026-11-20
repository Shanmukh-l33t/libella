"""Plugin + MCP API routes: listing, reload, server registration, degradation."""
import json
import sys

from fastapi.testclient import TestClient

from libella.api import create_api
from plugin_fixtures import MOCK_SERVER, TOOL_MANIFEST


def bearer(app):
    return {"Authorization": f"Bearer {app.token}"}


def test_plugins_list_and_reload(app, plugin_factory):
    # App scans <data_dir>/plugins at startup; drop a plugin in, then reload
    client = TestClient(create_api(app))
    assert client.get("/api/plugins", headers=bearer(app)).json()["loaded"] == []
    plugin_factory(TOOL_MANIFEST)  # factory writes into app.data_dir/plugins

    body = client.post("/api/plugins/reload", headers=bearer(app)).json()
    assert [e["name"] for e in body["loaded"]] == ["echoer"]
    assert body["available"][0]["name"] == "plugin_echoer"
    tools = [t["name"] for t in client.get("/api/tools", headers=bearer(app)).json()]
    assert "plugin_echoer" in tools


def test_plugins_routes_need_token(app):
    client = TestClient(create_api(app))
    assert client.get("/api/plugins").status_code == 401
    assert client.post("/api/plugins/reload").status_code == 401


def test_mcp_register_list_and_tools(app):
    client = TestClient(create_api(app))
    h = bearer(app)
    reg = client.post("/api/mcp/servers", headers=h,
                      json={"name": "mock", "command": [sys.executable, str(MOCK_SERVER)]})
    assert reg.status_code == 200, reg.text

    servers = client.get("/api/mcp/servers", headers=h).json()
    assert servers == [{"name": "mock", "command": [sys.executable, str(MOCK_SERVER)],
                        "available": True, "tools": ["echo", "run_shell"]}]

    tools = client.get("/api/mcp/mock/tools", headers=h).json()
    assert tools["available"] is True
    assert [t["name"] for t in tools["tools"]] == ["mcp_mock_echo"]
    assert tools["tools"][0]["parameters"]["required"] == ["target"]


def test_mcp_register_rejects_shell(app):
    client = TestClient(create_api(app))
    res = client.post("/api/mcp/servers", headers=bearer(app),
                      json={"name": "shell", "command": ["bash", "-c", "id"]})
    assert res.status_code == 400 and "shell" in res.json()["detail"]


def test_mcp_missing_server_degrades(app):
    client = TestClient(create_api(app))
    h = bearer(app)
    client.post("/api/mcp/servers", headers=h,
                json={"name": "gone", "command": ["/nonexistent/mcp-server"]})
    status = client.get("/api/mcp/servers", headers=h).json()
    assert status[0]["available"] is False and status[0]["error"]
    res = client.get("/api/mcp/gone/tools", headers=h)
    assert res.status_code == 200
    assert res.json()["available"] is False and res.json()["tools"] == []
    assert client.get("/api/mcp/unknown/tools", headers=h).status_code == 404


def test_mcp_servers_persist_across_app_restart(app):
    client = TestClient(create_api(app))
    client.post("/api/mcp/servers", headers=bearer(app),
                json={"name": "mock", "command": [sys.executable, str(MOCK_SERVER)]})
    from libella.api import App
    again = App(app.data_dir)
    stored = json.loads(again.db.one("SELECT value_json FROM settings WHERE key='mcp_servers'")
                        ["value_json"])
    assert stored[0]["name"] == "mock"
