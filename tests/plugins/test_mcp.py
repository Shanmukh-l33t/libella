"""MCP client: real stdio server, typed adapters, scope gate, graceful absence."""
import json
import sys

import pytest

from libella.mcp_client import (McpClient, McpError, McpToolset, register_server,
                                to_specs, validate_command)
from plugin_fixtures import MOCK_SERVER, SCOPE_SPEC  # noqa: F401


def client(name="mock", command=None, timeout=15):
    return McpClient({"name": name,
                      "command": command or [sys.executable, str(MOCK_SERVER)]},
                     timeout=timeout)


def test_lists_tools_and_hides_raw_shell():
    with client() as c:
        specs = to_specs(c)
    names = [s.name for s in specs]
    assert names == ["mcp_mock_echo"]  # run_shell is never surfaced
    spec = specs[0]
    assert spec.params["target"]["type"] == "string"
    assert spec.required == ["target"] and spec.target_param == "target"
    assert spec.mcp_tool == "echo"


def test_call_through_scope_gate_and_audit(app, scope):
    with client() as c:
        toolset = McpToolset(c, app.db, app.evidence, scope, "eng_plug", category="recon")
        res = toolset.call("mcp_mock_echo", {"target": "127.0.0.1", "note": "hi"})
    assert res["ok"] is True, res
    assert json.loads(res["text"])["echoed"] == {"target": "127.0.0.1", "note": "hi"}
    row = app.db.one("SELECT scope_decision, artifact_id FROM tool_calls WHERE id=?",
                     (res["call_id"],))
    assert row["scope_decision"] == "executed: ok" and row["artifact_id"]


def test_out_of_scope_call_is_refused_before_dispatch(app, scope):
    with client() as c:
        toolset = McpToolset(c, app.db, app.evidence, scope, "eng_plug", category="recon")
        res = toolset.call("mcp_mock_echo", {"target": "127.0.0.2"})
    assert res["ok"] is False and res["error"].startswith("out_of_scope")
    row = app.db.one("SELECT scope_decision, artifact_id FROM tool_calls WHERE id=?",
                     (res["call_id"],))
    assert row["scope_decision"].startswith("refused:") and row["artifact_id"] is None


def test_invalid_arguments_refused(app, scope):
    with client() as c:
        toolset = McpToolset(c, app.db, app.evidence, scope, "eng_plug", category="recon")
        res = toolset.call("mcp_mock_echo", {"target": "127.0.0.1", "cmd": "id"})
    assert res["ok"] is False and res["error"].startswith("invalid_params")


def test_missing_server_degrades(app, scope):
    absent = McpClient({"name": "gone", "command": ["/nonexistent/mcp-server"]}, timeout=5)
    assert absent.health()["available"] is False
    with pytest.raises(McpError):
        absent.list_tools()
    toolset = McpToolset(absent, app.db, app.evidence, scope, "eng_plug", category="recon")
    res = toolset.call("mcp_gone_echo", {"target": "127.0.0.1"})
    assert res["ok"] is False and res["degradation"] == "mcp_unavailable"
    assert res["error"].startswith("mcp_unavailable")


def test_server_that_exits_is_reported(tmp_path):
    script = tmp_path / "die.py"
    script.write_text("raise SystemExit(3)\n")
    dead = McpClient({"name": "dead", "command": [sys.executable, str(script)]}, timeout=5)
    with pytest.raises(McpError, match="exited|timed out"):
        dead.list_tools()
    assert dead.health()["available"] is False


@pytest.mark.parametrize("command", [
    ["bash", "-c", "id"],
    ["/bin/sh", "-c", "id"],
    ["powershell", "-Command", "whoami"],
    ["python3", "-c", "print(1)"],
    ["python3", "server.py; rm -rf /"],
    [],
    "python3 server.py",
])
def test_validate_command_rejects_shells(command):
    with pytest.raises(ValueError):
        validate_command(command)


def test_register_server_persists(app):
    conf = register_server(app.db, {"name": "mock",
                                    "command": [sys.executable, str(MOCK_SERVER)]})
    assert conf["name"] == "mock"
    from libella.mcp_client import find_server
    assert find_server(app.db, "mock")["command"][0] == sys.executable
