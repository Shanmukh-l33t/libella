"""Shared data for the plugin/MCP tests (imported by conftest and test modules)."""
from pathlib import Path

HERE = Path(__file__).resolve().parent
MOCK_SERVER = HERE / "mock_mcp_server.py"
SCOPE_SPEC = {"targets": [{"kind": "ip", "value": "127.0.0.1"}],
              "categories": ["web", "infra", "recon"]}

TOOL_MANIFEST = {
    "name": "echoer", "version": "1.0.0", "type": "tool",
    "contract": {"description": "echo typed params back",
                 "category": "recon",
                 "params": {"target": {"type": "string", "maxLength": 200},
                            "note": {"type": "string", "maxLength": 50}},
                 "required": ["target"]},
    "entrypoint": "plugin.py:run",
}

PLUGIN_CODE = """
def run(params):
    return {"echoed": params}
"""
