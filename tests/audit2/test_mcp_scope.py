"""Audit-2: MCP tools must be scope-gated on every dialing argument.

`McpToolset.call` only checked arguments whose *key* was in TARGET_PARAMS. A
server exposing {"site": "..."} (or a legit "target" plus a second "callback"
URL) therefore ran with no scope check at all, which is the one thing the MCP
adapter promises.
"""
import sys

import pytest

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.mcp_client import McpClient, McpToolset
from libella.scope import Scope

SERVER = '''
import json, sys

TOOLS = [
    {"name": "fetch", "description": "fetch a page",
     "inputSchema": {"type": "object",
                     "properties": {"site": {"type": "string", "maxLength": 200},
                                    "site_host": {"type": "string", "maxLength": 200}},
                     "required": ["site"]}},
    {"name": "notify", "description": "post a result somewhere",
     "inputSchema": {"type": "object",
                     "properties": {"target": {"type": "string"},
                                    "callback": {"type": "string"}},
                     "required": ["target"]}},
]

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    rid = msg.get("id")
    if rid is None:
        continue
    if msg.get("method") == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"],
                  "capabilities": {"tools": {}}}
    elif msg.get("method") == "tools/list":
        result = {"tools": TOOLS}
    else:
        result = {"content": [{"type": "text",
                               "text": json.dumps(msg.get("params", {}).get("arguments"))}],
                  "isError": False}
    print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}), flush=True)
'''


@pytest.fixture
def server(tmp_path):
    path = tmp_path / "mcp_server.py"
    path.write_text(SERVER)

    def make():
        return McpClient({"name": "lab", "command": [sys.executable, str(path)]}, timeout=15)

    return make


@pytest.fixture
def env(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    scope = Scope({"targets": [{"kind": "url", "value": "http://127.0.0.1:8080"}],
                   "categories": ["web"]})
    return db, ev, scope


def test_off_named_url_argument_is_scope_checked(server, env):
    db, ev, scope = env
    with server() as c:
        toolset = McpToolset(c, db, ev, scope, "eng")
        res = toolset.call("mcp_lab_fetch", {"site": "http://127.0.0.2:9000/steal"})
    assert res["ok"] is False and res["error"].startswith("out_of_scope"), res


def test_bare_hostname_argument_is_scope_checked(server, env):
    db, ev, scope = env
    with server() as c:
        toolset = McpToolset(c, db, ev, scope, "eng")
        res = toolset.call("mcp_lab_fetch", {"site": "127.0.0.1:8080/ok",
                                            "site_host": "127.0.0.2:9000"})
    assert res["ok"] is False and res["error"].startswith("out_of_scope"), res


def test_second_url_argument_is_scope_checked(server, env):
    db, ev, scope = env
    with server() as c:
        toolset = McpToolset(c, db, ev, scope, "eng")
        res = toolset.call("mcp_lab_notify",
                           {"target": "http://127.0.0.1:8080/ok",
                            "callback": "http://127.0.0.2:9000/hook"})
    assert res["ok"] is False and res["error"].startswith("out_of_scope"), res


def test_in_scope_arguments_still_run(server, env):
    db, ev, scope = env
    with server() as c:
        toolset = McpToolset(c, db, ev, scope, "eng")
        res = toolset.call("mcp_lab_notify",
                           {"target": "http://127.0.0.1:8080/ok",
                            "callback": "http://127.0.0.1:8080/hook"})
    assert res["ok"] is True, res
    row = db.one("SELECT scope_decision FROM tool_calls WHERE id=?", (res["call_id"],))
    assert row["scope_decision"].startswith("executed")
