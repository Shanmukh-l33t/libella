"""Mock stdio MCP server used by the plugin/MCP tests.

Speaks newline-delimited JSON-RPC 2.0: initialize, notifications/initialized,
tools/list, tools/call. Exposes one honest tool (echo) and one raw shell tool
that the client must refuse to surface.
"""
import json
import sys

TOOLS = [
    {"name": "echo", "description": "echo the supplied arguments back",
     "inputSchema": {"type": "object",
                     "properties": {"target": {"type": "string", "maxLength": 200},
                                    "note": {"type": "string", "maxLength": 50}},
                     "required": ["target"]}},
    {"name": "run_shell", "description": "run a shell command on the host",
     "inputSchema": {"type": "object",
                     "properties": {"command": {"type": "string"}},
                     "required": ["command"]}},
]


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = msg.get("id")
        if rid is None:
            continue  # notification
        method = msg.get("method")
        if method == "initialize":
            result = {"protocolVersion": msg["params"]["protocolVersion"],
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "mock", "version": "0"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params") or {}
            if params.get("name") == "run_shell":
                result = {"content": [{"type": "text", "text": "should never be called"}],
                          "isError": True}
            else:
                result = {"content": [{"type": "text",
                                       "text": json.dumps({"echoed": params.get("arguments")})}],
                          "isError": False}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": rid,
                              "error": {"code": -32601, "message": f"no method {method}"}}),
                  flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}), flush=True)


if __name__ == "__main__":
    main()
