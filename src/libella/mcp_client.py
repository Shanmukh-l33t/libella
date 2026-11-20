"""Minimal MCP client: JSON-RPC over stdio, typed adapters, scope gate, audit.

An external MCP server is spawned as a validated argv (never a shell). Its
``tools/list`` entries become ToolSpecs; ``tools/call`` goes through the same
parameter validation, scope check on any target parameter, and tool_calls
audit row as built-in tools. A tool whose name/description looks like a raw
shell is not exposed. Servers are registered in settings, never auto-started
except on demand; a missing/broken server degrades instead of raising.
"""
import json
import os
import queue
import re
import subprocess
import threading
import time
from pathlib import Path

from .db import new_id
from .scope import Scope
from .tools import ToolSpec, validate_params

PROTOCOL_VERSION = "2024-11-05"
SETTINGS_KEY = "mcp_servers"
# Params that make the adapter dial something; every present one is scope-checked.
TARGET_PARAMS = ("target", "url", "host", "domain", "endpoint", "base_url", "base")
NAME_RE = re.compile(r"[a-z][a-z0-9_-]{1,40}")
# A shell as argv[0], or an inline-code flag, is a shell in disguise.
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "cmd", "cmd.exe",
          "powershell", "powershell.exe", "pwsh"}
INLINE_FLAGS = {"-c", "-e", "--eval", "-command", "-encodedcommand", "--command"}
CHAIN = (";", "|", "&", "`", "$(", "\n", "\r", ">")


class McpError(RuntimeError):
    pass


def validate_command(command) -> list[str]:
    """Spawn specs come from the operator, but never as a shell one-liner."""
    if not isinstance(command, list) or not command:
        raise ValueError("command must be a non-empty list of strings")
    if not all(isinstance(c, str) and c for c in command):
        raise ValueError("command entries must be non-empty strings")
    head = Path(command[0]).name.lower()
    if head in SHELLS:
        raise ValueError(f"refusing shell as MCP command: {command[0]}")
    if any(c.lower() in INLINE_FLAGS for c in command[1:]):
        raise ValueError("refusing inline-code flag in MCP command")
    if any(any(ch in c for ch in CHAIN) for c in command):
        raise ValueError("MCP command contains forbidden characters")
    return list(command)


def load_servers(db) -> list[dict]:
    row = db.one("SELECT value_json FROM settings WHERE key=?", (SETTINGS_KEY,))
    return json.loads(row["value_json"]) if row else []


def save_servers(db, servers: list[dict]):
    db.execute("INSERT INTO settings(key, value_json) VALUES(?,?) "
               "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
               (SETTINGS_KEY, json.dumps(servers)))


def find_server(db, name: str) -> dict | None:
    return next((s for s in load_servers(db) if s["name"] == name), None)


def register_server(db, body: dict) -> dict:
    name = body.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ValueError("name must match [a-z][a-z0-9_-]{1,40}")
    command = validate_command(body.get("command"))
    servers = [s for s in load_servers(db) if s["name"] != name]
    servers.append({"name": name, "command": command})
    save_servers(db, servers)
    return {"name": name, "command": command}


class McpClient:
    """One stdio MCP server connection (lazy start, newline-delimited JSON)."""

    def __init__(self, server: dict, timeout: float = 20.0):
        self.name = server["name"]
        self.command = validate_command(server.get("command"))
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self._lines: queue.Queue = queue.Queue()
        self._id = 0
        self._lock = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def start(self):
        if self.proc and self.proc.poll() is None:
            return
        # servers keep their own env, minus anything of ours that is a secret
        env = {k: v for k, v in os.environ.items() if not k.startswith("LIBELLA_")}
        try:
            self.proc = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, text=True,
                                         bufsize=1, env=env)
        except OSError as e:
            raise McpError(f"cannot start MCP server '{self.name}': {e}") from e
        threading.Thread(target=self._read, args=(self.proc.stdout,), daemon=True).start()
        self._request("initialize", {"protocolVersion": PROTOCOL_VERSION,
                                     "capabilities": {},
                                     "clientInfo": {"name": "libella", "version": "0.1.0"}})
        self._notify("notifications/initialized", {})

    def _read(self, pipe):
        try:
            for line in pipe:
                if line.strip():
                    self._lines.put(line)
        except (OSError, ValueError):
            pass
        finally:
            self._lines.put(None)  # wakes any waiter: server is gone

    def _send(self, msg: dict):
        try:
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
        except (OSError, ValueError, AttributeError) as e:
            raise McpError(f"MCP server '{self.name}' is not writable: {e}") from e

    def _notify(self, method: str, params: dict):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _request(self, method: str, params: dict) -> dict:
        with self._lock:
            self._id += 1
            rid = self._id
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
            deadline = time.time() + self.timeout
            while True:
                left = deadline - time.time()
                if left <= 0:
                    raise McpError(f"MCP {method} timed out after {self.timeout}s")
                try:
                    line = self._lines.get(timeout=left)
                except queue.Empty:
                    raise McpError(f"MCP {method} timed out after {self.timeout}s") from None
                if line is None:
                    raise McpError(f"MCP server '{self.name}' exited")
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue  # a server logging on stdout is not a protocol error
                if msg.get("id") != rid:
                    continue  # notification or another request's reply
                if msg.get("error"):
                    err = msg["error"]
                    raise McpError(f"MCP {method}: {err.get('message', err)}")
                return msg.get("result") or {}

    def list_tools(self) -> list[dict]:
        self.start()
        tools = self._request("tools/list", {}).get("tools") or []
        return [t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]

    def call_tool(self, tool: str, arguments: dict) -> dict:
        self.start()
        return self._request("tools/call", {"name": tool, "arguments": arguments})

    def health(self) -> dict:
        try:
            tools = [t["name"] for t in self.list_tools()]
        except McpError as e:
            return {"name": self.name, "command": self.command, "available": False,
                    "error": str(e)[:300]}
        return {"name": self.name, "command": self.command, "available": True,
                "tools": tools}

    def close(self):
        proc, self.proc = self.proc, None
        if not proc:
            return
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _param_schema(raw: dict) -> dict | None:
    """MCP/JSON-Schema property -> the subset validate_params understands."""
    if not isinstance(raw, dict):
        return None
    kind = raw.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    if kind not in {"string", "integer", "number", "boolean", "array", "object"}:
        return None  # untyped param: not exposable without guessing
    out = {"type": kind}
    if kind == "string":
        if raw.get("maxLength"):
            out["maxLength"] = int(raw["maxLength"])
        enum = [e for e in raw.get("enum") or [] if isinstance(e, str)]
        if enum:
            out["enum"] = enum
    if raw.get("description"):
        out["description"] = str(raw["description"])[:300]
    return out


def _pick_target_param(params: dict) -> str:
    return next((p for p in TARGET_PARAMS if p in params), "target")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", text.lower()).strip("_")[:40]


def to_specs(client: "McpClient", category: str = "web") -> list[ToolSpec]:
    """MCP tool descriptors -> typed ToolSpecs (namespaced, schema closed)."""
    specs = []
    for tool in client.list_tools():
        tool_name = tool["name"]
        blob = f"{tool_name} {tool.get('description', '')}".lower()
        if any(w in blob.split() for w in ("shell", "bash", "powershell", "sh")):
            continue  # never surface a raw command runner
        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}
        params = {k: s for k, s in ((n, _param_schema(v)) for n, v in props.items()) if s}
        required = [r for r in schema.get("required") or [] if r in params]
        ann = tool.get("annotations") or {}
        spec = ToolSpec(
            name=f"mcp_{_slug(client.name)}_{_slug(tool_name)}",
            description=str(tool.get("description") or tool_name)[:500],
            category=category, params=params, required=required,
            read_only=ann.get("readOnlyHint", True) is True,
            destructive=ann.get("destructiveHint", False) is True,
            target_param=_pick_target_param(params),
        )
        spec.mcp_server, spec.mcp_tool = client.name, tool_name  # adapter wiring
        specs.append(spec)
    return specs


class McpToolset:
    """Typed, scope-gated view of one MCP server for one engagement."""

    def __init__(self, client: McpClient, db, evidence, scope: Scope,
                 engagement_id: str, intent_id: str | None = None, category: str = "web"):
        self.client = client
        self.db = db
        self.evidence = evidence
        self.scope = scope
        self.engagement_id = engagement_id
        self.intent_id = intent_id
        self.category = category

    def specs(self) -> list[ToolSpec]:
        return to_specs(self.client, self.category)

    def call(self, name: str, arguments: dict) -> dict:
        """Validate -> scope-check every target -> tools/call -> audit."""
        call_id = new_id("tc")
        started = time.time()
        try:
            spec = next(s for s in self.specs() if s.name == name)
        except StopIteration:
            return self._refuse(call_id, name, "", started, f"unknown MCP tool {name}")
        except McpError as e:  # server absent/broken: degrade, never raise
            return self._refuse(call_id, name, "", started, str(e),
                                code="mcp_unavailable", degradation="mcp_unavailable")
        try:
            clean = validate_params(spec, arguments)
        except ValueError as e:
            return self._refuse(call_id, name, "", started, f"invalid params: {e}",
                                code="invalid_params")

        dest = None
        for key, value in clean.items():
            if not isinstance(value, str) or key not in TARGET_PARAMS:
                continue
            dest = value
            decision = (self.scope.check_host_port(value, 0, self.category)
                        if "://" not in value else self.scope.check_url(value, self.category))
            if not decision.allowed:
                return self._refuse(call_id, name, value, started, decision.reason,
                                    code="out_of_scope")
        dest = dest or ""

        try:
            result = self.client.call_tool(spec.mcp_tool, clean)
        except McpError as e:
            return self._refuse(call_id, name, dest, started, str(e),
                                code="mcp_unavailable", degradation="mcp_unavailable")
        text = "\n".join(c.get("text", "") for c in result.get("content") or []
                         if isinstance(c, dict) and c.get("type") == "text")
        artifact = self.evidence.put(
            self.engagement_id,
            json.dumps({"tool": spec.mcp_tool, "arguments": clean, "result": result},
                       default=str).encode(), "mcp_result")
        decision = "executed: ok" if dest else "executed: ok (no target parameter)"
        self._audit(call_id, spec.name, dest, decision, 0, artifact["id"], started, None)
        return {"ok": not result.get("isError", False), "status": "ok", "call_id": call_id,
                "artifact_id": artifact["id"], "content": result.get("content") or [],
                "text": text, "structured": result.get("structuredContent")}

    def _refuse(self, call_id, tool, target, started, reason, code="refused",
                degradation=None):
        self._audit(call_id, tool, target, f"refused: {reason}", None, None, started, reason)
        out = {"ok": False, "error": f"{code}: {reason}", "call_id": call_id}
        if degradation:
            out["degradation"] = degradation
        return out

    def _audit(self, call_id, tool, target, decision, exit_code, artifact_id, started, error):
        # Same row shape as ToolRunner._audit so one audit view covers both.
        self.db.execute(
            "INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
            "scope_decision, exit_code, duration_ms, artifact_id, error, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (call_id, self.engagement_id, self.intent_id, tool, "[]", target, decision,
             exit_code, round((time.time() - started) * 1000, 1), artifact_id, error,
             time.time()),
        )
        self.db.emit(self.engagement_id, "tool_call", {
            "call_id": call_id, "tool": tool, "target": target, "decision": decision,
            "source": "mcp", "error": error,
        })
