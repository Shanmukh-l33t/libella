"""Subprocess tool runner: validated argv, scope gate, timeouts, audit.

The LLM never composes a command line. Adapters build argv from typed
params; this runner re-checks scope, executes without a shell, caps output,
and writes an audit row for every call (including refusals).
"""
import json
import subprocess
import threading
import time
from pathlib import Path

from ..db import DB, new_id
from ..evidence import EvidenceStore
from ..scope import Scope
from . import ToolSpec, resolve_binary, validate_params

MAX_OUTPUT = 512 * 1024  # per stream cap


class ToolRunner:
    def __init__(self, db: DB, evidence: EvidenceStore, workdir: str | Path):
        self.db = db
        self.evidence = evidence
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        spec: ToolSpec,
        params: dict,
        scope: Scope,
        engagement_id: str,
        intent_id: str | None,
        target: str,
        category: str | None = None,
    ) -> dict:
        """Execute a typed tool call. Returns structured result + audit refs."""
        call_id = new_id("tc")
        started = time.time()
        cat = category or spec.category
        if cat != spec.category:
            # a tool may not run under a category it does not belong to
            err = f"tool '{spec.name}' is category '{spec.category}', not '{cat}'"
            self._audit(call_id, engagement_id, intent_id, spec.name, [], target,
                        f"refused: {err}", None, started, None, err)
            return {"ok": False, "error": f"category_mismatch: {err}", "call_id": call_id}
        try:
            clean = validate_params(spec, params)
        except ValueError as e:
            self._audit(call_id, engagement_id, intent_id, spec.name, [], target,
                        f"refused: invalid params: {e}", None, started, None, str(e))
            return {"ok": False, "error": f"invalid_params: {e}", "call_id": call_id}

        # scope the parameter the adapter actually dials, not a caller's claim
        dest = clean.get(spec.target_param) or target
        decision = scope.check_host_port(dest, 0, cat) if _is_host(dest) else scope.check_url(dest, cat)
        if not decision.allowed:
            self._audit(call_id, engagement_id, intent_id, spec.name, [], dest,
                        f"refused: {decision.reason}", None, started, None, decision.reason)
            return {"ok": False, "error": f"out_of_scope: {decision.reason}", "call_id": call_id}

        if spec.binary and resolve_binary(spec.binary) is None:
            err = f"tool binary '{spec.binary}' not installed"
            self._audit(call_id, engagement_id, intent_id, spec.name, [], dest,
                        "refused: missing binary", None, started, None, err)
            return {"ok": False, "error": f"missing_tool: {err}", "call_id": call_id,
                    "degradation": "missing_tool"}

        try:
            argv = spec.handler(clean, decision)  # adapter builds argv list
        except Exception as e:
            self._audit(call_id, engagement_id, intent_id, spec.name, [], dest,
                        f"refused: argv build error: {e}", None, started, None, str(e))
            return {"ok": False, "error": f"argv_error: {e}", "call_id": call_id}
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            err = "adapter must return list[str] argv"
            self._audit(call_id, engagement_id, intent_id, spec.name, [], dest,
                        "refused: bad argv", None, started, None, err)
            return {"ok": False, "error": err, "call_id": call_id}
        # resolve binary to absolute path (restricted PATH below must still find it)
        if spec.binary:
            resolved = resolve_binary(argv[0])
            if resolved:
                argv[0] = resolved

        rundir = self.workdir / engagement_id / call_id
        rundir.mkdir(parents=True, exist_ok=True)
        stdout, stderr, exit_code, timed_out, truncated = _run_capped(
            argv, rundir, {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(rundir),
                           "LANG": "C.UTF-8", "NO_COLOR": "1"}, spec.timeout_s)

        duration_ms = (time.time() - started) * 1000
        artifact = self.evidence.put(
            engagement_id,
            json.dumps({"argv": argv, "stdout": stdout.decode(errors="replace"),
                        "stderr": stderr.decode(errors="replace"), "exit_code": exit_code,
                        "timed_out": timed_out, "truncated": truncated}, default=str).encode(),
            "tool_output",
        )
        status = "timeout" if timed_out else ("ok" if exit_code == 0 else "failed")
        self._audit(call_id, engagement_id, intent_id, spec.name, argv, dest,
                    f"executed: {status}", exit_code, started, artifact["id"],
                    None if status == "ok" else status)
        result = {
            "ok": status == "ok", "status": status, "call_id": call_id,
            "artifact_id": artifact["id"], "exit_code": exit_code,
            "duration_ms": round(duration_ms, 1),
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
            "truncated": truncated,
            "partial": timed_out,
        }
        if timed_out:
            result["degradation"] = "timeout_partial_never_complete"
        return result

    def _audit(self, call_id, engagement_id, intent_id, tool, argv, target,
               decision, exit_code, started, artifact_id, error):
        self.db.execute(
            "INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
            "scope_decision, exit_code, duration_ms, artifact_id, error, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (call_id, engagement_id, intent_id, tool, json.dumps(argv), target, decision,
             exit_code, round((time.time() - started) * 1000, 1), artifact_id, error, time.time()),
        )
        self.db.emit(engagement_id, "tool_call", {
            "call_id": call_id, "tool": tool, "target": target,
            "decision": decision, "exit_code": exit_code, "error": error,
        })


def _run_capped(argv: list[str], cwd: Path, env: dict, timeout: float):
    """Run argv and stream both pipes into bounded buffers.

    Output is capped while capturing, not after: a chatty tool must not be
    able to make the platform buffer gigabytes.
    """
    proc = subprocess.Popen(argv, cwd=str(cwd), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = bytearray(), bytearray()
    truncated = [False]

    def drain(pipe, buf):
        try:
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    return
                if len(buf) < MAX_OUTPUT:
                    buf += chunk[:MAX_OUTPUT - len(buf)]
                if len(chunk) and len(buf) >= MAX_OUTPUT:
                    truncated[0] = True
        except (OSError, ValueError):
            return  # pipe closed by timeout kill

    readers = [threading.Thread(target=drain, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, err), daemon=True)]
    for t in readers:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    for t in readers:
        t.join(5)
    for pipe in (proc.stdout, proc.stderr):
        try:
            pipe.close()
        except OSError:
            pass
    return bytes(out), bytes(err), (None if timed_out else proc.returncode), timed_out, truncated[0]


def _is_host(target: str) -> bool:
    return "://" not in target
