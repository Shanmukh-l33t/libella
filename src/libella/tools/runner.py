"""Subprocess tool runner: validated argv, scope gate, timeouts, audit.

The LLM never composes a command line. Adapters build argv from typed
params; this runner re-checks scope, executes without a shell, caps output,
and writes an audit row for every call (including refusals).

A subprocess is killed (process group) when its timeout expires, when the
engagement is cancelled or paused, or when its authorized window closes, so
a control is never bounded by the tool's own timeout.
"""
import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from ..assessment_window import stored_stop_refusal
from ..db import DB, new_id
from ..evidence import EvidenceStore
from ..scope import Decision, Scope
from . import ToolSpec, resolve_binary, validate_params

MAX_OUTPUT = 512 * 1024  # per stream cap
POLL_S = 0.1  # how often a running tool re-checks its timeout / cancel flag


class ToolRunner:
    def __init__(self, db: DB, evidence: EvidenceStore, workdir: str | Path, limiter=None):
        self.db = db
        self.evidence = evidence
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        # (engagement_id, rps) -> object with .wait(); the orchestrator wires the
        # probe's per-engagement limiter here so tool launches and HTTP requests
        # together honor the declared rate.
        self.limiter = limiter

    def run(
        self,
        spec: ToolSpec,
        params: dict,
        scope: Scope,
        engagement_id: str,
        intent_id: str | None,
        target: str,
        category: str | None = None,
        on_progress=None,
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
        if _is_host(dest):
            ports = _declared_ports(spec, clean)
            authorized = scope.authorized_ports(dest) if spec.port_param else None
            if ports is None and spec.port_param and authorized:
                # an undeclared/ranged port set cannot be confined to the authorized ports
                decision = Decision(False, f"port set not declared; cannot confine to "
                                           f"the authorized ports {authorized}")
            else:
                decision = scope.check_host_port(dest, None, cat)
                for p in ports or ():
                    if not decision.allowed:
                        break
                    decision = scope.check_host_port(dest, p, cat)
        else:
            decision = scope.check_url(dest, cat)
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
        if self.limiter is not None:
            self.limiter(engagement_id, scope.rate_limit_rps).wait()
        stdout, stderr, exit_code, timed_out, truncated = _run_capped(
            argv, rundir, {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(rundir),
                           "LANG": "C.UTF-8", "NO_COLOR": "1"}, spec.timeout_s,
            should_stop=lambda: self._stop_reason(engagement_id) is not None,
            on_line=on_progress)
        stopped_by = None if timed_out else self._stop_reason(engagement_id)
        cancelled = stopped_by is not None

        duration_ms = (time.time() - started) * 1000
        artifact = self.evidence.put(
            engagement_id,
            json.dumps({"argv": argv, "stdout": stdout.decode(errors="replace"),
                        "stderr": stderr.decode(errors="replace"), "exit_code": exit_code,
                        "timed_out": timed_out, "cancelled": cancelled,
                        "stopped_by": stopped_by,
                        "truncated": truncated}, default=str).encode(),
            "tool_output",
        )
        status = ("cancelled" if cancelled else
                  "timeout" if timed_out else ("ok" if exit_code == 0 else "failed"))
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
            "partial": timed_out or cancelled,
            "cancelled": cancelled,
            "stopped_by": stopped_by,
        }
        if stopped_by:
            # why it stopped, so a caller reporting r["error"] says something true
            result["error"] = stopped_by
        if timed_out:
            result["degradation"] = "timeout_partial_never_complete"
        elif cancelled:
            result["degradation"] = "cancelled_partial_never_complete"
        return result

    def _stop_reason(self, engagement_id: str) -> str | None:
        """A cancelled/paused engagement, or a closed window, must not keep a subprocess alive."""
        return stored_stop_refusal(self.db, engagement_id)

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


def _run_capped(argv: list[str], cwd: Path, env: dict, timeout: float, should_stop=None,
                on_line=None):
    """Run argv and stream both pipes into bounded buffers.

    Output is capped while capturing, not after: a chatty tool must not be
    able to make the platform buffer gigabytes. The child is its own session,
    so a timeout or a cancel kills its whole process group (no orphaned
    scanner children continuing to touch the target).
    """
    proc = subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    out, err = bytearray(), bytearray()
    truncated = [False]

    def drain(pipe, buf, emit=None):
        pending = b""
        try:
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    return
                if len(buf) < MAX_OUTPUT:
                    buf += chunk[:MAX_OUTPUT - len(buf)]
                if len(chunk) and len(buf) >= MAX_OUTPUT:
                    truncated[0] = True
                if emit is not None:
                    pending += chunk
                    *lines, pending = pending.split(b"\n")
                    pending = pending[-4096:]  # a line longer than this is not progress
                    for line in lines[-40:]:   # bound work per chunk on a chatty tool
                        try:
                            emit(line.decode(errors="replace"))
                        except Exception:
                            pass  # a progress consumer must never kill the scan
        except (OSError, ValueError):
            return  # pipe closed by timeout/cancel kill

    readers = [threading.Thread(target=drain, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, err, on_line), daemon=True)]
    for t in readers:
        t.start()
    timed_out = False
    deadline = time.monotonic() + timeout
    while True:
        try:
            proc.wait(timeout=POLL_S)
            break
        except subprocess.TimeoutExpired:
            stop = _stop_requested(should_stop)
            if stop or time.monotonic() >= deadline:
                timed_out = not stop  # a cancel is a cancel, not a timeout
                _kill_group(proc)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                break
    for t in readers:
        t.join(5)
    for pipe in (proc.stdout, proc.stderr):
        try:
            pipe.close()
        except OSError:
            pass
    return bytes(out), bytes(err), (None if timed_out else proc.returncode), timed_out, truncated[0]


def _stop_requested(should_stop) -> bool:
    """A monitor that fails to answer must not keep a tool alive past its timeout."""
    try:
        return bool(should_stop and should_stop())
    except Exception:
        return False


def _kill_group(proc):
    """Kill the tool and everything it spawned (it runs in its own session)."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def _is_host(target: str) -> bool:
    return "://" not in target


def _declared_ports(spec: ToolSpec, params: dict) -> list[int] | None:
    """Ports the adapter will dial, when its param makes them enumerable.

    None means no enumerable port set (absent, or a range/service name): callers
    may only authorize the host itself, never claim an allowed_ports match.
    """
    raw = params.get(spec.port_param) if spec.port_param else None
    if not raw:
        return None
    ports = []
    for part in str(raw).split(","):
        part = part.strip()
        if not part.isdigit():
            return None
        ports.append(int(part))
    return ports
