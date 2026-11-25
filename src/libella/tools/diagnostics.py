"""Functional tool diagnostics: run the tool's version/self-test command.

A binary on PATH is not a working scanner. This probe executes only the
tool's own version flag (no target, no engagement params), with no shell,
captured output and a short timeout, and reports ready/broken/missing. It
takes no target. Executables are trusted local installations, not sandboxed.
"""
import os
import re
import tempfile
import threading
import time
from pathlib import Path

from . import ToolSpec, resolve_binary

PROBE_TIMEOUT_S = 5.0
CACHE_TTL_S = 30.0  # repeated /api/tools calls must not re-exec every scanner
VERSION_ARGS = {
    "nmap": ["--version"],
    "nuclei": ["-version"],
    "semgrep": ["--version"],
    "httpx": ["-version"],
    "subfinder": ["-version"],
    "trivy": ["--version"],
    "gitleaks": ["version"],
    "ffuf": ["-V"],
    "zap.sh": ["-version"],
}
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
# Prefer a labelled version: scanners print warnings/engine notices before it
# (e.g. nuclei's "go1.17~1.26" fallback warning ahead of "Engine Version: v3.11.1").
_LABELLED_VERSION_RE = re.compile(r"version:?\s*v?(\d+\.\d+(?:\.\d+)?)", re.I)

# shortcut: keyed by binary name only; a replaced binary reads stale for <=30s.
_CACHE: dict[str, tuple[float, dict]] = {}
_PROBE_LOCK = threading.Lock()


def clear_cache() -> None:
    _CACHE.clear()


def _parse_version(out: str) -> str | None:
    m = _LABELLED_VERSION_RE.search(out)
    if m:
        return m.group(1)
    m = _VERSION_RE.search(out)
    return m.group(0) if m else None


def _probe(binary: str) -> dict:
    hit = _CACHE.get(binary)
    if hit and time.monotonic() - hit[0] < CACHE_TTL_S:
        return dict(hit[1])
    args = VERSION_ARGS.get(os.path.basename(binary))
    path = resolve_binary(binary)
    if path is None:
        result = {"status": "missing", "version": None,
                  "detail": f"binary '{binary}' not found"}
    elif not args:
        result = {"status": "unverified", "version": None, "detail": "No version probe configured."}
    else:
        from .runner import _run_capped

        try:
            with tempfile.TemporaryDirectory() as home:
                stdout, stderr, code, timed_out, _ = _run_capped(
                    [os.path.abspath(path), *args], Path(home),
                    {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8"},
                    PROBE_TIMEOUT_S)
        except OSError:
            result = {"status": "broken", "version": None, "detail": "Could not execute the version probe."}
        else:
            version = _parse_version((stdout + b"\n" + stderr).decode(errors="replace"))
            if timed_out:
                result = {"status": "broken", "version": None, "detail": "Version probe timed out."}
            elif code == 0 and version:
                result = {"status": "ready", "version": version,
                          "detail": f"Version command returned {version}."}
            elif code == 0:
                result = {"status": "broken", "version": None,
                          "detail": "The command returned no recognizable version."}
            else:
                result = {"status": "broken", "version": version,
                          "detail": f"Version command exited with code {code}."}
    _CACHE[binary] = (time.monotonic(), result)
    return dict(result)


def diagnose(spec: ToolSpec) -> dict:
    """Check whether an allowlisted version command starts; not scanner readiness."""
    if spec.binary is None:
        return {"name": spec.name, "status": "unverified", "version": None,
                "detail": "In-process adapter; no version probe configured."}
    with _PROBE_LOCK:
        return {"name": spec.name, **_probe(spec.binary)}
