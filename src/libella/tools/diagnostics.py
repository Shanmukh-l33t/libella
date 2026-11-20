"""Functional tool diagnostics: run the tool's version/self-test command.

A binary on PATH is not a working scanner. This probe executes only the
tool's own version flag (no target, no engagement params), with no shell,
captured output and a short timeout, and reports ready/broken/missing. It
never dials anything, so it needs no scope decision.
"""
import os
import re
import subprocess
import time

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
    args = VERSION_ARGS.get(os.path.basename(binary), ["--version"])
    path = resolve_binary(binary)
    if path is None:
        result = {"status": "missing", "version": None,
                  "detail": f"binary '{binary}' not found"}
    else:
        try:
            p = subprocess.run([path, *args], capture_output=True, text=True,
                               errors="replace", timeout=PROBE_TIMEOUT_S, shell=False)
        except subprocess.TimeoutExpired:
            result = {"status": "broken", "version": None,
                      "detail": f"'{' '.join(args)}' timed out after {PROBE_TIMEOUT_S:g}s"}
        except OSError as e:
            result = {"status": "broken", "version": None, "detail": f"cannot execute: {e}"}
        else:
            out = f"{p.stdout}\n{p.stderr}".strip()
            version = _parse_version(out)
            if p.returncode == 0 and version:
                result = {"status": "ready", "version": version,
                          "detail": f"'{' '.join(args)}' -> {version}"}
            elif p.returncode == 0:
                result = {"status": "broken", "version": None,
                          "detail": f"exit 0 but no version in output: {out[:160]}"}
            else:
                result = {"status": "broken", "version": None,
                          "detail": f"exit {p.returncode}: {out[:160]}"}
    _CACHE[binary] = (time.monotonic(), result)
    return dict(result)


def diagnose(spec: ToolSpec) -> dict:
    """One readiness row for a tool: ready | broken | missing."""
    if spec.binary is None:
        return {"name": spec.name, "status": "ready", "version": None,
                "detail": "in-process handler; no external binary to probe"}
    return {"name": spec.name, **_probe(spec.binary)}
