"""Source-code & supply-chain assessment for a local repository.

Two epistemic levels, kept strictly apart:

* code issues (CWE-94/78/502/489/798) are *observed*: each one is bound to the
  scanner artifact that produced it. Nothing was dialed, so there is nothing to
  replay — they are never promoted to validated. Promotion needs a deterministic
  re-verification pass (re-scan the pinned file+line and diff the hit), which
  this module does not fake.
* dependency CVEs are *potentially_affected* observations. A pinned version
  matching an OSV advisory says the version range is affected; it says nothing
  about whether the vulnerable code is loaded, reachable, or exploitable here.
  They are never submitted as findings.

Every subprocess is argv-only (no shell), time-boxed, output-capped, and
audited in tool_calls with its evidence artifact.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .db import new_id
from .tools import resolve_binary, validate_params
from .tools.code_adapters import (GITLEAKS, SEMGREP, TRIVY_FS, LocalCtx, SPECS,
                                  confine_repo, gitleaks_report_path,
                                  parse_gitleaks_json, parse_semgrep_json,
                                  parse_trivy_json)
from .tools.runner import MAX_OUTPUT, _run_capped

__all__ = ["assess_repo", "SPECS", "CATALOG"]

OSV_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 20
MAX_PINS = 40
PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([0-9][A-Za-z0-9.+!-]*)$")

CATALOG = {
    "CWE-94": {
        "title": "Dynamic code evaluation of untrusted input", "severity": "high",
        "owasp": "A03:2021", "confidence": "high",
        "description": "A runtime value reaches eval()/exec(), so the request decides which "
                       "Python code the server runs.",
        "impact": "Arbitrary code execution in the service process and its credentials.",
        "remediation": "Parse the value with ast.literal_eval, a real grammar, or a lookup "
                       "table; never evaluate request data.",
    },
    "CWE-78": {
        "title": "OS command injection through a shell", "severity": "high",
        "owasp": "A03:2021", "confidence": "high",
        "description": "A command string built from runtime input is executed with "
                       "shell=True, so shell metacharacters become commands.",
        "impact": "Arbitrary command execution as the service account.",
        "remediation": "Pass an argv list with shell=False and validate the argument against "
                       "a strict allowlist.",
    },
    "CWE-502": {
        "title": "Deserialization of untrusted data", "severity": "high",
        "owasp": "A08:2021", "confidence": "high",
        "description": "pickle/yaml deserialize attacker-controlled bytes, which can build "
                       "arbitrary objects and run code via __reduce__.",
        "impact": "Remote code execution during deserialization.",
        "remediation": "Use a data-only format (json, msgpack) with a schema check; never "
                       "unpickle request bodies.",
    },
    "CWE-489": {
        "title": "Debug mode enabled in the server entry point", "severity": "medium",
        "owasp": "A05:2021", "confidence": "high",
        "description": "The application runs with debug=True, exposing the Werkzeug "
                       "interactive debugger and verbose tracebacks.",
        "impact": "Code execution via the debugger console plus source and config disclosure.",
        "remediation": "Run with debug=False; enable debugging locally only, behind a flag "
                       "that cannot be set in production.",
    },
    "CWE-798": {
        "title": "Hardcoded credential in source", "severity": "high",
        "owasp": "A07:2021", "confidence": "high",
        "description": "A key or secret literal is committed to the repository, so everyone "
                       "with read access to the code (or its history) holds it.",
        "impact": "Impersonation of the service against the credential's provider.",
        "remediation": "Load secrets from the environment or a secret manager, rotate the "
                       "exposed value, and purge it from history.",
    },
}

def _binary(name: str) -> str | None:
    """Prefer the interpreter's own bin dir (semgrep lives in the venv)."""
    local = os.path.join(os.path.dirname(sys.executable), name)
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return resolve_binary(name)


def _audit(db, call_id, engagement_id, intent_id, tool, argv, target, decision,
           exit_code, started, artifact_id, error):
    db.execute(
        "INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
        "scope_decision, exit_code, duration_ms, artifact_id, error, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (call_id, engagement_id, intent_id, tool, json.dumps(argv), target, decision,
         exit_code, round((time.time() - started) * 1000, 1), artifact_id, error, time.time()),
    )
    db.emit(engagement_id, "tool_call", {
        "call_id": call_id, "tool": tool, "target": target, "decision": decision,
        "exit_code": exit_code, "error": error,
    })


def _exec(spec, params, ctx, db, evidence, engagement_id, intent_id) -> dict:
    """Run one adapter: validate -> argv -> subprocess -> evidence + audit row."""
    call_id = new_id("tc")
    started = time.time()
    try:
        clean = validate_params(spec, params)
        argv = spec.handler(clean, ctx)
        if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
            raise ValueError("adapter must return a non-empty list[str] argv")
    except ValueError as e:
        _audit(db, call_id, engagement_id, intent_id, spec.name, [],
               f"file://{params.get('repo', '?')}", "refused: " + str(e),
               None, started, None, str(e))
        return {"ok": False, "error": f"invalid_params: {e}", "call_id": call_id}

    binary = _binary(argv[0])
    if binary is None:
        err = f"tool binary '{argv[0]}' not installed"
        _audit(db, call_id, engagement_id, intent_id, spec.name, [],
               f"file://{params.get('repo', '?')}", "refused: missing binary",
               None, started, None, err)
        return {"ok": False, "error": f"missing_tool: {err}", "call_id": call_id,
                "degradation": "missing_tool"}
    argv[0] = binary

    rundir = Path(ctx.workdir) / call_id
    rundir.mkdir(parents=True, exist_ok=True)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(rundir), "LANG": "C.UTF-8",
           "NO_COLOR": "1", "SEMGREP_SEND_METRICS": "off",
           "TRIVY_CACHE_DIR": os.path.join(str(rundir), "trivy-cache")}
    stdout, stderr, code, timed_out, truncated = _run_capped(argv, rundir, env, spec.timeout_s)

    payload = {"argv": argv, "stdout": stdout.decode(errors="replace"),
               "stderr": stderr.decode(errors="replace"), "exit_code": code,
               "timed_out": timed_out, "truncated": truncated}
    report = None
    if spec is GITLEAKS:
        path = gitleaks_report_path(ctx)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                report = fh.read(MAX_OUTPUT).decode(errors="replace")
            payload["report"] = report
    artifact = evidence.put(engagement_id, json.dumps(payload, default=str).encode(),
                            "tool_output")
    status = "timeout" if timed_out else ("ok" if code == 0 else "failed")
    _audit(db, call_id, engagement_id, intent_id, spec.name, argv, f"file://{params['repo']}",
           f"executed: {status} (local filesystem, no target egress)", code, started,
           artifact["id"], None if status == "ok" else status)
    return {"ok": status == "ok", "status": status, "call_id": call_id, "argv": argv,
            "artifact_id": artifact["id"], "exit_code": code, "report": report,
            "stdout": stdout.decode(errors="replace"), "truncated": truncated,
            "timed_out": timed_out, "error": None if status == "ok" else status}


def _mask(text: str) -> str:
    text = re.sub(r'"[^"\n]{8,}"', '"***"', text)
    return re.sub(r"'[^'\n]{8,}'", "'***'", text)


def _rel_in_repo(repo: str, path: str | None) -> str | None:
    if not path:
        return None
    full = path if os.path.isabs(path) else os.path.join(repo, path)
    real = os.path.realpath(full)
    if real != repo and not real.startswith(repo + os.sep):
        return None
    return os.path.relpath(real, repo)


def _source_line(repo: str, rel: str, line: int | None, mask: bool = False) -> str:
    if not line:
        return ""
    path = os.path.realpath(os.path.join(repo, rel))
    if not path.startswith(repo + os.sep):
        return ""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, text in enumerate(fh, 1):
                if i == line:
                    text = text.strip()[:300]
                    return _mask(text) if mask else text
    except OSError:
        return ""
    return ""


def _hits(repo: str, runs: dict) -> list[dict]:
    """Collect code hits from the parsed scanner outputs, one per root cause."""
    code: list[dict] = []
    secrets: list[dict] = []
    seen: set[tuple] = set()

    def add(cwe, path, line, rule, masked=False):
        rel = _rel_in_repo(repo, path)
        if cwe not in CATALOG or rel is None or not line:
            return
        hit = {"cwe": cwe, "file": rel, "line": int(line), "rule": rule, "masked": masked}
        if (cwe, rel, int(line)) in seen:
            return
        seen.add((cwe, rel, int(line)))
        (secrets if masked else code).append(hit)

    for h in parse_semgrep_json(runs["semgrep"].get("stdout") or ""):
        add(h["cwe"], h["path"], h["line"], h["rule"])
    for s in parse_trivy_json(runs["trivy_fs"].get("stdout") or "")["secrets"]:
        add("CWE-798", s["target"], s["line"], f"trivy:{s['rule']}", masked=True)
    for g in parse_gitleaks_json(runs["gitleaks"].get("report") or ""):
        add("CWE-798", g["file"], g["line"], f"gitleaks:{g['rule']}", masked=True)

    # one credential per adjacent cluster: scanners anchor a PEM block on its
    # first or last line and neighbours share a single fix
    # shortcut: 3-line radius, tighten if a repo packs distinct secrets
    clusters: list[dict] = []
    for hit in secrets:
        kept = next((c for c in clusters if c["file"] == hit["file"]
                     and abs(c["line"] - hit["line"]) <= 3), None)
        if kept is None:
            clusters.append(hit)
        elif hit["line"] < kept["line"]:
            kept["line"] = hit["line"]
    return code + clusters


def _submit(hit, repo, artifact_ids, evidence, pipeline, engagement_id, intent_id) -> dict:
    meta = CATALOG[hit["cwe"]]
    label = os.path.basename(repo)
    quote = _source_line(repo, hit["file"], hit["line"], mask=hit["masked"])
    artifact = artifact_ids.get("gitleaks" if hit["masked"] else "semgrep")
    ev = evidence.put_json(engagement_id, {
        "repo": repo, "file": hit["file"], "line": hit["line"], "cwe": hit["cwe"],
        "rule": hit["rule"], "quote": quote, "scanner_artifact": artifact,
        "epistemic_state": "observed (static; no replay possible)",
    }, "code_finding")
    cand = {
        "title": f"{meta['title']} ({hit['file']}:{hit['line']})",
        "cwe": hit["cwe"], "owasp": meta["owasp"], "severity": meta["severity"],
        "confidence": meta["confidence"],
        "endpoint": f"file://{label}/{hit['file']}#L{hit['line']}",
        "description": meta["description"], "impact": meta["impact"],
        "remediation": meta["remediation"], "evidence_ids": [ev["id"]], "quote": quote,
        "quote_in": "code",
        "dedup_key": f"code:{label}:{hit['cwe']}:{hit['file']}:{hit['line']}",
        "proof_request": {"method": "STATIC", "file": hit["file"], "line": hit["line"],
                          "rule": hit["rule"], "scanner_artifact": artifact},
    }
    return pipeline.submit_candidate(engagement_id, cand, intent_id)


def _pins(repo: str) -> list[tuple[str, str]]:
    """Exact `name==version` pins from requirements.txt (the only file we read)."""
    pins = []
    try:
        with open(os.path.join(repo, "requirements.txt"), encoding="utf-8",
                  errors="replace") as fh:
            lines = fh.read(200_000).splitlines()
    except OSError:
        return pins
    for raw in lines:
        m = PIN_RE.match(raw.split("#", 1)[0].strip())
        if m and "*" not in m.group(2):
            pins.append((m.group(1), m.group(2)))
    return pins[:MAX_PINS]


def _osv_cves(data: dict) -> list[str]:
    out: list[str] = []
    for v in data.get("vulns") or []:
        ids = [v.get("id")] + list(v.get("aliases") or [])
        cve = next((i for i in ids if i and i.startswith("CVE-")), v.get("id"))
        if cve and cve not in out:
            out.append(cve)
    return out


def _osv_assess(repo: str, db, evidence, pipeline, engagement_id, intent_id,
                observations: list) -> dict:
    """Version-matched advisories: observations only, never findings."""
    pins = _pins(repo)
    call_id = new_id("tc")
    started = time.time()
    retrieved_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    queries, hits, failures = [], [], []
    for package, version in pins:
        body = json.dumps({"package": {"name": package, "ecosystem": "PyPI"},
                           "version": version}).encode()
        try:
            req = urllib.request.Request(OSV_URL, data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
                data = json.loads(resp.read(MAX_OUTPUT))
        except (OSError, ValueError) as e:
            failures.append(f"{package}=={version}: {e}")
            continue
        queries.append({"package": package, "version": version, "response": data})
        for cve in _osv_cves(data):
            hits.append({"cve": cve, "package": package, "version": version,
                         "source": "osv", "retrieved_at": retrieved_at})
    artifact = evidence.put_json(engagement_id, {"url": OSV_URL, "retrieved_at": retrieved_at,
                                                 "queries": queries}, "osv_query")
    _audit(db, call_id, engagement_id, intent_id, "osv", ["POST", OSV_URL], OSV_URL,
           "executed: public advisory metadata (package names/versions only, no target egress)",
           0 if not failures else 1, started, artifact["id"], "; ".join(failures) or None)

    recorded = []
    for hit in hits:
        oid = pipeline.record_observation(
            engagement_id, intent_id, "potentially_affected",
            json.dumps(hit, sort_keys=True), evidence_id=artifact["id"], quote=hit["cve"])
        observations.append(oid)
        recorded.append({"id": oid, **hit})
    return {"pins": [f"{p}=={v}" for p, v in pins], "potentially_affected": recorded,
            "artifact_id": artifact["id"], "errors": failures}


def assess_repo(repo_path, db, evidence, pipeline, engagement_id, intent_id=None, *,
                roots=None, dependencies=True) -> dict:
    """Assess a local repository: static code issues + dependency advisory matches.

    roots: directories a repo path may live in (default: LIBELLA_CODE_ROOTS or cwd).
    dependencies: query OSV for pinned versions (never promotes to findings).
    """
    started = time.time()
    repo = confine_repo(str(repo_path), roots)
    workdir = tempfile.mkdtemp(prefix="libella-code-")
    ctx = LocalCtx(workdir, roots=roots)
    runs, degradations, findings, observations = {}, [], [], []
    try:
        plans = (("semgrep", SEMGREP, {"repo": repo, "ruleset": "local"}),
                 ("trivy_fs", TRIVY_FS, {"repo": repo, "scanners": "secret,misconfig"}),
                 ("gitleaks", GITLEAKS, {"repo": repo}))
        for name, spec, params in plans:
            run = _exec(spec, params, ctx, db, evidence, engagement_id, intent_id)
            runs[name] = run
            if not run["ok"]:
                degradations.append({"tool": name,
                                     "reason": run.get("error") or f"exit {run['exit_code']}"})
        hits = sorted(_hits(repo, runs), key=lambda h: (h["cwe"], h["file"], h["line"]))
        artifact_ids = {name: run.get("artifact_id") for name, run in runs.items()}
        for hit in hits:
            findings.append(_submit(hit, repo, artifact_ids, evidence, pipeline,
                                    engagement_id, intent_id))
        for name, run in runs.items():
            if run["ok"]:
                observations.append(pipeline.record_observation(
                    engagement_id, intent_id, "code_scan",
                    f"{name}: scan of {os.path.basename(repo)} completed"
                    f" ({run['artifact_id']})", evidence_id=run["artifact_id"]))
        deps = ({"pins": [], "potentially_affected": []} if not dependencies else
                _osv_assess(repo, db, evidence, pipeline, engagement_id, intent_id,
                            observations))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return {
        "repo": repo, "engagement_id": engagement_id,
        "findings": findings, "observations": observations, "dependencies": deps,
        "scanners": {n: {"ok": r["ok"], "artifact_id": r.get("artifact_id"),
                         "argv": r.get("argv")} for n, r in runs.items()},
        "degradations": degradations,
        "duration_ms": round((time.time() - started) * 1000, 1),
    }
