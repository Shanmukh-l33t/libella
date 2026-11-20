"""Code / supply-chain scanner adapters: semgrep, trivy fs, gitleaks.

Same contract as adapters.py — closed params, argv built by code, parsers that
return structured dicts — except the target is a local directory, not a URL,
so the scope gate does not apply: `confine_repo` is the trust boundary.

Handlers receive a `LocalCtx` (not a Scope Decision) and use it only to place
their artifacts (rules file, caches, reports) in a per-assessment directory.
"""
import json
import os
import re
import tempfile

from . import ToolSpec

# Audited ruleset kept local: the registry rulesets (p/python, p/default) need
# network access and change under us, which would make scans non-reproducible.
LOCAL_RULES = """rules:
  - id: libella-eval-exec
    languages: [python]
    message: Dynamic code evaluation; runtime input reaches the interpreter.
    severity: ERROR
    metadata: {cwe: ["CWE-94"], confidence: HIGH}
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
  - id: libella-shell-true
    languages: [python]
    message: Command run through a shell.
    severity: ERROR
    metadata: {cwe: ["CWE-78"], confidence: HIGH}
    pattern-either:
      - pattern: subprocess.$F(..., shell=True, ...)
      - pattern: os.system(...)
      - pattern: os.popen(...)
  - id: libella-unsafe-deserialization
    languages: [python]
    message: Deserialization of untrusted data into arbitrary objects.
    severity: ERROR
    metadata: {cwe: ["CWE-502"], confidence: HIGH}
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: yaml.load($X)
  - id: libella-flask-debug-true
    languages: [python]
    message: Flask debug mode enabled in the server entry point.
    severity: ERROR
    metadata: {cwe: ["CWE-489"], confidence: HIGH}
    pattern: $APP.run(..., debug=True, ...)
"""

CWE_RE = re.compile(r"CWE-(\d+)")
# These reach argv as a path, so shell metacharacters are refused up front.
FORBIDDEN_PATH_CHARS = (";", "|", "&", "$", "`", "\n", "\r", ">", "<", "\x00")


class LocalCtx:
    """'decision' argument for local adapters: a work dir plus allowed roots."""

    resolved_ips: list[str] = []

    def __init__(self, workdir: str, roots: list[str] | None = None):
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.roots = roots


def code_roots() -> list[str]:
    env = os.environ.get("LIBELLA_CODE_ROOTS")
    roots = [p for p in (env or "").split(os.pathsep) if p]
    return roots or [os.getcwd()]


def _ctx_dir(decision) -> str:
    d = getattr(decision, "workdir", None)
    if not d:
        d = tempfile.mkdtemp(prefix="libella-code-")
    os.makedirs(d, exist_ok=True)
    return d


def confine_repo(value: str, roots: list[str] | None = None) -> str:
    """A repo path must be an existing directory inside one of the code roots."""
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("repo must be a non-empty path string")
    if any(c in value for c in FORBIDDEN_PATH_CHARS):
        raise ValueError("repo path contains forbidden characters")
    if ".." in value.replace("\\", "/").split("/"):
        raise ValueError("repo path must not contain '..'")
    real = os.path.realpath(os.path.abspath(os.path.expanduser(value)))
    if not os.path.isdir(real):
        raise ValueError(f"repo path '{value}' is not an existing directory")
    for root in roots if roots is not None else code_roots():
        r = os.path.realpath(os.path.abspath(os.path.expanduser(root)))
        if real == r or real.startswith(r + os.sep):
            return real
    raise ValueError(f"repo path '{value}' is outside the permitted code roots")


# ---- semgrep ----

def rules_file(decision) -> str:
    path = os.path.join(_ctx_dir(decision), "libella-code-rules.yml")
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(LOCAL_RULES)
    return path


def _semgrep_argv(p: dict, decision) -> list[str]:
    repo = confine_repo(p["repo"], getattr(decision, "roots", None))
    ruleset = p.get("ruleset", "local")
    config = rules_file(decision) if ruleset == "local" else ruleset
    return ["semgrep", "--config", config, "--json", "--quiet", "--metrics=off",
            "--disable-version-check", "--no-git-ignore", "--timeout", "30",
            "--max-target-bytes", "2000000", repo]


def _first_cwe(metadata: dict) -> str | None:
    for item in metadata.get("cwe") or []:
        m = CWE_RE.search(str(item))
        if m:
            return f"CWE-{m.group(1)}"
    return None


def parse_semgrep_json(stdout: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return []
    out = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        check_id = r.get("check_id") or ""
        out.append({
            "rule": check_id.rsplit(".", 1)[-1],  # a config path prefixes the id
            "path": r.get("path"),
            "line": (r.get("start") or {}).get("line"),
            "message": extra.get("message"),
            "severity": extra.get("severity"),
            "cwe": _first_cwe(extra.get("metadata") or {}),
        })
    return out


SEMGREP = ToolSpec(
    name="semgrep", description="Static analysis of a local repository (CWE rules).",
    category="code", binary="semgrep", timeout_s=300, network_effect=False,
    params={
        "repo": {"type": "string", "maxLength": 4096},
        "ruleset": {"type": "string", "enum": ["local", "p/python", "p/default"]},
    },
    required=["repo"], handler=_semgrep_argv, target_param="repo",
)


# ---- trivy fs ----

def _trivy_argv(p: dict, decision) -> list[str]:
    repo = confine_repo(p["repo"], getattr(decision, "roots", None))
    cache = os.path.join(_ctx_dir(decision), "trivy-cache")
    return ["trivy", "fs", "--format", "json", "--quiet", "--no-progress",
            "--exit-code", "0", "--skip-check-update", "--skip-db-update",
            "--cache-dir", cache, "--timeout", "120s",
            "--scanners", p.get("scanners", "secret,misconfig"), repo]


def parse_trivy_json(stdout: str) -> dict:
    empty = {"vulnerabilities": [], "secrets": [], "misconfigurations": []}
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return empty
    out = {k: [] for k in empty}
    for res in data.get("Results") or []:
        target = res.get("Target")
        for v in res.get("Vulnerabilities") or []:
            out["vulnerabilities"].append({
                "cve": v.get("VulnerabilityID"), "package": v.get("PkgName"),
                "version": v.get("InstalledVersion"), "fixed": v.get("FixedVersion"),
                "severity": v.get("Severity"), "target": target,
            })
        for s in res.get("Secrets") or []:
            out["secrets"].append({"rule": s.get("RuleID"), "target": target,
                                   "line": s.get("StartLine"), "title": s.get("Title"),
                                   "severity": s.get("Severity")})
        for m in res.get("Misconfigurations") or []:
            out["misconfigurations"].append({
                "id": m.get("ID"), "target": target,
                "line": (m.get("CauseMetadata") or {}).get("StartLine"),
                "title": m.get("Title"), "severity": m.get("Severity"),
            })
    return out


TRIVY_FS = ToolSpec(
    name="trivy_fs", description="Filesystem scan of a local repository (secrets, misconfig).",
    category="code", binary="trivy", timeout_s=300, network_effect=False,
    params={
        "repo": {"type": "string", "maxLength": 4096},
        # dependency CVEs come from OSV: a trivy vuln scan would need a DB download
        "scanners": {"type": "string", "enum": ["secret", "misconfig", "secret,misconfig"]},
    },
    required=["repo"], handler=_trivy_argv, target_param="repo",
)


# ---- gitleaks ----

def gitleaks_report_path(decision) -> str:
    return os.path.join(_ctx_dir(decision), "gitleaks.json")


def _gitleaks_argv(p: dict, decision) -> list[str]:
    repo = confine_repo(p["repo"], getattr(decision, "roots", None))
    return ["gitleaks", "dir", repo, "--report-format", "json",
            "--report-path", gitleaks_report_path(decision),
            "--no-banner", "--exit-code", "0", "--redact"]


def parse_gitleaks_json(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    return [{"rule": f.get("RuleID"), "file": f.get("File"), "line": f.get("StartLine"),
             "description": f.get("Description")} for f in data]


GITLEAKS = ToolSpec(
    name="gitleaks", description="Secret scan of a local repository (values redacted).",
    category="code", binary="gitleaks", timeout_s=180, network_effect=False,
    params={"repo": {"type": "string", "maxLength": 4096}},
    required=["repo"], handler=_gitleaks_argv, target_param="repo",
)

SPECS = [SEMGREP, TRIVY_FS, GITLEAKS]
PARSERS = {"semgrep": parse_semgrep_json, "trivy_fs": parse_trivy_json,
           "gitleaks": parse_gitleaks_json}
