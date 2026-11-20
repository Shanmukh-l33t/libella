"""Container image assessment: trivy vulnerability scan of LOCAL images.

No target egress (local image analysis). CVE matches are version-based:
recorded as potentially_affected observations, NEVER auto-validated findings
(same discipline as the OSV dependency layer).
"""
import json
import subprocess
import time

from ..db import DB, new_id
from ..evidence import EvidenceStore
from ..findings import FindingPipeline
from . import ToolSpec, resolve_binary, validate_params

MAX_OUTPUT = 4 * 1024 * 1024


def _trivy_image_argv(p: dict, decision=None) -> list[str]:
    return ["trivy", "image", "--format", "json", "--scanners", "vuln",
            "--timeout", "10m", "--quiet", p["image"]]


TRIVY_IMAGE = ToolSpec(
    name="trivy_image", description="Vulnerability scan of a local container image (version-based).",
    category="code", binary="trivy", timeout_s=600, network_effect=False,
    params={"image": {"type": "string", "maxLength": 300}},
    required=["image"], handler=_trivy_image_argv,
)


def parse_trivy_json(stdout: str) -> dict:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {"vulnerabilities": [], "parse_error": True}
    vulns = []
    for result in data.get("Results", []):
        target = result.get("Target")
        for v in result.get("Vulnerabilities", []) or []:
            vulns.append({
                "id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"),
                "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion"),
                "severity": v.get("Severity"), "title": v.get("Title"),
                "target": target,
            })
    return {"vulnerabilities": vulns, "parse_error": False}


def assess_image(image: str, db: DB, evidence: EvidenceStore, pipeline: FindingPipeline,
                 engagement_id: str, intent_id: str | None = None) -> dict:
    """Scan a local image; record version-based CVE observations with evidence."""
    started = time.time()
    call_id = new_id("tc")
    try:
        validate_params(TRIVY_IMAGE, {"image": image})
    except ValueError as e:
        db.execute(
            "INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
            "scope_decision, exit_code, duration_ms, artifact_id, error, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (call_id, engagement_id, intent_id, "trivy_image", "[]", image,
             f"refused: {e}", None, 0, None, str(e), time.time()))
        return {"ok": False, "error": str(e)}
    binary = resolve_binary("trivy")
    if binary is None:
        db.emit(engagement_id, "degradation", {"code": "missing_tool", "detail": "trivy not installed"})
        return {"ok": False, "error": "missing_tool: trivy", "degradation": "missing_tool"}
    # image must exist locally (no remote pull by the platform)
    inspect = subprocess.run(["docker", "image", "inspect", image],
                             capture_output=True, timeout=30)
    if inspect.returncode != 0:
        db.emit(engagement_id, "degradation",
                {"code": "image_not_local", "detail": f"{image} not present locally"})
        return {"ok": False, "error": f"image_not_local: {image}"}
    argv = [binary, "image", "--format", "json", "--scanners", "vuln",
            "--timeout", "10m", "--quiet", image]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=600)
        stdout = proc.stdout[:MAX_OUTPUT]
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        db.emit(engagement_id, "degradation", {"code": "timeout", "detail": "trivy image scan"})
        return {"ok": False, "error": "timeout", "degradation": "timeout_partial_never_complete"}
    parsed = parse_trivy_json(stdout.decode(errors="replace"))
    ev = evidence.put_json(engagement_id, {"image": image, "argv": argv[1:],
                                           "parsed": parsed}, "container_scan")
    db.execute(
        "INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
        "scope_decision, exit_code, duration_ms, artifact_id, error, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (call_id, engagement_id, intent_id, "trivy_image", json.dumps(argv[1:]), image,
         "executed: local image (no target egress)", exit_code,
         round((time.time() - started) * 1000, 1), ev["id"],
         None if exit_code == 0 else f"exit {exit_code}", time.time()))
    by_sev = {}
    for v in parsed["vulnerabilities"]:
        sev = (v.get("severity") or "UNKNOWN").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        pipeline.record_observation(
            engagement_id, intent_id, "potentially_affected",
            f"{v['id']} {v['pkg']} {v['installed']} (fixed: {v.get('fixed') or 'none'}) "
            f"severity={sev} - version match, exposure unconfirmed",
            ev["id"])
    db.emit(engagement_id, "container_scan_complete",
            {"image": image, "total": len(parsed["vulnerabilities"]), "by_severity": by_sev})
    return {"ok": exit_code == 0, "image": image, "evidence_id": ev["id"],
            "total": len(parsed["vulnerabilities"]), "by_severity": by_sev,
            "note": "version-based matches; not confirmed findings"}
