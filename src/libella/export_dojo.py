"""DefectDojo "Generic Findings Import" JSON export of the normalized report.

The upstream parser (`dojo/tools/generic/json_parser.py`, DefectDojo 3.5.202) is strict:
missing title/severity/description raises, and any field outside its whitelist aborts the
whole import. So this module emits only whitelisted keys, from the already-redacted
report dict — never from the database.

Identities are stable: `unique_id_from_tool` is `libella:<engagement>:<finding id>`, and
`date` comes from the engagement start, so re-exporting an unchanged engagement yields
byte-identical JSON. `verified` mirrors the last independent replay verdict only.
"""
from datetime import UTC, datetime
from urllib.parse import urlparse

SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
VERIFIED_VERDICT = "reproduced"
# DefectDojo: active = still present, false_p = assessed and not a defect, is_mitigated = fixed.
NOT_A_DEFECT = {"ruled_out"}
FIXED = {"retested_fixed"}


def _cwe(value) -> int | None:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return int(digits) if digits else None


def _endpoints(value) -> list[str]:
    # The parser prepends "//" to schemeless strings and Endpoint.from_uri then rejects
    # host-less values, aborting the whole import; such an endpoint stays in the description.
    v = str(value or "").strip()
    if "://" not in v or " " in v:
        return []
    try:
        host = urlparse(v).hostname
    except ValueError:
        return []
    return [v] if host else []


def _verification(finding: dict) -> tuple[bool, str]:
    vs = finding.get("verifications") or []
    if not vs:
        return False, "none recorded — not independently confirmed"
    last = vs[-1]
    verdict = str(last.get("verdict") or "unknown")
    return verdict == VERIFIED_VERDICT, f"{verdict} — {last.get('detail') or 'no detail'}"


def _description(finding: dict) -> str:
    verified, verification = _verification(finding)
    parts = [
        f"**Libella state:** {finding.get('state')} | **confidence:** {finding.get('confidence')} | "
        f"**verification:** {'verified' if verified else 'not verified'}",
        f"**Endpoint:** {finding.get('endpoint') or 'n/a'}",
        str(finding.get("description") or "(no description captured)"),
    ]
    for label, key in (("Impact", "impact"), ("Remediation", "remediation")):
        if finding.get(key):
            parts.append(f"**{label}:** {finding[key]}")
    parts.append(f"**Independent verification:** {verification}")
    if finding.get("evidence_ids"):
        parts.append(f"**Evidence:** {', '.join(finding['evidence_ids'])}")
    return "\n\n".join(parts)


def _finding(engagement_id: str, finding: dict) -> dict:
    state = str(finding.get("state") or "")
    verified, _ = _verification(finding)
    item = {
        "title": str(finding.get("title") or finding.get("id") or "Untitled finding"),
        "severity": SEVERITY.get(str(finding.get("severity") or "").lower(), "Info"),
        "description": _description(finding),
        "unique_id_from_tool": f"libella:{engagement_id}:{finding.get('id')}",
        "active": state not in NOT_A_DEFECT | FIXED,
        "verified": verified,
        "dynamic_finding": True,
    }
    if state in NOT_A_DEFECT:
        item["false_p"] = True
    if state in FIXED:
        item["is_mitigated"] = True
    if cwe := _cwe(finding.get("cwe")):
        item["cwe"] = cwe
    if endpoints := _endpoints(finding.get("endpoint")):
        item["endpoints"] = endpoints
    return item


def defectdojo_export(report: dict) -> dict:
    """Generic Findings JSON for one rendered report; keys limited to the parser whitelist."""
    eng = report.get("engagement") or {}
    eid = str(eng.get("id") or "")
    summary = report.get("summary") or {}
    limits = [f"{d.get('code')}: {d.get('detail')}" for d in report.get("degradations") or []]
    description = (f"Libella engagement {eng.get('name') or eid} (status: {eng.get('status')}); "
                   f"{summary.get('findings_total', 0)} findings, {summary.get('confirmed', 0)} "
                   f"independently validated.")
    if limits:
        description += "\n\nCoverage limitations — read before trusting an empty result:\n" + \
                       "\n".join(f"- {line}" for line in limits)
    if eng.get("status") != "done":
        description += "\n\nAssessment did not complete; results may be incomplete."
    out = {
        "name": f"Libella: {eng.get('name') or eid}",
        "type": "Libella",
        "description": description,
        "findings": [_finding(eid, f) for f in report.get("findings") or []],
    }
    if started := (eng.get("started_at") or eng.get("finished_at")):
        out["findings"] = [{**f, "date": datetime.fromtimestamp(started, UTC).strftime("%Y-%m-%d")}
                           for f in out["findings"]]
    return out
