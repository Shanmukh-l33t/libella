"""Offline release gate over redacted Libella report JSON.

Compares a current report with an optional baseline and fails closed: a new
verified high/critical finding, or coverage that is missing/failed/unknown,
never passes. Malformed input is an error (exit 2), not a finding.
No scanner is invoked; this only reads files Libella already produced.

Requirements are evaluated against a policy the gate resolves itself
(`--policy`, default auto from the declared profile). A read-only profile
(passive / production_safe) may pass on its own requirements while policy
skips are reported as limitations; the gate never reports that as active
coverage.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

CONFIRMED_STATES = {"validated", "reported", "retested_persists"}
STATES = {"suspected", "observed", "validated", "reported", "remediated",
          "retested_fixed", "retested_persists", "ruled_out"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
RISK = {"critical", "high"}
FAILED_ENGAGEMENT_STATES = {"failed", "cancelled", "budget_exhausted"}
# Profiles whose declared ceiling is read-only; policy skips are expected there.
READ_ONLY_PROFILES = {"passive", "production_safe"}
ACTIVE_PROFILES = {"safe_active", "controlled_validation", "advanced_validation"}
POLICIES = ("auto", "passive", "active", "strict")
POLICY_RESTRICTION = "policy_restriction"
# A requirement is satisfied unless it is a failure/missing/unknown state;
# "limitation" is a recorded, expected reduction of scope, never a pass claim.
SATISFIED = {"ok", "limitation"}
_WS = re.compile(r"\s+")
_XML_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")
_MAX_XML_TEXT = 2000


class GateInputError(ValueError):
    """The report is unreadable or does not match the report schema."""


def _need(obj, key, kind, where):
    val = obj.get(key) if isinstance(obj, dict) else None
    ok = isinstance(val, kind) and not (kind is int and isinstance(val, bool))
    if not ok:
        raise GateInputError(f"{where}.{key}: expected {kind.__name__}")
    return val


def _nullable_str(obj, key, where):
    if not isinstance(obj, dict) or key not in obj:
        raise GateInputError(f"{where}.{key}: missing")
    val = obj[key]
    if val is not None and not isinstance(val, str):
        raise GateInputError(f"{where}.{key}: expected string or null")
    return val


def _norm(value):
    return _WS.sub(" ", (value or "").strip().lower())


def normalize(doc, source="report"):
    """Validate a report document and return only the fields the gate acts on."""
    if not isinstance(doc, dict):
        raise GateInputError(f"{source}: top level must be an object")
    eng = _need(doc, "engagement", dict, source)
    summary = _need(doc, "summary", dict, source)
    raw_findings = _need(doc, "findings", list, source)
    degradations = _need(doc, "degradations", list, source)

    status = _need(eng, "status", str, f"{source}.engagement")
    profile = eng.get("profile")
    if profile is not None and not isinstance(profile, str):
        raise GateInputError(f"{source}.engagement.profile: expected string or null")
    counts = {k: _need(summary, k, int, f"{source}.summary")
              for k in ("intents", "intents_done", "intents_blocked", "findings_total", "confirmed")}

    findings = []
    for i, raw in enumerate(raw_findings):
        where = f"{source}.findings[{i}]"
        title = _need(raw, "title", str, where)
        endpoint = _nullable_str(raw, "endpoint", where)
        cwe = _nullable_str(raw, "cwe", where)
        severity = _need(raw, "severity", str, where)
        state = _need(raw, "state", str, where)
        if severity not in SEVERITIES:
            raise GateInputError(f"{where}.severity: unknown value {severity!r}")
        if state not in STATES:
            raise GateInputError(f"{where}.state: unknown value {state!r}")
        findings.append({
            "key": (_norm(title), _norm(endpoint), _norm(cwe)),
            "title": title, "endpoint": endpoint, "severity": severity, "state": state,
            "verified": state in CONFIRMED_STATES,
        })
    for i, d in enumerate(degradations):
        if not isinstance(d, dict):
            raise GateInputError(f"{source}.degradations[{i}]: expected an object")
    return {"status": status, "profile": profile, "summary": counts, "findings": findings,
            "degradations": [str(d.get("code") or "unspecified") for d in degradations]}


def load_report(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise GateInputError(f"cannot read {path}: {e}") from None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise GateInputError(f"{path}: invalid JSON: {e}") from None
    return normalize(doc, str(path))


def _coverage_item(name, category, status, detail=""):
    return {"name": name, "category": category, "status": status, "detail": detail}


def resolve_policy(profile, policy="auto"):
    """Resolve the requirement set. Only the declared profile may pick it; an
    unrecognised profile falls back to strict rather than assuming read-only."""
    if policy not in POLICIES:
        raise GateInputError(f"--policy: unknown value {policy!r}")
    if policy != "auto":
        return policy
    name = (profile or "").strip().lower()
    if name in READ_ONLY_PROFILES:
        return "passive"
    if name in ACTIVE_PROFILES:
        return "active"
    return "strict"


def _code_list(codes):
    counts = {}
    for c in codes:
        counts[c] = counts.get(c, 0) + 1
    return ", ".join(f"{c} x{n}" if n > 1 else c for c, n in counts.items())


def _degradation_items(report, policy):
    """Split recorded degradations into expected limitations and real failures.

    `policy_restriction` means the profile boundary skipped work: expected for a
    read-only profile, unexpected (incomplete coverage) anywhere else.
    """
    codes = report["degradations"]
    skipped = [c for c in codes if c == POLICY_RESTRICTION]
    other = [c for c in codes if c != POLICY_RESTRICTION]
    items = []
    if policy == "passive":
        items.append(_coverage_item(
            "policy-limitations", "limitations", "limitation" if skipped else "ok",
            f"{len(skipped)} check(s) skipped by the read-only profile (expected): "
            f"{_code_list(skipped)}" if skipped else "no policy skips recorded"))
        items.append(_coverage_item(
            "degradations", "policy", "failed" if other else "ok",
            "non-policy limitations recorded: " + _code_list(other) if other else ""))
    elif policy == "active":
        detail = "recorded limitations: " + _code_list(codes) if codes else ""
        if skipped:
            detail += ("; " if detail else "") + (
                "policy_restriction is unexpected for an active profile: it means "
                "work this profile permits was refused")
        items.append(_coverage_item("degradations", "policy",
                                    "failed" if codes else "ok", detail))
    else:  # strict: every recorded limitation is a failure, as before
        items.append(_coverage_item(
            "degradations", "policy", "unknown" if codes else "ok",
            "recorded limitations: " + _code_list(codes) if codes else ""))
    return items


def _coverage(report, baseline, policy):
    s, cov = report["summary"], []
    profile = report["profile"]
    declared = f"declared profile {profile!r}" if profile else "no profile declared"
    if policy == "passive":
        covers = "read-only (passive) requirements"
    elif policy == "active":
        covers = "active requirements"
    else:
        covers = "strict requirements (every limitation fails)"
    cov.append(_coverage_item("profile", "policy", "ok",
                              f"{declared} -> {policy} policy: {covers}"))

    if report["status"] == "done":
        cov.append(_coverage_item("engagement-status", "execution", "ok"))
    elif report["status"] in FAILED_ENGAGEMENT_STATES:
        cov.append(_coverage_item("engagement-status", "execution", "failed",
                                  f"assessment ended with status {report['status']!r}"))
    else:
        cov.append(_coverage_item("engagement-status", "execution", "unknown",
                                  f"assessment status {report['status']!r} is not complete"))

    if s["intents"] == 0:
        cov.append(_coverage_item("intents", "coverage", "missing",
                                  "no tracked intents in report"))
    elif s["intents_blocked"] > 0:
        cov.append(_coverage_item("intents", "coverage", "failed",
                                  f"{s['intents_blocked']} of {s['intents']} intents blocked"))
    elif s["intents_done"] != s["intents"]:
        cov.append(_coverage_item("intents", "coverage", "unknown",
                                  f"{s['intents_done']} of {s['intents']} intents complete"))
    else:
        cov.append(_coverage_item("intents", "coverage", "ok"))

    cov.extend(_degradation_items(report, policy))
    if policy == "passive":
        cov.append(_coverage_item(
            "active-validation", "limitations", "limitation",
            f"{declared}: active validation was NOT performed; a PASS is a "
            f"read-only assessment, not an active penetration test"))

    actual_confirmed = sum(1 for f in report["findings"] if f["verified"])
    if s["findings_total"] != len(report["findings"]):
        cov.append(_coverage_item("findings-totals", "incomplete", "unknown",
                                  f"declares {s['findings_total']} findings, lists "
                                  f"{len(report['findings'])}"))
    elif s["confirmed"] != actual_confirmed:
        cov.append(_coverage_item("findings-totals", "incomplete", "unknown",
                                  f"declares {s['confirmed']} confirmed, found {actual_confirmed}"))
    else:
        cov.append(_coverage_item("findings-totals", "incomplete", "ok"))

    if baseline is not None:
        current_keys = {f["key"] for f in report["findings"]}
        gone = [f for f in baseline["findings"] if f["key"] not in current_keys]
        if gone:
            names = ", ".join(f["title"] for f in gone[:5])
            more = f" (+{len(gone) - 5} more)" if len(gone) > 5 else ""
            cov.append(_coverage_item(
                "baseline-findings", "regression", "missing",
                f"{len(gone)} tracked findings absent from current report: {names}{more}"))
        else:
            cov.append(_coverage_item("baseline-findings", "regression", "ok"))
    return cov


def evaluate(baseline, report, policy="auto"):
    """Return every gate violation and every requirement, pass only if none fail.

    The policy is resolved inside the gate (never read from a report field), so a
    report cannot widen its own requirements.
    """
    resolved = resolve_policy(report["profile"], policy)
    known_risk = ({f["key"] for f in baseline["findings"]
                   if f["verified"] and f["severity"] in RISK}
                  if baseline else set())
    violations = [f for f in report["findings"]
                  if f["verified"] and f["severity"] in RISK and f["key"] not in known_risk]
    coverage = _coverage(report, baseline, resolved)
    return {"violations": violations, "coverage": coverage, "profile": report["profile"],
            "policy": resolved,
            "passed": not violations and all(c["status"] in SATISFIED for c in coverage)}


def _xml_text(value):
    return _XML_BAD.sub("\ufffd", str(value))[:_MAX_XML_TEXT]


def write_junit(path, result=None, error=None):
    """Minimal JUnit XML that a stock parser accepts; untrusted text is sanitized."""
    suite = ET.Element("testsuite", name="libella-gate")
    cases = []
    if error is not None:
        case = ET.SubElement(suite, "testcase", classname="libella.gate", name="input")
        node = ET.SubElement(case, "error", message=_xml_text(f"input error: {error}"))
        node.text = _xml_text(error)
        cases.append(case)
        failures, errors = 0, 1
    else:
        for c in result["coverage"]:
            case = ET.SubElement(suite, "testcase", classname="libella.gate.coverage",
                                 name=_xml_text(f"{c['name']}-{c['status']}"))
            if c["status"] == "limitation":
                # limitation = expected, recorded reduction of scope; visible but not a failure
                ET.SubElement(case, "skipped",
                              message=_xml_text(f"limitation: {c['detail']}"))
            elif c["status"] not in SATISFIED:
                node = ET.SubElement(case, "failure",
                                     message=_xml_text(f"coverage {c['status']}: {c['detail']}"))
                node.text = _xml_text(c["detail"])
            cases.append(case)
        for f in result["violations"]:
            case = ET.SubElement(suite, "testcase", classname="libella.gate.finding",
                                 name=_xml_text(f["title"]))
            node = ET.SubElement(case, "failure",
                                 message=_xml_text(f"new verified {f['severity']}: {f['title']}"))
            node.text = _xml_text(f"{f['severity']} at {f['endpoint'] or 'unknown endpoint'}")
            cases.append(case)
        failures = sum(1 for c in cases if c.find("failure") is not None)
        errors = 0
    suite.set("tests", str(len(cases)))
    suite.set("failures", str(failures))
    suite.set("errors", str(errors))
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(target, encoding="utf-8", xml_declaration=True)


def _print(result):
    print("libella-gate: PASS" if result["passed"] else "libella-gate: FAIL")
    print(f"  policy: {result['policy']} (declared profile {result['profile']!r})")
    ok = sum(1 for c in result["coverage"] if c["status"] in SATISFIED)
    lim = sum(1 for c in result["coverage"] if c["status"] == "limitation")
    print(f"  requirements: {ok} satisfied ({lim} as recorded limitations), "
          f"{len(result['coverage']) - ok} not satisfied")
    for c in result["coverage"]:
        marker = "ok" if c["status"] == "ok" else c["status"]
        print(f"  [{marker}] {c['category']}/{c['name']}"
              + (f": {c['detail']}" if c["detail"] else ""))
    for f in result["violations"]:
        print(f"  [vulnerability] new verified {f['severity']}: {f['title']} "
              f"({f['endpoint'] or 'unknown endpoint'})")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="libella-gate",
        description="Fail CI on new verified high/critical findings or incomplete coverage.")
    p.add_argument("--current", required=True, help="report.json from the assessment to gate")
    p.add_argument("--baseline", help="earlier report.json to compare against")
    p.add_argument("--junit", help="write JUnit XML results here")
    p.add_argument("--policy", choices=POLICIES, default="auto",
                   help="requirement set: auto (from the report profile), passive, active, "
                        "or strict (fail on any recorded limitation, including expected "
                        "policy skips). Only narrows: --policy active/strict always applies.")
    a = p.parse_args(argv)

    try:
        baseline = load_report(a.baseline) if a.baseline else None
        result = evaluate(baseline, load_report(a.current), a.policy)
    except GateInputError as e:
        print(f"libella-gate: input error: {e}", file=sys.stderr)
        if a.junit:
            try:
                write_junit(a.junit, error=str(e))
            except OSError as we:
                print(f"libella-gate: cannot write {a.junit}: {we}", file=sys.stderr)
        return 2

    _print(result)
    if a.junit:
        try:
            write_junit(a.junit, result=result)
        except OSError as e:
            print(f"libella-gate: cannot write {a.junit}: {e}", file=sys.stderr)
            return 2
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
