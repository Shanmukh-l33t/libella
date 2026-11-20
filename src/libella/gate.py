"""Offline release gate over redacted Libella report JSON.

Compares a current report with an optional baseline and fails closed: a new
verified high/critical finding, or coverage that is missing/failed/unknown,
never passes. Malformed input is an error (exit 2), not a finding.
No scanner is invoked; this only reads files Libella already produced.
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
    return {"status": status, "summary": counts, "findings": findings,
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


def _coverage_item(name, status, detail=""):
    return {"name": name, "status": status, "detail": detail}


def _coverage(report, baseline):
    s, cov = report["summary"], []
    if report["status"] == "done":
        cov.append(_coverage_item("engagement-status", "ok"))
    elif report["status"] in FAILED_ENGAGEMENT_STATES:
        cov.append(_coverage_item("engagement-status", "failed",
                                  f"assessment ended with status {report['status']!r}"))
    else:
        cov.append(_coverage_item("engagement-status", "unknown",
                                  f"assessment status {report['status']!r} is not complete"))

    if s["intents"] == 0:
        cov.append(_coverage_item("intents", "missing", "no tracked intents in report"))
    elif s["intents_blocked"] > 0:
        cov.append(_coverage_item("intents", "failed",
                                  f"{s['intents_blocked']} of {s['intents']} intents blocked"))
    elif s["intents_done"] != s["intents"]:
        cov.append(_coverage_item("intents", "unknown",
                                  f"{s['intents_done']} of {s['intents']} intents complete"))
    else:
        cov.append(_coverage_item("intents", "ok"))

    if report["degradations"]:
        cov.append(_coverage_item("degradations", "unknown",
                                  "recorded limitations: " + ", ".join(report["degradations"])))
    else:
        cov.append(_coverage_item("degradations", "ok"))

    actual_confirmed = sum(1 for f in report["findings"] if f["verified"])
    if s["findings_total"] != len(report["findings"]):
        cov.append(_coverage_item("findings-totals", "unknown",
                                  f"declares {s['findings_total']} findings, lists "
                                  f"{len(report['findings'])}"))
    elif s["confirmed"] != actual_confirmed:
        cov.append(_coverage_item("findings-totals", "unknown",
                                  f"declares {s['confirmed']} confirmed, found {actual_confirmed}"))
    else:
        cov.append(_coverage_item("findings-totals", "ok"))

    if baseline is not None:
        current_keys = {f["key"] for f in report["findings"]}
        gone = [f for f in baseline["findings"] if f["key"] not in current_keys]
        if gone:
            names = ", ".join(f["title"] for f in gone[:5])
            more = f" (+{len(gone) - 5} more)" if len(gone) > 5 else ""
            cov.append(_coverage_item(
                "baseline-findings", "missing",
                f"{len(gone)} tracked findings absent from current report: {names}{more}"))
        else:
            cov.append(_coverage_item("baseline-findings", "ok"))
    return cov


def evaluate(baseline, report):
    """Return every gate violation and every coverage check, pass only if none fail."""
    known_risk = ({f["key"] for f in baseline["findings"]
                   if f["verified"] and f["severity"] in RISK}
                  if baseline else set())
    violations = [f for f in report["findings"]
                  if f["verified"] and f["severity"] in RISK and f["key"] not in known_risk]
    coverage = _coverage(report, baseline)
    return {"violations": violations, "coverage": coverage,
            "passed": not violations and all(c["status"] == "ok" for c in coverage)}


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
            if c["status"] != "ok":
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
    for c in result["coverage"]:
        if c["status"] != "ok":
            print(f"  coverage {c['status']}: {c['name']}: {c['detail']}")
    for f in result["violations"]:
        print(f"  new verified {f['severity']}: {f['title']} ({f['endpoint'] or 'unknown endpoint'})")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="libella-gate",
        description="Fail CI on new verified high/critical findings or incomplete coverage.")
    p.add_argument("--current", required=True, help="report.json from the assessment to gate")
    p.add_argument("--baseline", help="earlier report.json to compare against")
    p.add_argument("--junit", help="write JUnit XML results here")
    a = p.parse_args(argv)

    try:
        baseline = load_report(a.baseline) if a.baseline else None
        result = evaluate(baseline, load_report(a.current))
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
