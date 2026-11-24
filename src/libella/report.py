"""Deterministic report rendering from typed state. No model-authored evidence.

Outputs: Markdown, JSON, SARIF 2.1.0. Redaction pass over secrets/PII.
Coverage and degradation sections are mandatory: a blocked scan must never
read as 'all clear'.
"""
import hashlib
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote

from . import __version__
from . import coverage, scan_record
from .db import DB
from .evidence import EvidenceStore

_CRED_LABEL = (r"(?:proxy-)?authorization|(?:set-)?cookie|x-api-key|x-auth-token|password|"
               r"passwd|pwd|secret|api[_-]?key|access[_-]?key|token")

REDACT_PATTERNS = [
    # credential headers in any scheme (Basic/Digest/Negotiate): the scheme word used to
    # absorb the match, leaving the credential itself in the report
    (re.compile(r"(?i)\b((?:proxy-)?authorization)\s*:\s*[^\n\"']+"), r"\1: [REDACTED]"),
    (re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|authorization)\s*[:=]\s*[\"']?([^\s\"',;&]{4,})"),
     r"\1=[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"), "Bearer [REDACTED]"),
    # header forms: "Cookie: ...", "Set-Cookie: ..."
    (re.compile(r"(?i)\b((?:set-)?cookie|x-api-key|x-auth-token)\s*:\s*[^\n\"']+"),
     r"\1: [REDACTED]"),
    # quoted key/value pairs (JSON bodies, dict reprs): the quotes around the key defeated
    # every labelled pattern, so whole credential-bearing request/response bodies shipped.
    # Affixes cover db_password / client_secret / access_key_id; the value quote is kept so
    # the surrounding document still parses.
    (re.compile(rf"(?i)([\"'])(?:[a-z0-9_.-]*(?:{_CRED_LABEL})[a-z0-9_.-]*)\1\s*:\s*([\"'])[^\"'\n]*\2"),
     r"\1\2[REDACTED]\2"),
    (re.compile(r"(?i)\b(session|sessionid|jsessionid|phpsessid|sid|auth[_-]?token)\s*=\s*[A-Za-z0-9%._\-]{8,}"),
     r"\1=[REDACTED]"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[REDACTED-CARD]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED-EMAIL]"),
    (re.compile(r"SI_SECRET_[A-Z_]+"), "[REDACTED-CREDENTIAL]"),
    # opaque bearer tokens carry no label: JWTs appear in bodies, bundles and quotes
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
     "[REDACTED-JWT]"),
]

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie",
                     "x-api-key", "x-auth-token"}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_SARIF = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def redact(text: str) -> str:
    for pat, repl in REDACT_PATTERNS:
        text = pat.sub(repl, text)
    return text


def redact_headers(headers: dict | None) -> dict:
    """Mask credential-bearing header values before they leave the process."""
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE_HEADERS else v)
            for k, v in (headers or {}).items()}


# Serializes the write+ledger step so two concurrent GETs of one state record once.
# shortcut: per process; two processes can still append one artifact row each.
_RENDER_LOCK = threading.Lock()


def _write_atomic(path: Path, text: str) -> None:
    """Readers must never see a half-written report: temp file, then os.replace."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _md(value) -> str:
    """Single-line, code-span-safe rendering of any untrusted value."""
    s = "" if value is None else str(value)
    return s.replace("\r", " ").replace("\n", " ").replace("`", "'")


def _safe(value):
    """Redacted, single-line form. Every report surface (md/json/sarif) uses it."""
    return None if value is None else _md(redact(str(value)))


def _csv_escape(s: str) -> str:
    if s and s[0] in "=+-@\t\r":
        return "'" + s
    return s


def captured_checks_md(cov: dict) -> list[str]:
    samples = cov.get("captured_response_checks", ())
    if not samples:
        return []
    return ["\n### Captured response checks\n",
            "Sample results are not application-wide verdicts.\n", *[
        f"- {s['requirement_id']}: {s['outcome']} ({s['evidence_id']}). {s['reason']}" for s in samples
    ], ""]


def _coverage_md(md: list, c: dict) -> None:
    """One standard's ledger: totals, per-chapter table, and what was never tested."""
    cs = c["summary"]
    fw = c["framework"]
    level = f" Level {cs['level']}" if cs.get("level") else ""
    name = str(fw["id"]).removeprefix("OWASP-")  # "WSTG 4.2", "ASVS 5.0.0 Level 2"
    md.append(f"\n## {_md(name)} {_md(fw['version'])}{level} coverage\n")
    md.extend(captured_checks_md(c))
    md.append("Derived from what this engagement executed, not from what was planned. "
              "A requirement that is not tested is not a pass, and a check that covers only "
              "part of a requirement is reported as partial evidence.\n")
    if cs.get("excluded_by_level"):
        md.append(f"- {cs['total']} of {cs['catalog']} requirements apply at the selected level "
                  f"({cs['excluded_by_level']} higher-level requirements excluded)")
    md.append(f"- Applicable: {cs['applicable']} of {cs['total']} | "
              f"supported by a Libella check: {cs['supported']} | attempted: {cs['attempted']} | "
              f"completed: {cs['completed']} (partial evidence: {cs.get('partial', 0)}) | "
              f"with findings: {cs['with_findings']}")
    md.append(f"- Skipped by profile or dependency: {cs['skipped']} | manual review required: "
              f"{cs['manual_required']} | not tested: {cs['not_tested']}\n")
    md.append("| Chapter | requirements | completed | findings | skipped | manual | untested |")
    md.append("|---|---|---|---|---|---|---|")
    for cat in c["categories"]:
        k = cat["counts"]
        done = sum(k.get(x, 0) for x in coverage.COMPLETED)
        md.append(f"| {_md(cat['id'])} {_md(cat['name'])} | {cat['tests']} | {done} | "
                  f"{k['finding_unverified'] + k['finding_verified']} | "
                  f"{k['skipped_policy'] + k['skipped_dependency']} | "
                  f"{k['requires_manual']} | {cat['tests'] - done} |")
    untested = {}
    for t in c["not_tested"]:
        untested.setdefault(t["id"].rsplit("-" if t["id"].startswith("WSTG") else ".", 1)[0],
                            []).append(t["id"])
    if untested:
        md.append("\n### Not tested\n")
        for prefix in sorted(untested):
            md.append(f"- {prefix} ({len(untested[prefix])}): {', '.join(untested[prefix])}")
    md.append("")


def render_report(db: DB, evidence: EvidenceStore, engagement_id: str,
                  outdir: str | Path | None = None) -> dict:
    eng = db.one("SELECT * FROM engagements WHERE id=?", (engagement_id,))
    findings = db.query(
        "SELECT * FROM findings WHERE engagement_id=? ORDER BY CASE severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at",
        (engagement_id,))
    assets = db.query("SELECT * FROM assets WHERE engagement_id=?", (engagement_id,))
    intents = db.query("SELECT * FROM intents WHERE engagement_id=?", (engagement_id,))
    degradations = db.query(
        "SELECT * FROM events WHERE engagement_id=? AND kind='degradation' ORDER BY seq",
        (engagement_id,))
    tool_calls = db.query("SELECT * FROM tool_calls WHERE engagement_id=?", (engagement_id,))
    agent_runs = db.query(
        "SELECT role, model, status, exit_reason, iterations, cost_usd FROM agent_runs "
        "WHERE engagement_id=? ORDER BY started_at", (engagement_id,))
    started = db.one(
        "SELECT payload_json FROM events WHERE engagement_id=? AND kind='engagement_started' "
        "ORDER BY seq DESC LIMIT 1", (engagement_id,))
    mode = json.loads(started["payload_json"]).get("mode") if started else None
    verifications = db.query("SELECT * FROM verifications WHERE finding_id IN "
                             "(SELECT id FROM findings WHERE engagement_id=?)", (engagement_id,))
    spend = db.one("SELECT COALESCE(SUM(cost_usd),0) c, COALESCE(SUM(input_tokens),0) i, "
                   "COALESCE(SUM(output_tokens),0) o FROM llm_usage WHERE engagement_id=?",
                   (engagement_id,))
    scope = json.loads(eng["scope_json"])

    by_state = {}
    for f in findings:
        by_state[f["state"]] = by_state.get(f["state"], 0) + 1
    # one source of truth for "independently validated": the same state set the
    # offline gate derives `verified` from, so a report cannot declare a count
    # its own per-finding flags contradict. retest states are earned, not bypassed
    # (findings.ALLOWED_TRANSITIONS), so this is a claim about a reproduced proof.
    CONFIRMED_STATES = {"validated", "reported", "retested_persists"}  # == gate.CONFIRMED_STATES

    def _verified(f: dict) -> bool:
        return f["state"] in CONFIRMED_STATES

    confirmed = [f for f in findings if _verified(f)]
    # a missing binary or a bad argv is "not run", not a scope refusal
    refused = [t for t in tool_calls if (t["scope_decision"] or "").startswith("refused")
               and not re.match(r"refused: (missing binary|argv build error|bad argv)", t["scope_decision"])]

    report = {
        "engagement": {"id": eng["id"], "name": _safe(eng["name"]), "status": eng["status"],
                       "profile": eng["profile"], "mode": mode,
                       "started_at": eng["started_at"],
                       "finished_at": eng["finished_at"], "status_detail": _safe(eng["status_detail"])},
        "scope": scope,
        "summary": {
            "assets": len(assets), "intents": len(intents),
            "intents_done": sum(1 for i in intents if i["status"] == "done"),
            "intents_blocked": sum(1 for i in intents if i["status"] == "blocked"),
            "findings_total": len(findings), "findings_by_state": by_state,
            "confirmed": len(confirmed),
            "tool_calls": len(tool_calls), "scope_refusals": len(refused),
            "llm_cost_usd": round(spend["c"], 4),
            "llm_tokens": spend["i"] + spend["o"],
        },
        "findings": [],
        "degradations": [{"code": _safe(json.loads(d["payload_json"]).get("code")),
                          "detail": _safe(json.loads(d["payload_json"]).get("detail"))}
                         for d in degradations],
        "agent_runs": [{"role": r["role"], "model": r["model"], "status": r["status"],
                        "exit_reason": r["exit_reason"], "iterations": r["iterations"],
                        "cost_usd": r["cost_usd"]} for r in agent_runs],
        "generated_at": time.time(),
    }
    # Methodology coverage is part of the report, not an appendix: an untested
    # category must never read as clean.
    def _ledger(cov):
        return {
            "framework": cov["framework"], "summary": cov["summary"],
            "categories": [{"id": c["id"], "name": c["name"], "tests": len(c["tests"]),
                            "counts": c["counts"]} for c in cov["categories"]],
            "captured_response_checks": [s for c in cov["categories"] for t in c["tests"]
                                         for s in t["automatic"].get("samples", ())],
            "not_tested": [{"id": t["id"], "title": t["title"], "status": t["status"]}
                           for c in cov["categories"] for t in c["tests"]
                           if t["automatic"]["status"] not in coverage.COMPLETED
                           and t["status"] != "covered"],
        }
    nuclei = scan_record.nuclei_scans(db, engagement_id, _safe)
    report["scans"] = {"nuclei": nuclei} if nuclei else {}
    report["coverage"] = _ledger(coverage.workspace(db, engagement_id, evidence=evidence))
    # every standard the engagement selected is accounted for in the report itself
    try:
        selected = json.loads(eng.get("standards_json") or "{}")
    except ValueError:
        selected = {}
    report["standards"] = [_ledger(coverage.workspace(db, engagement_id, fid, evidence))
                           for fid in selected if fid != coverage.DEFAULT]
    for f in findings:
        vs = [v for v in verifications if v["finding_id"] == f["id"]]
        report["findings"].append({
            "id": f["id"], "title": _safe(f["title"]), "cwe": _safe(f["cwe"]), "owasp": _safe(f["owasp"]),
            "severity": f["severity"], "confidence": f["confidence"], "state": f["state"],
            "endpoint": _safe(f["endpoint"]), "description": _safe(f["description"]),
            "impact": _safe(f["impact"]), "remediation": _safe(f["remediation"]),
            "evidence_ids": [_safe(e) for e in json.loads(f["evidence_ids_json"])],
            "verifications": [{"attempt": v["attempt"], "verdict": v["verdict"],
                               "detail": _safe(v["detail"])} for v in vs],
            "verified": _verified(f),
        })

    # ---- Markdown ----
    md = []
    md.append(f"# Penetration Test Report: {_md(redact(eng['name']))}\n")
    md.append(f"Engagement `{eng['id']}` | profile `{_md(eng['profile'])}` | "
              f"mode `{_md(mode)}` | status `{_md(eng['status'])}`")
    if eng["status_detail"]:
        md.append(f"Status detail: {_md(redact(eng['status_detail']))}")
    md.append("\nGenerated by Libella (deterministic rendering from captured evidence).\n")
    md.append("## Summary\n")
    s = report["summary"]
    md.append(f"- Assets discovered: {s['assets']}")
    md.append(f"- Findings: {s['findings_total']} total, {s['confirmed']} independently validated")
    md.append(f"- Finding states: {json.dumps(by_state)}")
    md.append(f"- Tool calls: {s['tool_calls']} ({s['scope_refusals']} refused by scope policy)")
    md.append(f"- Model cost: ${s['llm_cost_usd']} ({s['llm_tokens']} tokens)")
    md.append("\n## Scope\n")
    for t in scope.get("targets", []):
        md.append(f"- {_md(t['kind'])}: `{_md(t['value'])}`")
    for ex in scope.get("exclusions", []):
        md.append(f"- EXCLUDED {_md(ex['kind'])}: `{_md(ex['value'])}`")
    if report["degradations"]:
        md.append("\n## Coverage limitations (read before trusting 'no findings')\n")
        for d in report["degradations"]:
            md.append(f"- **{_md(d['code'])}**: {_md(redact(str(d['detail'])))}")
    md.extend(scan_record.scan_md(report["scans"]))
    if agent_runs:
        md.append("\n## Agent runs\n")
        for r in agent_runs:
            md.append(f"- {_md(r['role'])} ({_md(r['model'])}): {_md(r['status'])} after "
                      f"{r['iterations']} iterations, exit `{_md(r['exit_reason'])}`")
    if eng["status"] not in ("done",):
        md.append(f"\n> Assessment ended with status `{eng['status']}`. Results may be incomplete.\n")
    for c in [report["coverage"], *report["standards"]]:
        _coverage_md(md, c)
    md.append("\n## Findings\n")
    if not findings:
        md.append("No findings recorded. Check coverage limitations above before interpreting this as secure.\n")
    for i, f in enumerate(report["findings"], 1):
        md.append(f"### {i}. {f['title']}")
        md.append(f"- Severity: **{f['severity']}** | Confidence: {f['confidence']} | State: `{f['state']}`")
        md.append(f"- CWE: {f['cwe'] or 'n/a'} | OWASP: {f['owasp'] or 'n/a'}")
        md.append(f"- Endpoint: `{f['endpoint']}`")
        md.append(f"- Description: {f['description']}")
        md.append(f"- Impact: {f['impact']}")
        md.append(f"- Remediation: {f['remediation']}")
        if f["verifications"]:
            last = f["verifications"][-1]
            md.append(f"- Independent verification: **{last['verdict']}** ({last['detail']})")
        md.append(f"- Evidence: {', '.join('`'+e+'`' for e in f['evidence_ids'])}")
        md.append("")
    # Impact is a separate dimension from verification: a verified finding is a
    # reproduced signal, not proof of what it costs. Say which, explicitly.
    impact = db.query("SELECT kind, summary, quote, evidence_id FROM observations "
                      "WHERE engagement_id=? AND kind='impact_demonstrated' "
                      "ORDER BY rowid", (engagement_id,))
    report["impact"] = [{"summary": _safe(o["summary"]), "quote": _safe(o["quote"]),
                         "evidence_id": _safe(o["evidence_id"])} for o in impact]
    md.append("\n## Demonstrated impact\n")
    if report["impact"]:
        for o in report["impact"]:
            md.append(f"- {o['summary']}")
            if o["quote"]:
                md.append(f"  - observed: `{o['quote']}`")
            if o["evidence_id"]:
                md.append(f"  - evidence: `{o['evidence_id']}`")
    elif any(f["verified"] for f in report["findings"]):
        md.append("Verified findings reproduced their recorded signal; none was taken further to a "
                  "demonstrated impact in this engagement. Impact proof requires an explicitly "
                  "authorized lab, so nothing here shows what an attacker would gain.")
    else:
        md.append("Nothing was verified, so no impact could be demonstrated.")
    md.append("")

    md.append("\n## Method\n")
    md.append("Reconnaissance and crawling, deterministic web checks, template scanning (where available), "
              "independent replay verification of every candidate finding. Every tool call was scope-checked "
              "before execution and audited. Evidence is content-addressed and hash-chained.\n")
    md_text = redact("\n".join(md))

    # ---- SARIF ----
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Libella", "version": __version__,
                                "informationUri": "https://github.com/Shanmukh-l33t/libella"}},
            "results": [{
                "ruleId": f["cwe"] or "libella/finding",
                "level": SEV_SARIF.get(f["severity"], "note"),
                "message": {"text": f"{f['title']}. {f['description'] or ''}".strip()},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": quote(f["endpoint"] or "target",
                                 safe=":/?#[]@!$&'()*+,;=%")}}}],
                "properties": {"state": f["state"], "confidence": f["confidence"],
                               "verification": f["verifications"][-1]["verdict"] if f["verifications"] else "none"},
            } for f in report["findings"]],
        }],
    }

    outdir = Path(outdir) if outdir else Path(evidence.root) / engagement_id / "report"
    outdir.mkdir(parents=True, exist_ok=True)
    _write_atomic(outdir / "report.md", md_text)
    _write_atomic(outdir / "report.json", json.dumps(report, indent=2, default=str))
    _write_atomic(outdir / "report.sarif", json.dumps(sarif, indent=2))
    # One artifact row per unchanged state: a report GET is a read, not an event.
    state = hashlib.sha256(json.dumps({**report, "generated_at": None}, sort_keys=True,
                                      default=str).encode()).hexdigest()
    with _RENDER_LOCK:
        last = db.one("SELECT payload_json FROM events WHERE engagement_id=? "
                      "AND kind='report_rendered' ORDER BY seq DESC LIMIT 1", (engagement_id,))
        prev = json.loads(last["payload_json"]) if last else {}
        if prev.get("state") == state and prev.get("evidence_id"):
            return {"outdir": str(outdir), "evidence_id": prev["evidence_id"],
                    "summary": report["summary"]}
        ev = evidence.put_json(engagement_id, report, "report")
        db.emit(engagement_id, "report_rendered",
                {"evidence_id": ev["id"], "path": str(outdir), "state": state})
    return {"outdir": str(outdir), "evidence_id": ev["id"], "summary": report["summary"]}
