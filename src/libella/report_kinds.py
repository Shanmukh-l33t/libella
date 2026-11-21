"""Focused report documents built from the canonical report.

One canonical report.json is the source of truth; these are views of it for a
different reader: an executive who wants the risk and the limits, a reviewer who
wants the methodology coverage, an auditor who wants the evidence ledger, and a
CI system that wants machine-readable results.

Nothing here invents a fact: every number is read from the rendered report, so a
focused document can never disagree with the technical one.
"""
import csv
import io

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _esc(value) -> str:
    return (str("" if value is None else value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _counts(report: dict) -> dict:
    counts = {s: 0 for s in SEV_ORDER}
    for f in report.get("findings", []):
        if f.get("verified"):
            sev = str(f.get("severity") or "info")
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def _verified(report: dict) -> list[dict]:
    return [f for f in report.get("findings", []) if f.get("verified")]


def _limits(report: dict) -> list[str]:
    return [f"{d.get('code')}: {d.get('detail')}" for d in report.get("degradations", [])]


def _scope_lines(report: dict) -> list[str]:
    scope = report.get("scope") or {}
    out = [f"{t.get('kind')}: {t.get('value')}" for t in scope.get("targets", [])]
    if scope.get("categories"):
        out.append("Categories: " + ", ".join(scope["categories"]))
    if scope.get("rate_limit_rps"):
        out.append(f"Declared rate: {scope['rate_limit_rps']} requests/s")
    return out


def _period(report: dict) -> str:
    eng = report.get("engagement") or {}
    import time as _t
    def fmt(v):
        return _t.strftime("%Y-%m-%d %H:%M UTC", _t.gmtime(v)) if isinstance(v, (int, float)) else "unknown"
    return f"{fmt(eng.get('started_at'))} to {fmt(eng.get('finished_at'))}"


# ---- executive ------------------------------------------------------------

def executive_md(report: dict) -> str:
    s = report.get("summary") or {}
    counts = _counts(report)
    verified = _verified(report)
    eng = report.get("engagement") or {}
    cov = (report.get("coverage") or {}).get("summary") or {}
    lines = [f"# Executive security summary: {eng.get('name', 'assessment')}", "",
             f"Engagement `{eng.get('id', '')}` | status **{eng.get('status', '')}** | "
             f"profile `{eng.get('profile', '')}` | mode `{eng.get('mode') or 'deterministic'}`",
             "", f"Assessment period: {_period(report)}", "", "## What was assessed", ""]
    lines += [f"- {line}" for line in _scope_lines(report)]
    lines += ["", f"{s.get('assets', 0)} assets were discovered and {cov.get('completed', 0)} of "
                  f"{cov.get('supported', 0)} supported methodology tests completed automatically.", "",
              "## Verified findings", ""]
    if verified:
        lines.append("| Severity | Finding | Endpoint |")
        lines.append("|---|---|---|")
        for f in verified:
            lines.append(f"| {str(f.get('severity', '')).upper()} | {f.get('title', '')} | "
                         f"`{f.get('endpoint', '')}` |")
        lines += ["", f"{len(verified)} finding(s) were independently reproduced by replaying the "
                       f"captured proof. {s.get('findings_total', 0) - len(verified)} further "
                       f"observation(s) were recorded but NOT reproduced, and are not claimed as "
                       f"vulnerabilities."]
    elif s.get("findings_total"):
        lines += [f"No verified vulnerabilities. {s.get('findings_total', 0)} observation(s) were "
                  f"recorded and none could be reproduced as a vulnerability; unverified "
                  f"observations are not claimed as issues.", "",
                  "An absence of verified findings is not a guarantee of security: read the "
                  "limitations below, which state what was not tested."]
    else:
        lines += ["No observations were recorded, verified or otherwise.", "",
                  "A clean run is not a guarantee of security: read the limitations below, "
                  "which state what was not tested and why."]
    sev = ", ".join(f"{k}: {v}" for k, v in counts.items() if v) or "none verified"
    lines += ["", f"Verified by severity: {sev}", "", "## Limitations of this assessment", ""]
    limits = _limits(report)
    lines += [f"- {line}" for line in limits] or ["- None reported."]
    if cov.get("manual_required"):
        lines.append(f"- {cov['manual_required']} methodology tests require a human tester and were "
                     f"not performed by this run.")
    lines += ["", "## Recommended next steps", ""]
    if verified:
        lines.append("1. Remediate the verified findings in severity order; the technical report "
                     "carries the exact request, evidence and remediation for each.")
        lines.append("2. Re-run this engagement after the fixes to confirm them (retest).")
    else:
        lines.append("1. Confirm the untested categories above with a manual review or a wider scope.")
        lines.append("2. Keep the recorded observations open until they are reproduced or dismissed.")
    lines += ["", "_Generated by Libella from captured evidence. Only reproduced findings are "
                  "reported as vulnerabilities._", ""]
    return "\n".join(lines)


# ---- methodology and coverage --------------------------------------------

def coverage_md(report: dict) -> str:
    eng = report.get("engagement") or {}
    cov = report.get("coverage") or {}
    s = cov.get("summary") or {}
    fw = cov.get("framework")
    if isinstance(fw, dict):
        fw_name = " ".join(x for x in (fw.get("id"), fw.get("version")) if x) or "unknown framework"
    else:
        fw_name = str(fw or "unknown framework")
    lines = [f"# Methodology and coverage: {eng.get('name', 'assessment')}", "",
             f"Framework: **{fw_name}**", "",
             "| Measure | Count |", "|---|---|"]
    for key in ("total", "applicable", "supported", "attempted", "completed", "with_findings",
                "manual_required", "skipped", "not_tested"):
        if key in s:
            lines.append(f"| {key.replace('_', ' ')} | {s[key]} |")
    lines += ["", "`supported` is the denominator the engine can automate; `manual_required` and "
                  "`not_tested` are never counted as passes.", "", "## Status by test", ""]
    statuses = s.get("statuses") or {}
    for status, n in sorted(statuses.items()):
        lines.append(f"- {status.replace('_', ' ')}: {n}")
    cats = cov.get("categories") or []
    if cats:
        lines += ["", "## By category", "", "| Category | Applicable | Completed | Findings |",
                  "|---|---|---|---|"]
        for c in cats:
            got = c.get("counts") or {}  # keyed by automatic status, not by summary measure
            done = sum(got.get(x, 0) for x in ("completed_no_issue", "partial_evidence",
                                               "finding_unverified", "finding_verified"))
            hits = got.get("finding_unverified", 0) + got.get("finding_verified", 0)
            lines.append(f"| {c.get('name') or c.get('id')} | {c.get('tests', 0)} | "
                         f"{done} | {hits} |")
    not_tested = cov.get("not_tested") or []
    if not_tested:
        lines += ["", "## Not tested", ""]
        for t in not_tested[:200]:
            if isinstance(t, dict):
                lines.append(f"- {t.get('id')}: {t.get('status')} ({t.get('reason') or ''})")
            else:
                lines.append(f"- {t}")
    for std in report.get("standards") or []:
        ss = std.get("summary") or {}
        sfw = std.get("framework") or {}
        level = f" Level {ss['level']}" if ss.get("level") else ""
        lines += ["", f"## {sfw.get('title') or sfw.get('id')} {sfw.get('version', '')}{level}", "",
                  "| Measure | Count |", "|---|---|"]
        for key in ("total", "catalog", "excluded_by_level", "applicable", "supported",
                    "attempted", "completed", "partial", "with_findings", "manual_required",
                    "skipped", "not_tested"):
            if key in ss:
                lines.append(f"| {key.replace('_', ' ')} | {ss[key]} |")
    lines += ["", "_A completed automated check is not a manual assessment. Read the limitations "
                  "with this table._", ""]
    return "\n".join(lines)


# ---- evidence appendix ----------------------------------------------------

def evidence_csv(db, engagement_id: str) -> str:
    """One row per evidence record, in chain order. Redacted: metadata only, no bodies."""
    rows = db.query("SELECT id, kind, sha256, bytes, created_at, chain_hash FROM evidence "
                    "WHERE engagement_id=? ORDER BY rowid", (engagement_id,))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["evidence_id", "kind", "sha256", "bytes", "created_at_utc", "chain_hash"])
    import time as _t
    for r in rows:
        writer.writerow([r["id"], r["kind"], r["sha256"], r["bytes"],
                         _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(r["created_at"] or 0)),
                         r["chain_hash"]])
    return buf.getvalue()


# ---- CI / GitLab ----------------------------------------------------------

def gitlab_json(report: dict) -> dict:
    """GitLab DAST report (schema 15.0.0) from verified findings only."""
    sev = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
    vulns = []
    for f in _verified(report):
        vulns.append({
            "id": f.get("id"),
            "name": f.get("title"),
            "description": f.get("description") or "",
            "severity": sev.get(f.get("severity"), "Medium"),
            "solution": f.get("remediation") or "",
            "scanner": {"id": "libella", "name": "Libella"},
            "location": {"hostname": f.get("endpoint") or "",
                         "path": f.get("endpoint") or "",
                         "method": (f.get("proof_request") or {}).get("method", "GET")},
            "identifiers": [{"type": "cwe", "name": str(f.get("cwe") or ""),
                             "value": str(f.get("cwe") or ""),
                             "url": "https://cwe.mitre.org/"}],
            "links": [], "details": {"evidence_ids": f.get("evidence_ids") or []},
        })
    return {"version": "15.0.0",
            "scan": {"scanner": {"id": "libella", "name": "Libella",
                                 "vendor": {"name": "Libella"}},
                     "type": "dast", "start_time": _period(report),
                     "status": "success", "analyzer": {"id": "libella", "name": "Libella"}},
            "vulnerabilities": vulns}


# ---- shared HTML shell ----------------------------------------------------

_HTML_CSS = """
body{font:14px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
color:#111;max-width:900px;margin:40px auto;padding:0 24px}
h1{font-size:26px;letter-spacing:-.02em;margin:0 0 6px}
h2{font-size:16px;margin:28px 0 8px;padding-bottom:6px;border-bottom:1px solid #e5e7eb}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13px}
th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f9fafb;font-weight:600}
code{background:#f3f4f6;padding:1px 4px;border-radius:3px;font-size:12px}
.muted{color:#6b7280}.limit{border-left:3px solid #f59e0b;background:#fffbeb;padding:8px 12px;margin:6px 0}
@media print{body{margin:0}h2{page-break-after:avoid}}
"""


def html_doc(title: str, body_html: str) -> str:
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>{_esc(title)}</title><style>{_HTML_CSS}</style></head>"
            f"<body>{body_html}</body></html>")


def md_to_html(md: str) -> str:
    """Tiny renderer for the documents above: headings, tables, lists, paragraphs."""
    import re

    def inline(text: str) -> str:
        text = _esc(text).replace("&amp;lt;", "&lt;").replace("&amp;gt;", "&gt;")
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
        text = re.sub(r"_(.+?)_", r"<em>\1</em>", text)
        return text

    out, table = [], []
    for line in md.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= {"-", ":"} and c for c in cells):
                continue
            table.append(cells)
            continue
        if table:
            head, *rows = table
            out.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head)
                       + "</tr></thead><tbody>"
                       + "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>"
                                 for r in rows) + "</tbody></table>")
            table = []
        if not line.strip():
            out.append("")
        elif line.startswith("# "):
            out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("- "):
            out.append(f"<li>{inline(line[2:])}</li>")
        elif line[0].isdigit() and line[1:3] in (". ", ") "):
            out.append(f"<li>{inline(line[3:])}</li>")
        else:
            out.append(f"<p>{inline(line)}</p>")
    if table:
        head, *rows = table
        out.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head)
                   + "</tr></thead><tbody>"
                   + "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>"
                             for r in rows) + "</tbody></table>")
    html = "\n".join(out)
    return _wrap_lists(html)


def _wrap_lists(html: str) -> str:
    out, open_list = [], False
    for line in html.splitlines():
        if line.startswith("<li>"):
            if not open_list:
                out.append("<ul>")
                open_list = True
            out.append(line)
        else:
            if open_list:
                out.append("</ul>")
                open_list = False
            out.append(line)
    if open_list:
        out.append("</ul>")
    return "\n".join(out)
