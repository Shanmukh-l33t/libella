"""Professional report exports from the redacted report.json dict.

All functions consume the already-redacted report produced by report.render_report,
so credential/PII redaction is inherited. HTML is self-contained (no external assets,
no script). DOCX/XLSX are real Office documents; CSV carries a spreadsheet
formula-injection guard. Nothing here re-reads raw evidence or the network.
"""
import csv
import html
import io
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_STATE_LABEL = {
    "suspected": "Suspected", "observed": "Observed", "validated": "Verified",
    "reported": "Reported", "remediated": "Remediated", "retested_fixed": "Retested fixed",
    "retested_persists": "Still present", "ruled_out": "Ruled out",
}


def _findings(report: dict) -> list[dict]:
    return sorted(report.get("findings", []),
                  key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f.get("title", "")))


def _esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render_html(report: dict) -> str:
    eng = report.get("engagement", {})
    s = report.get("summary", {})
    rows = []
    for f in _findings(report):
        verdict = "Verified" if f.get("verified") else _STATE_LABEL.get(f.get("state"), f.get("state", ""))
        rows.append(
            "<tr>"
            f"<td><span class='sev sev-{_esc(f.get('severity'))}'>{_esc(f.get('severity'))}</span></td>"
            f"<td>{_esc(f.get('title'))}</td>"
            f"<td>{_esc(f.get('cwe'))}</td>"
            f"<td class='mono'>{_esc(f.get('endpoint'))}</td>"
            f"<td>{_esc(verdict)}</td>"
            "</tr>"
        )
    detail = []
    for f in _findings(report):
        detail.append(
            "<section class='finding'>"
            f"<h3>{_esc(f.get('title'))} <span class='sev sev-{_esc(f.get('severity'))}'>{_esc(f.get('severity'))}</span></h3>"
            f"<p class='meta'>{_esc(f.get('cwe'))} · {_esc(f.get('owasp'))} · {_esc(f.get('endpoint'))}</p>"
            f"<p><strong>What is wrong.</strong> {_esc(f.get('description'))}</p>"
            f"<p><strong>Impact (predicted).</strong> {_esc(f.get('impact'))}</p>"
            f"<p><strong>Remediation.</strong> {_esc(f.get('remediation'))}</p>"
            f"<p class='meta'>Verification: {'independently reproduced' if f.get('verified') else 'not independently confirmed'}.</p>"
            "</section>"
        )
    limits = "".join(
        f"<li><strong>{_esc(d.get('code'))}</strong>: {_esc(d.get('detail'))}</li>"
        for d in report.get("degradations", []))
    limits_block = (
        f"<h2>Coverage limitations</h2><p>Read before interpreting 'no findings' as secure.</p><ul>{limits}</ul>"
        if limits else "<h2>Coverage limitations</h2><p>None recorded.</p>")
    scope_items = "".join(
        f"<li>{_esc(t.get('kind'))}: <span class='mono'>{_esc(t.get('value'))}</span></li>"
        for t in report.get("scope", {}).get("targets", []))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Libella report — {_esc(eng.get('name'))}</title>
<style>
:root {{ color-scheme: light; }}
body {{ font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  margin: 0; background: #f7f8fa; color: #1a202c; }}
.wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 24px 64px; }}
h1 {{ font-size: 24px; margin: 0 0 4px; }} h2 {{ font-size: 18px; margin: 32px 0 8px; }}
h3 {{ font-size: 16px; margin: 0 0 6px; }}
.meta {{ color: #64748b; font-size: 13px; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
table {{ border-collapse: collapse; width: 100%; background: #fff; border: 1px solid #e2e8f0; }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; font-size: 13px; vertical-align: top; }}
th {{ background: #f1f5f9; }}
.sev {{ display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: capitalize; }}
.sev-critical {{ background: #7f1d1d; color: #fff; }} .sev-high {{ background: #fee2e2; color: #b91c1c; }}
.sev-medium {{ background: #fef3c7; color: #b45309; }} .sev-low {{ background: #e0f2fe; color: #0369a1; }}
.sev-info {{ background: #f1f5f9; color: #475569; }}
.finding {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; }}
.cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }}
.card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 16px; min-width: 120px; }}
.card b {{ display: block; font-size: 22px; }}
.note {{ background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px; padding: 12px 16px; font-size: 13px; }}
</style></head><body><div class="wrap">
<h1>Penetration Test Report</h1>
<p class="meta">{_esc(eng.get('name'))} · engagement {_esc(eng.get('id'))} · profile {_esc(eng.get('profile'))}
 · status {_esc(eng.get('status'))}</p>
<p class="note">Deterministic rendering from captured evidence. A verified finding means an independent
replay reproduced the recorded proof; it is not, by itself, a claim of demonstrated business impact.
This automated report is not a substitute for a full manual penetration test.</p>
<div class="cards">
<div class="card"><b>{s.get('findings_total', 0)}</b>findings</div>
<div class="card"><b>{s.get('confirmed', 0)}</b>verified</div>
<div class="card"><b>{s.get('assets', 0)}</b>assets</div>
<div class="card"><b>{s.get('scope_refusals', 0)}</b>scope refusals</div>
</div>
<h2>Summary of findings</h2>
<table><thead><tr><th>Severity</th><th>Title</th><th>CWE</th><th>Endpoint</th><th>Verification</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="5">No findings recorded.</td></tr>'}</tbody></table>
{limits_block}
<h2>Scope</h2><ul>{scope_items}</ul>
<h2>Finding detail</h2>{''.join(detail) if detail else '<p>No findings recorded.</p>'}
<p class="meta">Generated by Libella.</p>
</div></body></html>"""


def render_docx(report: dict, out_path) -> Path:
    from docx import Document
    from docx.shared import Pt

    out = Path(out_path)
    eng = report.get("engagement", {})
    s = report.get("summary", {})
    doc = Document()
    doc.add_heading("Penetration Test Report", 0)
    doc.add_paragraph(f"{eng.get('name', '')} · engagement {eng.get('id', '')} · "
                      f"profile {eng.get('profile', '')} · status {eng.get('status', '')}")
    doc.add_paragraph("Deterministic rendering from captured evidence. Verified means an independent "
                      "replay reproduced the recorded proof; it is not a claim of demonstrated business "
                      "impact. This automated report is not a full manual penetration test.")
    doc.add_heading("Summary", 1)
    doc.add_paragraph(f"Findings: {s.get('findings_total', 0)} total, {s.get('confirmed', 0)} verified. "
                      f"Assets: {s.get('assets', 0)}. Scope refusals: {s.get('scope_refusals', 0)}.")
    if report.get("degradations"):
        doc.add_heading("Coverage limitations", 1)
        for d in report["degradations"]:
            doc.add_paragraph(f"{d.get('code')}: {d.get('detail')}", style="List Bullet")
    doc.add_heading("Findings", 1)
    if not report.get("findings"):
        doc.add_paragraph("No findings recorded. Review coverage limitations before interpreting this as secure.")
    for f in _findings(report):
        doc.add_heading(f"[{f.get('severity', '')}] {f.get('title', '')}", 2)
        p = doc.add_paragraph()
        p.add_run(f"{f.get('cwe', '')} · {f.get('owasp', '')} · {f.get('endpoint', '')}").italic = True
        doc.add_paragraph(f"What is wrong: {f.get('description', '')}")
        doc.add_paragraph(f"Impact (predicted): {f.get('impact', '')}")
        doc.add_paragraph(f"Remediation: {f.get('remediation', '')}")
        doc.add_paragraph("Verification: " + ("independently reproduced" if f.get("verified")
                                              else "not independently confirmed"))
    for para in doc.paragraphs:
        for run in para.runs:
            if run.font.size is None:
                run.font.size = Pt(10.5)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return out


def _safe_cell(value) -> str:
    text = "" if value is None else str(value)
    # Spreadsheet formula-injection guard: neutralize a leading =, +, -, @.
    if text[:1] in ("=", "+", "-", "@"):
        return "\t" + text
    return text


def render_xlsx(report: dict, out_path) -> Path:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    out = Path(out_path)
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    eng = report.get("engagement", {})
    s = report.get("summary", {})
    summary.append(["Field", "Value"])
    for k, v in [("Engagement", eng.get("id")), ("Name", eng.get("name")),
                 ("Profile", eng.get("profile")), ("Status", eng.get("status")),
                 ("Findings", s.get("findings_total")), ("Verified", s.get("confirmed")),
                 ("Assets", s.get("assets")), ("Scope refusals", s.get("scope_refusals"))]:
        summary.append([k, _safe_cell(v)])
    for cell in summary[1]:
        cell.font = Font(bold=True)
    findings = wb.create_sheet("Findings")
    findings.append(["Severity", "Title", "CWE", "OWASP", "Endpoint", "State", "Verified",
                     "Description", "Impact", "Remediation"])
    for cell in findings[1]:
        cell.font = Font(bold=True)
    for f in _findings(report):
        findings.append([_safe_cell(f.get("severity")), _safe_cell(f.get("title")),
                         _safe_cell(f.get("cwe")), _safe_cell(f.get("owasp")),
                         _safe_cell(f.get("endpoint")),
                         _safe_cell(_STATE_LABEL.get(f.get("state"), f.get("state"))),
                         "yes" if f.get("verified") else "no",
                         _safe_cell(f.get("description")), _safe_cell(f.get("impact")),
                         _safe_cell(f.get("remediation"))])
    limits = wb.create_sheet("Limitations")
    limits.append(["Code", "Detail"])
    for cell in limits[1]:
        cell.font = Font(bold=True)
    for d in report.get("degradations", []):
        limits.append([_safe_cell(d.get("code")), _safe_cell(d.get("detail"))])
    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(str(out))
    return out


def render_csv(report: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Severity", "Title", "CWE", "OWASP", "Endpoint", "State", "Verified",
                     "Description", "Impact", "Remediation"])
    for f in _findings(report):
        writer.writerow([_safe_cell(f.get("severity")), _safe_cell(f.get("title")),
                         _safe_cell(f.get("cwe")), _safe_cell(f.get("owasp")),
                         _safe_cell(f.get("endpoint")),
                         _safe_cell(_STATE_LABEL.get(f.get("state"), f.get("state"))),
                         "yes" if f.get("verified") else "no",
                         _safe_cell(f.get("description")), _safe_cell(f.get("impact")),
                         _safe_cell(f.get("remediation"))])
    return buf.getvalue()
