"""PDF export of the canonical report.json (reportlab platypus).

Rendering is presentation-only: every string is redacted through report.redact()
before it reaches the page, and platypus paginates long content automatically.
"""
import time
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)

from .report import redact

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": colors.HexColor("#7f1d1d"), "high": colors.HexColor("#b91c1c"),
             "medium": colors.HexColor("#b45309"), "low": colors.HexColor("#0369a1"),
             "info": colors.HexColor("#475569")}
INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
RULE = colors.HexColor("#cbd5e1")


def _text(value) -> str:
    """Redact then XML-escape: report content is untrusted."""
    return escape(redact("" if value is None else str(value)))


def _p(value, style) -> Paragraph:
    return Paragraph(_text(value).replace("\n", "<br/>"), style)


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=ss["Title"], fontSize=30, leading=36, textColor=INK,
                                spaceAfter=6),
        "subtitle": ParagraphStyle("st", parent=ss["Normal"], fontSize=13, leading=18,
                                   textColor=MUTED, alignment=TA_CENTER, spaceAfter=4),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontSize=17, leading=22,
                             textColor=INK, spaceBefore=10, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12.5, leading=16,
                             textColor=INK, spaceBefore=10, spaceAfter=4, keepWithNext=1),
        "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5, leading=13.5, textColor=INK),
        "small": ParagraphStyle("s", parent=ss["Normal"], fontSize=8, leading=11, textColor=MUTED),
        "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=8.5, leading=11, textColor=INK),
        "cellhead": ParagraphStyle("ch", parent=ss["Normal"], fontSize=8.5, leading=11,
                                   textColor=colors.white),
    }


def _kv_table(rows, st, widths=(34 * mm, 132 * mm)):
    data = [[_p(k, ParagraphStyle("k", parent=st["cell"], textColor=MUTED)), _p(v, st["cell"])]
            for k, v in rows if v not in (None, "", [])]
    if not data:
        return Spacer(1, 1)
    t = Table(data, colWidths=list(widths))
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                           ("TOPPADDING", (0, 0), (-1, -1), 1),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE)]))
    return t


def _severity_counts(findings):
    return {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}


def _risk_table(findings, st):
    counts = _severity_counts(findings)
    data = [[_p("Severity", st["cellhead"]), _p("Findings", st["cellhead"]),
             _p("Share", st["cellhead"])]]
    total = len(findings) or 1
    for sev in SEVERITIES:
        n = counts[sev]
        data.append([_p(sev.upper(), ParagraphStyle("sv", parent=st["cell"],
                                                    textColor=SEV_COLOR[sev])),
                     _p(n, st["cell"]), _p(f"{100 * n / total:.0f}%", st["cell"])])
    data.append([_p("<b>Total</b>", st["cell"]), _p(f"<b>{len(findings)}</b>", st["cell"]),
                 _p("100%" if findings else "0%", st["cell"])])
    t = Table(data, colWidths=[50 * mm, 40 * mm, 40 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.25, RULE),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _finding_block(i, f, st):
    flow = []
    head = Table([[Paragraph(f"{i}", ParagraphStyle("n", parent=st["body"], fontSize=14,
                                                    textColor=colors.white)),
                   Paragraph(f"<b>{_text(f.get('title'))}</b>",
                             ParagraphStyle("ft", parent=st["body"], fontSize=11, leading=14))]],
                 colWidths=[10 * mm, 156 * mm])
    head.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), SEV_COLOR.get(f.get("severity"), MUTED)),
                              ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f1f5f9")),
                              ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("TOPPADDING", (0, 0), (-1, -1), 5),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    flow.append(head)
    flow.append(Spacer(1, 3))
    short_rows = [
        ("Severity", f"{f.get('severity')} | confidence {f.get('confidence')}"),
        ("State", f.get("state")), ("CWE", f.get("cwe")), ("OWASP", f.get("owasp")),
        ("Endpoint", f.get("endpoint")),
        ("Remediation owner", f.get("owner")), ("Fix commit", f.get("fix_commit")),
        ("Evidence", ", ".join(str(e) for e in f.get("evidence_ids") or [])),
    ]
    flow.append(_kv_table(short_rows, st))
    # long free text as paragraphs: table cells cannot split across pages
    for label, value in (("Description", f.get("description")), ("Impact", f.get("impact")),
                         ("Remediation", f.get("remediation"))):
        if value:
            flow.append(_p(label, st["h2"]))
            flow.append(_p(value, st["body"]))
    vs = f.get("verifications") or []
    if vs:
        flow.append(_p("Verification history", st["h2"]))
        data = [[_p(h, st["cellhead"]) for h in ("Attempt", "Verdict", "Detail")]]
        for v in vs:
            data.append([_p(v.get("attempt"), st["cell"]), _p(v.get("verdict"), st["cell"]),
                         _p(v.get("detail"), st["cell"])])
        t = Table(data, colWidths=[18 * mm, 30 * mm, 118 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), INK),
                               ("GRID", (0, 0), (-1, -1), 0.25, RULE),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        flow.append(t)
    rt = f.get("retests") or []
    if rt:
        flow.append(_p("Retest history", st["h2"]))
        data = [[_p(h, st["cellhead"]) for h in ("Verdict", "Detail")]] + \
               [[_p(r.get("verdict"), st["cell"]), _p(r.get("detail"), st["cell"])] for r in rt]
        t = Table(data, colWidths=[30 * mm, 136 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), INK),
                               ("GRID", (0, 0), (-1, -1), 0.25, RULE)]))
        flow.append(t)
    flow.append(Spacer(1, 10))
    return flow


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 12 * mm, "Libella — deterministic report from captured evidence")
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(RULE)
    canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
    canvas.restoreState()


def render_pdf(report_json: dict, out_path: str | Path) -> Path:
    """Write a redacted PDF for a report.json dict; returns the written path."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    st = _styles()
    eng = report_json.get("engagement") or {}
    summary = report_json.get("summary") or {}
    findings = report_json.get("findings") or []
    degradations = report_json.get("degradations") or []
    scope = report_json.get("scope") or {}
    generated = report_json.get("generated_at")

    doc = BaseDocTemplate(str(out), pagesize=A4, title=f"Libella report {eng.get('id', '')}",
                          author="Libella", leftMargin=18 * mm, rightMargin=18 * mm,
                          topMargin=18 * mm, bottomMargin=20 * mm)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=_footer)])

    flow = [
        Spacer(1, 45 * mm),
        _p("PENETRATION TEST REPORT", st["subtitle"]),
        Spacer(1, 4 * mm),
        _p(eng.get("name") or "Engagement", st["title"]),
        Spacer(1, 2 * mm),
        _p(f"Engagement {eng.get('id', '')} | profile {eng.get('profile', '')} | "
           f"status {eng.get('status', '')}", st["subtitle"]),
        Spacer(1, 8 * mm),
        _p("Generated " + time.strftime("%Y-%m-%d %H:%M UTC",
                                        time.gmtime(generated or time.time())), st["subtitle"]),
        Spacer(1, 20 * mm),
        _kv_table([("Targets", ", ".join(f"{t.get('kind')}: {t.get('value')}"
                                         for t in scope.get("targets") or [])),
                   ("Exclusions", ", ".join(f"{e.get('kind')}: {e.get('value')}"
                                            for e in scope.get("exclusions") or [])),
                   ("Findings", f"{len(findings)} recorded, "
                                f"{summary.get('confirmed', 0)} validated"),
                   ("Assets", summary.get("assets")),
                   ("Coverage limitations", len(degradations))], st),
        PageBreak(),
        _p("Executive summary", st["h1"]),
        _p(f"This assessment of {eng.get('name') or 'the target'} recorded {len(findings)} "
           f"finding(s) across {summary.get('assets', 0)} discovered asset(s). "
           f"{summary.get('confirmed', 0)} finding(s) were independently validated by replaying "
           f"the captured proof against the live target; findings that could not be reproduced are "
           f"not reported as confirmed.", st["body"]),
        Spacer(1, 4),
        _p(f"Engagement status: {eng.get('status')}. "
           + (f"Detail: {eng.get('status_detail')}. " if eng.get("status_detail") else "")
           + f"Tool calls executed: {summary.get('tool_calls', 0)} "
             f"({summary.get('scope_refusals', 0)} refused by scope policy).", st["body"]),
        Spacer(1, 6),
        _p("Risk summary", st["h1"]),
        _risk_table(findings, st),
        Spacer(1, 4),
        _p("Finding states: " + (", ".join(f"{k} {v}" for k, v in
                                           (summary.get("findings_by_state") or {}).items())
                                 or "none"), st["small"]),
        _p("Findings", st["h1"]),
    ]
    if not findings:
        flow.append(_p("No findings recorded. Read the coverage limitations section before "
                       "interpreting this as secure.", st["body"]))
    for i, f in enumerate(findings, 1):
        block = _finding_block(i, f, st)
        flow.append(KeepTogether(block[:2]))  # keep the heading with its header row
        flow.extend(block[2:])

    flow.append(PageBreak())
    flow.append(_p("Coverage limitations", st["h1"]))
    if degradations:
        flow.append(_p("A blocked or degraded check must never read as 'all clear'. The "
                       "following limitations bound the confidence of this report:", st["body"]))
        for d in degradations:
            flow.append(_p(f"{d.get('code')}: {d.get('detail')}", st["body"]))
    else:
        flow.append(_p("No degradations were recorded for this engagement.", st["body"]))
    if eng.get("status") != "done":
        flow.append(Spacer(1, 4))
        flow.append(_p(f"Assessment ended with status {eng.get('status')}. Results may be "
                       f"incomplete.", st["body"]))
    flow.append(_p("Methodology", st["h1"]))
    flow.append(_p("Reconnaissance and crawling, deterministic web checks, template scanning "
                   "where available, and independent replay verification of every candidate "
                   "finding. Every tool call is scope-checked before execution and audited; "
                   "evidence is content-addressed and hash-chained. All report text passes a "
                   "redaction pass for credentials, tokens and personal data.", st["body"]))
    doc.build(flow)
    return out
