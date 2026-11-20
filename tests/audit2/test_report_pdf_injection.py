"""Audit-2: target-controlled text must not become PDF markup or an unredacted leak.

`Paragraph` interprets a mini-HTML dialect. `_p` escapes before substituting
newlines, so a finding title/description carrying `</font>` or `<img onerror>`
must arrive as literal characters; and a JWT quoted from the target must arrive
as the redaction placeholder.
"""
import json

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.report import render_report
from libella.report_pdf import render_pdf

TITLE = "<b>bold</b></font><img src='http://127.0.0.1:1/x' onerror='x'>"
JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9."
       "c2lnbmF0dXJlX2Zvcl9hdWRpdDJfdGVzdF9vbmx5")
BODY = f"quote: </para><link href='http://127.0.0.1:1/'/> {JWT}"


def _build(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
               "VALUES('eng','markup','safe_active','done','{}',0)")
    db.execute(
        "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
        "description, evidence_ids_json, dedup_key, created_at, updated_at) "
        "VALUES('f1','eng',?,'CWE-79','high','high','observed',?, '[]','k',0,0)",
        (TITLE, BODY))
    render_report(db, ev, "eng", tmp_path / "out")
    return json.loads((tmp_path / "out" / "report.json").read_text())


def test_pdf_keeps_markup_literal_and_redacts_token(tmp_path):
    report = _build(tmp_path)
    pdf = render_pdf(report, tmp_path / "out" / "report.pdf")

    from pypdf import PdfReader
    text = "\n".join(p.extract_text() or "" for p in PdfReader(str(pdf)).pages)
    assert JWT not in text, "a captured JWT was rendered into the PDF"
    assert "[REDACTED-JWT]" in text
    # markup is displayed, not interpreted: the tags survive as characters
    assert "<b>bold</b>" in text and "onerror" in text
