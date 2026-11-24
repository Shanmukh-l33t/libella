"""Professional report exports: HTML, DOCX, XLSX, CSV from the redacted report."""
import json
import zipfile

import pytest
from openpyxl import load_workbook

from libella.report_formats import render_csv, render_docx, render_html, render_xlsx

SENTINEL = "SI_SECRET"


@pytest.fixture
def report(report_json_path):
    return json.loads(report_json_path.read_text())


def test_html_is_self_contained_and_redacted(report):
    html = render_html(report)
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "SQL injection" in html
    assert "<script" not in html.lower()  # no injected script from finding text
    assert SENTINEL not in html
    assert "Coverage limitations" in html


def test_docx_is_a_valid_office_document(report, tmp_path):
    out = tmp_path / "report.docx"
    render_docx(report, out)
    assert zipfile.is_zipfile(out)
    with zipfile.ZipFile(out) as z:
        body = z.read("word/document.xml").decode("utf-8")
    assert "SQL injection" in body
    assert SENTINEL not in body


def test_xlsx_has_findings_and_summary_sheets(report, tmp_path):
    out = tmp_path / "report.xlsx"
    render_xlsx(report, out)
    wb = load_workbook(out)
    assert "Findings" in wb.sheetnames and "Summary" in wb.sheetnames
    rows = list(wb["Findings"].iter_rows(values_only=True))
    assert rows[0][0] == "Severity"
    assert any("SQL injection" in (r[1] or "") for r in rows[1:])
    flat = " ".join(str(c) for row in wb["Findings"].iter_rows(values_only=True) for c in row if c)
    assert SENTINEL not in flat


def test_csv_has_header_and_one_row_per_finding(report):
    text = render_csv(report)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert lines[0].startswith("Severity,Title")
    assert len(lines) == 1 + len(report["findings"])
    assert SENTINEL not in text


@pytest.mark.parametrize("fmt,ctype", [
    ("html", "text/html"), ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"), ("csv", "text/csv"),
])
def test_report_route_serves_each_format(client, report_json_path, fmt, ctype):
    eid = "eng_a"
    resp = client.get(f"/api/engagements/{eid}/report?format={fmt}")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith(ctype)
    assert len(resp.content) > 200
    assert SENTINEL.encode() not in resp.content
