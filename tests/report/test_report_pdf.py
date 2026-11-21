"""PDF export: valid file, key sections, redaction, long-content pagination."""
import json

from libella.report_pdf import render_pdf

try:
    from pypdf import PdfReader
except ImportError:  # header-only fallback when pypdf is absent
    PdfReader = None


def _pdf_text(path, pages=None):
    reader = PdfReader(str(path))
    texts = [p.extract_text() or "" for p in reader.pages[:pages]]
    return reader, "\n".join(texts)


def test_pdf_is_valid_and_has_key_sections(tmp_path, report_json_path):
    report = json.loads(report_json_path.read_text())
    out = render_pdf(report, tmp_path / "report.pdf")

    raw = out.read_bytes()
    assert raw[:5] == b"%PDF-"
    assert len(raw) > 3000
    assert raw.rstrip().endswith(b"%%EOF")

    if PdfReader is None:
        return
    reader, text = _pdf_text(out)
    assert len(reader.pages) >= 3
    low = text.lower()
    for section in ("executive summary", "risk summary", "coverage limitations", "methodology",
                    "sql injection in parameter", "debug endpoint"):
        assert section in low, f"missing section: {section}"
    # the risk table's Total row is house markup and must render bold, not as literal tags
    assert "<b>" not in text and "Total" in text


def test_pdf_redacts_secrets(tmp_path, report_json_path):
    report = json.loads(report_json_path.read_text())
    out = render_pdf(report, tmp_path / "redact.pdf")
    assert out.read_bytes()[:5] == b"%PDF-"
    if PdfReader is None:
        return
    _, text = _pdf_text(out)
    assert "9K9XXE57" not in text and "22A3MWKS" not in text
    assert "[REDACTED]" in text


def test_long_content_paginates(tmp_path, report_json_path):
    report = json.loads(report_json_path.read_text())
    report["findings"][0]["description"] = "Long description sentence. " * 900
    out = render_pdf(report, tmp_path / "long.pdf")
    assert out.read_bytes()[:5] == b"%PDF-"
    if PdfReader is not None:
        assert len(PdfReader(str(out)).pages) >= 4


def test_empty_report_still_renders(tmp_path):
    minimal = {"engagement": {"id": "eng_x", "name": "empty", "profile": "safe_active",
                              "status": "done"},
               "scope": {"targets": [{"kind": "url", "value": "http://127.0.0.1:1"}]},
               "summary": {"assets": 0, "findings_total": 0, "confirmed": 0,
                           "tool_calls": 0, "scope_refusals": 0, "findings_by_state": {}},
               "findings": [], "degradations": [], "generated_at": 0}
    out = render_pdf(minimal, tmp_path / "empty.pdf")
    assert out.stat().st_size > 2000
    if PdfReader is not None:
        _, text = _pdf_text(out)
        assert "No findings recorded" in text
