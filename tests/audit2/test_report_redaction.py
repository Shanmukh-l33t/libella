"""Audit-2: an opaque bearer token in captured text must not reach the report.

`redact()` keyed on labels ("token=", "Cookie:", "Bearer ..."). A JWT quoted
straight out of a response body or a JS bundle has no label, so it was rendered
verbatim in MD/JSON/SARIF and in the PDF export.
"""
import json

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.report import redact, render_report

JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")


def test_jwt_is_redacted():
    out = redact(f"leaked client token {JWT} in bundle.js")
    assert "eyJhbGci" not in out
    assert "REDACTED" in out


def test_report_renders_no_raw_jwt(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
               "VALUES('eng','e','safe_active','done','{}',0)")
    db.execute(
        "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
        "description, evidence_ids_json, dedup_key, created_at, updated_at) "
        "VALUES('f1','eng','Token in bundle','CWE-798','high','high','observed',?, '[]','k',0,0)",
        (f"hardcoded token {JWT}",))
    res = render_report(db, ev, "eng", tmp_path / "out")
    text = (tmp_path / "out" / "report.json").read_text() + \
        (tmp_path / "out" / "report.md").read_text()
    assert "eyJhbGci" not in text
    assert json.loads((tmp_path / "out" / "report.json").read_text())["findings"][0]["description"]
    assert res["outdir"]
