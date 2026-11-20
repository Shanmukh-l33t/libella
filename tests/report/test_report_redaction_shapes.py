"""Report privacy: credential shapes that used to survive the redaction pass.

Labelled patterns keyed on `password=` / `Cookie:` / `Bearer `. Two shapes slipped
through every one of them: a quoted JSON/dict key (`{"password": "..."}`) and an
`Authorization` header carrying a non-Bearer scheme (`Authorization: Basic ...`),
where the scheme word absorbed the match and left the credential in the export.
The same secrets then reached report.md/json/sarif and the PDF.
"""
import json
from pathlib import Path

import pytest

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.report import redact, render_report
from libella.report_pdf import render_pdf

PW = "pw-" + "Zq4Wm8Rn2Tv6"
B64 = "YWRtaW46" + "c3VwZXJzZWNyZXQ="
BEARER = "tok-" + "Hf7Ld3Ks9Px5"
SECRETS = (PW, B64, BEARER)


@pytest.mark.parametrize("text", [
    f'{{"password": "{PW}"}}',
    f'{{"db_password": "{PW}", "api_key": "{PW}"}}',
    f"{{'password': '{PW}'}}",                       # python dict repr in tool output
    f'{{"Authorization": "Basic {B64}"}}',
    f'{{"authorization":"Basic {B64}"}}',
    f"Authorization: Basic {B64}",
    f"authorization: Basic {B64}",
    f'{{"set-cookie": "session={B64}"}}',
])
def test_quoted_and_auth_header_credentials_are_redacted(text):
    out = redact(text)
    assert PW not in out and B64 not in out, out
    assert "[REDACTED" in out
    assert redact(out) == out, "redaction must be idempotent (md/pdf re-run it)"


def test_ordinary_report_prose_is_untouched():
    for text in ("Session cookie 'session' missing flags (HttpOnly, Secure, SameSite)",
                 "Authorization checks are missing on /admin",
                 'The response echoed {"role": "admin"}'):
        assert redact(text) == text, text


def _seed(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, created_at, "
               "status_detail) VALUES('eng','Acme','safe_active','done',?,0,?)",
               (json.dumps({"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}]}),
                f'replay failed for {{"password": "{PW}"}}'))
    db.execute("INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
               "endpoint, description, evidence_ids_json, dedup_key, created_at, updated_at) "
               "VALUES('f1','eng','Auth bypass','CWE-287','high','high','validated',"
               "'http://127.0.0.1:8801/api/login',?,'[]','k',0,0)",
               (f'login accepted {{"Authorization": "Basic {B64}"}}',))
    db.emit("eng", "degradation", {"code": "llm_planner_failed",
                                   "detail": f'provider echoed {{"authorization": "Bearer {BEARER}"}}'})
    return db, ev


def test_no_surface_leaks_and_exports_stay_valid(tmp_path):
    db, ev = _seed(tmp_path)
    res = render_report(db, ev, "eng")
    out = Path(res["outdir"])

    report = json.loads((out / "report.json").read_text())
    assert report["findings"][0]["severity"] == "high"   # structure survives redaction
    pdf = render_pdf(report, out / "report.pdf")

    from pypdf import PdfReader
    surfaces = {"md": (out / "report.md").read_text(),
                "json": (out / "report.json").read_text(),
                "sarif": (out / "report.sarif").read_text(),
                "evidence": ev.read(res["evidence_id"]).decode(),
                "pdf": "\n".join(p.extract_text() or "" for p in PdfReader(str(pdf)).pages)}
    for name, text in surfaces.items():
        for secret in SECRETS:
            assert secret not in text, f"{name} leaked a credential"
        assert "[REDACTED" in text, f"{name} shows no redaction marker"
    assert ev.verify_chain("eng")["ok"]
