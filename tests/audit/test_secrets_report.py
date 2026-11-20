"""Secrets handling and report integrity (markdown/JSON/SARIF/CSV)."""
import json
import re
from urllib.parse import urlsplit


from libella.report import _csv_escape, redact, render_report


def test_cookie_headers_are_redacted():
    val = "abcdef0123456789abcdef"
    for text in (f"Cookie: se{'ssion'}={val}",
                 f"Set-Cookie: se{'ssion'}={val}; Path=/",
                 f'{{"cookie": "se{"ssion"}={val}"}}',
                 f'"set-cookie": "se{"ssion"}={val}; HttpOnly"'):
        out = redact(text)
        assert val not in out, out
        assert "REDACTED" in out


def test_redaction_keeps_finding_text_intact():
    text = "Session cookie 'session' missing flags (HttpOnly, Secure, SameSite)"
    assert redact(text) == text


def test_report_text_fields_are_redacted_everywhere(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    secret = "hu" + "nter2hu" + "nter2"
    ev = app.evidence.put_json(eid, {}, "http_exchange")
    app.pipeline.submit_candidate(eid, {
        "title": "Credential exposure", "severity": "high", "endpoint": lab.base,
        "description": f"app config leaks password={secret}",
        "impact": f"attacker reads password={secret}",
        "remediation": f"rotate password={secret}",
        "evidence_ids": [ev["id"]], "dedup_key": "leak"})
    render_report(app.db, app.evidence, eid)
    out = app.evidence.root / eid / "report"
    for name in ("report.md", "report.json", "report.sarif"):
        text = (out / name).read_text()
        assert secret not in text, f"{name} leaked the secret"


def test_markdown_injection_via_endpoint_and_name(app, mk_eng, lab):
    eid = mk_eng(lab.base, name="eng\n## Injected by target")
    ev = app.evidence.put_json(eid, {}, "http_exchange")
    evil = lab.base + "/a`%0a%0a##%20Injected%20section%0a`"
    app.pipeline.submit_candidate(eid, {
        "title": "t`\n## Pwned", "severity": "low", "endpoint": evil,
        "description": "d", "evidence_ids": [ev["id"]], "dedup_key": "md"})
    render_report(app.db, app.evidence, eid)
    md = (app.evidence.root / eid / "report" / "report.md").read_text()
    assert "\n## Injected" not in md
    assert "\n## Pwned" not in md
    headings = [ln for ln in md.splitlines() if ln.startswith("## ")]
    assert set(headings) <= {"## Summary", "## Scope", "## Findings", "## Method",
                             "## Coverage limitations (read before trusting 'no findings')"}


def test_sarif_is_structurally_valid(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    ev = app.evidence.put_json(eid, {}, "http_exchange")
    app.pipeline.submit_candidate(eid, {
        "title": "=cmd|' /C calc'!A0", "severity": "medium",
        "endpoint": lab.base + "/x y?q=a b", "description": "d",
        "evidence_ids": [ev["id"]], "dedup_key": "sarif"})
    render_report(app.db, app.evidence, eid)
    doc = json.loads((app.evidence.root / eid / "report" / "report.sarif").read_text())
    assert doc["version"] == "2.1.0" and "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Libella"
    for res in run["results"]:
        assert res["level"] in ("error", "warning", "note", "none")
        assert res["message"]["text"].strip()
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not re.search(r"[\s\x00-\x1f]", uri), uri
        urlsplit(uri)  # parses as a URI


def test_csv_formula_escaping():
    for dangerous in ("=cmd|' /C calc'!A0", "+1+1", "-1+1", "@SUM(A1)", "\tfoo", "\rfoo"):
        assert _csv_escape(dangerous).startswith("'")
    assert _csv_escape("normal finding") == "normal finding"
