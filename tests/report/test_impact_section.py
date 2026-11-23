"""D-3: the report separates "verified" from "impact demonstrated"."""
import json
import time

from libella.api import App
from libella.report import render_report


def _app(tmp_path):
    app = App(tmp_path / "data")
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
        "VALUES('e','r','safe_active','done',?,0)",
        (json.dumps({"targets": [{"kind": "url", "value": "http://127.0.0.1:1"}],
                     "categories": ["web"]}),))
    app.db.execute(
        "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
        "evidence_ids_json, created_at, updated_at) VALUES('f1','e','SQL injection','CWE-89',"
        "'high','high','validated','[]',?,?)", (time.time(), time.time()))
    return app


def test_a_verified_finding_without_impact_says_so(tmp_path):
    app = _app(tmp_path)
    out = render_report(app.db, app.evidence, "e", tmp_path / "rep")
    md = (out["outdir"] + "/report.md") if isinstance(out["outdir"], str) else ""
    text = open(md).read()
    assert "## Demonstrated impact" in text
    assert "none was taken further to a demonstrated impact" in text


def test_a_demonstrated_impact_is_listed_with_its_quote(tmp_path):
    app = _app(tmp_path)
    ev = app.evidence.put_json("e", {"ok": True}, "http")
    app.pipeline.record_observation("e", None, "impact_demonstrated",
                                    "SQL injection read marker 'CANARY-1'", ev["id"],
                                    quote="CANARY-1")
    out = render_report(app.db, app.evidence, "e", tmp_path / "rep")
    doc = json.loads(open(out["outdir"] + "/report.json").read())
    assert doc["impact"][0]["quote"] == "CANARY-1"
    text = open(out["outdir"] + "/report.md").read()
    assert "SQL injection read marker" in text and "CANARY-1" in text
