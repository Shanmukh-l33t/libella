"""Nuclei scope/progress reporting from persisted records only (inert data, no scanner run)."""
import json

from libella.api import App
from libella.report import render_report
from libella.report_kinds import coverage_md
from libella.scan_record import nuclei_scans, scan_md

ARGV = ["nuclei", "-u", "http://t", "-rate-limit", "20", "-timeout", "10", "-pt", "http",
        "-t", "/x", "-severity", "medium,high"]


def _app(tmp_path):
    app = App(tmp_path / "data")
    app.db.execute("INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
                   "VALUES('e','r','safe_active','done',?,0)",
                   (json.dumps({"targets": [{"kind": "url", "value": "http://t"}]}),))
    return app


def _call(app, cid, intent, end, dur=1000, error=None, exit_code=0, decision="executed: ok", argv=ARGV):
    app.db.execute("INSERT INTO tool_calls(id, engagement_id, intent_id, tool, argv_json, target, "
                   "scope_decision, exit_code, duration_ms, error, created_at) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (cid, "e", intent, "nuclei", json.dumps(argv), "http://t", decision, exit_code,
                    dur, error, end))


def _sample(app, intent, at, percent, **kw):
    app.db.execute("INSERT INTO events(engagement_id, kind, payload_json, created_at) "
                   "VALUES('e','scan_progress',?,?)",
                   (json.dumps({"tool": "nuclei", "intent_id": intent, "percent": percent,
                                "requests": 5, "matched": 1, "errors": 0, "templates": 321, **kw}), at))


def test_no_nuclei_means_no_section(tmp_path):
    app = _app(tmp_path)
    assert nuclei_scans(app.db, "e") == {}
    assert scan_md({}) == []


def test_legacy_clean_exit_without_progress_is_unknown_not_complete(tmp_path):
    app = _app(tmp_path)
    _call(app, "c1", "i1", 100)
    a = nuclei_scans(app.db, "e")["attempts"][0]
    assert a["completion"] == "unknown" and a["progress"]["reported"] is False
    assert a["progress"]["templates_selected"] is None and a["progress"]["matched"] is None
    assert a["filters"]["severity"] == "medium,high" and a["filters"]["rate_limit"] == "20"
    assert "templates selected not reported" in "\n".join(scan_md({"nuclei": nuclei_scans(app.db, "e")}))


def test_timeout_is_taken_from_the_record_and_is_unfinished(tmp_path):
    app = _app(tmp_path)
    _call(app, "c1", "i1", 100, error="timeout", exit_code=None)
    _sample(app, "i1", 99, 40)
    a = nuclei_scans(app.db, "e")["attempts"][0]
    assert a["timed_out"] and a["completion"] == "unfinished"
    assert a["progress"]["percent_last"] == 40 and a["progress"]["templates_selected"] == 321
    assert "time limit" in "\n".join(scan_md({"nuclei": nuclei_scans(app.db, "e")}))


def test_complete_requires_clean_exit_and_100_percent(tmp_path):
    app = _app(tmp_path)
    _call(app, "c1", "i1", 100)
    _sample(app, "i1", 99, 100)
    _call(app, "c2", "i2", 200)
    _sample(app, "i2", 199, 87)  # -si samples can lag the exit
    got = {a["call_id"]: a["completion"] for a in nuclei_scans(app.db, "e")["attempts"]}
    assert got == {"c1": "complete", "c2": "unknown"}


def test_repeated_attempts_do_not_inherit_each_others_progress(tmp_path):
    app = _app(tmp_path)
    _call(app, "c1", "i1", 100, dur=50000, error="timeout", exit_code=None)  # ran 50..100
    _call(app, "c2", "i1", 300, dur=50000)                                    # ran 250..300
    _sample(app, "i1", 90, 30)
    _sample(app, "i1", 290, 100)
    _sample(app, "i1", 175, 55)  # in neither window: attributed to neither
    a1, a2 = nuclei_scans(app.db, "e")["attempts"]
    assert (a1["attempt"], a2["attempt"], a1["attempts_for_intent"]) == (1, 2, 2)
    assert a1["progress"]["percent_last"] == 30 and a1["progress"]["samples"] == 1
    assert a2["progress"]["percent_last"] == 100 and a2["completion"] == "complete"


def test_refused_call_never_ran(tmp_path):
    app = _app(tmp_path)
    _call(app, "c1", "i1", 100, exit_code=None, decision="refused: out of scope")
    assert nuclei_scans(app.db, "e")["attempts"][0]["completion"] == "not_run"


def test_match_findings_counted_separately_and_rendered_in_both_reports(tmp_path):
    app = _app(tmp_path)
    app.db.execute("INSERT INTO findings(id, engagement_id, title, severity, confidence, state, "
                   "dedup_key, evidence_ids_json, created_at, updated_at) VALUES('f','e','[nuclei] x',"
                   "'high','low','suspected','nuclei:t:http://t','[]',0,0)")
    _call(app, "c1", "i1", 100)
    _sample(app, "i1", 99, 100)
    out = render_report(app.db, app.evidence, "e", tmp_path / "rep")
    doc = json.loads(open(out["outdir"] + "/report.json").read())
    assert doc["scans"]["nuclei"]["match_findings"] == 1
    assert "## Template scan (nuclei)" in open(out["outdir"] + "/report.md").read()
    assert "### Template scan (nuclei)" not in coverage_md(doc)
    assert "Template scan (nuclei)" in coverage_md(doc)
