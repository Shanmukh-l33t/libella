"""DefectDojo Generic Findings JSON export: shape, stable ids, truthful verification, auth."""
import sys
import time
from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "defectdojo"))
from harness import parse_generic_json  # noqa: E402

from libella.api import create_api  # noqa: E402
from libella.export_dojo import defectdojo_export  # noqa: E402

ALLOWED = {
    "title", "severity", "description", "date", "cwe", "endpoints", "active", "verified",
    "false_p", "is_mitigated", "unique_id_from_tool", "dynamic_finding",
}


def _finding(fid, title, state, endpoint="http://127.0.0.1:8801/a", verdicts=()):
    return {"id": fid, "title": title, "cwe": "CWE-89", "owasp": "A03:2021 Injection",
            "severity": "high", "confidence": "high", "state": state, "endpoint": endpoint,
            "description": "payload 'x' returned marker", "impact": "data loss",
            "remediation": "parameterize", "evidence_ids": ["ev_1"],
            "verifications": [{"attempt": i + 1, "verdict": v, "detail": f"d{i}"}
                              for i, v in enumerate(verdicts)]}


def _report(findings):
    return {"engagement": {"id": "eng_x", "name": "Synthetic", "status": "done",
                           "profile": "safe_active", "started_at": 1700000000.0,
                           "finished_at": 1700000100.0, "status_detail": None},
            "scope": {"targets": []},
            "summary": {"findings_total": len(findings), "confirmed": 0},
            "findings": findings,
            "degradations": [{"code": "tls_unreachable", "detail": "port 443 filtered"}],
            "generated_at": time.time()}


def test_shape_and_truthful_verification():
    body = defectdojo_export(_report([
        _finding("f1", "SQLi", "validated", verdicts=("reproduced",)),
        _finding("f2", "XSS", "observed"),
        _finding("f3", "Old bug", "ruled_out"),
        _finding("f4", "Fixed bug", "retested_fixed"),
    ]))
    by_id = {f["unique_id_from_tool"].rsplit(":", 1)[-1]: f for f in body["findings"]}
    assert set().union(*by_id.values()) <= ALLOWED
    assert by_id["f1"]["verified"] is True and by_id["f1"]["active"] is True
    assert by_id["f2"]["verified"] is False, "no replay verdict must never read as verified"
    assert by_id["f2"]["active"] is True
    assert by_id["f3"]["false_p"] is True and by_id["f3"]["active"] is False
    assert by_id["f4"]["is_mitigated"] is True and by_id["f4"]["active"] is False
    assert {f["severity"] for f in body["findings"]} == {"High"}
    assert {f["cwe"] for f in body["findings"]} == {89}
    assert {f["date"] for f in body["findings"]} == {"2023-11-14"}
    assert "not independently confirmed" in by_id["f2"]["description"]
    assert "tls_unreachable" in body["description"]  # coverage limits travel with the import


def test_repeats_keep_stable_distinct_ids():
    similar = [_finding("f1", "Reflected XSS", "validated", "http://h/a"),
               _finding("f2", "Reflected XSS", "validated", "http://h/b")]
    first = defectdojo_export(_report(similar))
    second = defectdojo_export(deepcopy(_report(similar)))
    ids = [f["unique_id_from_tool"] for f in first["findings"]]
    assert first == second, "re-export of unchanged state must be byte-identical"
    assert len(set(ids)) == 2 and ids == [f["unique_id_from_tool"] for f in second["findings"]]
    assert ids == ["libella:eng_x:f1", "libella:eng_x:f2"]


def test_hostless_endpoint_is_not_exported():
    # Endpoint.from_uri would raise and abort the import, so it must never reach the payload.
    item = defectdojo_export(_report([_finding("f9", "Odd", "observed", "http://")]))["findings"][0]
    assert "endpoints" not in item
    assert len(parse_generic_json({"findings": [item]})) == 1


def test_upstream_parser_accepts_export():
    body = defectdojo_export(_report([
        _finding("f1", "SQLi", "validated", verdicts=("reproduced",)),
        _finding("f2", "Reflected XSS", "validated"),
        _finding("f3", "Reflected XSS", "validated", "http://h/b"),
    ]))
    parsed = parse_generic_json(body)
    assert len(parsed) == 3
    assert [f.unique_id_from_tool for f in parsed] == [
        "libella:eng_x:f1", "libella:eng_x:f2", "libella:eng_x:f3"]
    assert parsed[0].verified is True and parsed[1].verified is False
    assert parsed[0].unsaved_endpoints[0].url == "http://127.0.0.1:8801/a"


def test_dojo_route_downloads_and_parser_accepts(client, pair):
    r = client.get("/api/engagements/eng_a/report?format=dojo")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert "attachment" in r.headers["content-disposition"]
    assert "SI_SECRET" not in r.text, "export must carry the redacted report, never raw secrets"
    body = r.json()
    parsed = parse_generic_json(body)
    assert len(parsed) == len(body["findings"]) == 3
    assert all(f.title and f.severity and f.description for f in parsed)
    assert len({f.unique_id_from_tool for f in parsed}) == 3


def test_dojo_route_requires_token(app, pair):
    anon = TestClient(create_api(app))
    assert anon.get("/api/engagements/eng_a/report?format=dojo").status_code == 401
    assert client_token_only(app).get(
        "/api/engagements/eng_nope/report?format=dojo").status_code == 404


def client_token_only(app):
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    return c
