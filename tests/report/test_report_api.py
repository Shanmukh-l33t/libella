"""API surface: PDF export, remediation updates, board, engagement comparison."""
from pathlib import Path

from libella.report import render_report


def test_report_pdf_format(client, pair):
    r = client.get("/api/engagements/eng_a/report?format=pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"
    assert len(r.content) > 3000


def test_render_failure_is_actionable_and_leaves_no_partial_report(client, pair):
    """An unwritable report path must name itself in the error, not read as a server bug."""
    outdir = Path(render_report(pair.db, pair.evidence, "eng_a")["outdir"])
    md = (outdir / "report.md").read_text()
    (outdir / "report.json").unlink()
    (outdir / "report.json").mkdir()  # os.replace(...) now fails with EISDIR for every user
    try:
        r = client.get("/api/engagements/eng_a/report?format=pdf")
    finally:
        (outdir / "report.json").rmdir()
    assert r.status_code == 500
    detail = r.json()["detail"]
    assert "Report render failed" in detail and "previous report" in detail, detail
    assert r.content[:5] != b"%PDF-", "a failed render served a report body"
    assert (outdir / "report.md").read_text() == md
    # no temp file survived the failed atomic write
    assert sorted(p.name for p in outdir.iterdir()) == ["report.md", "report.sarif"]
    ok = client.get("/api/engagements/eng_a/report?format=pdf")
    assert ok.status_code == 200 and ok.content[:5] == b"%PDF-"


def test_remediation_route_updates_and_board_groups(client, pair):
    r = client.post("/api/findings/f_eng_a_0/remediation",
                    json={"notes": "WAF rule", "owner": "alice", "fix_commit": "c0ffee1"})
    assert r.status_code == 200
    assert r.json()["owner"] == "alice"

    r = client.post("/api/findings/f_eng_a_1/remediation", json={"state": "remediated"})
    assert r.status_code == 200 and r.json()["remediated_at"]

    board = client.get("/api/engagements/eng_a/remediation-board").json()
    assert board["counts"]["in_progress"] == 1 and board["counts"]["remediated"] == 1
    assert board["total"] == 3


def test_remediation_route_errors(client, pair):
    assert client.post("/api/findings/f_nope/remediation", json={"owner": "x"}).status_code == 404
    assert client.post("/api/findings/f_eng_a_0/remediation",
                       json={"state": "bogus"}).status_code == 400
    assert client.get("/api/engagements/eng_nope/remediation-board").status_code == 404


def test_compare_route(client, pair):
    r = client.get("/api/compare", params={"a": "eng_a", "b": "eng_b"})
    assert r.status_code == 200
    body = r.json()
    assert body["counts"]["new"] == 1
    assert body["counts"]["persisting"] == 1
    assert body["a"]["name"] == "PairLab vuln"
    assert client.get("/api/compare", params={"a": "eng_a", "b": "eng_nope"}).status_code == 404


def test_new_routes_require_token(app, pair):
    from fastapi.testclient import TestClient
    from libella.api import create_api
    anon = TestClient(create_api(app))
    assert anon.get("/api/engagements/eng_a/remediation-board").status_code == 401
    assert anon.get("/api/compare", params={"a": "eng_a", "b": "eng_b"}).status_code == 401
