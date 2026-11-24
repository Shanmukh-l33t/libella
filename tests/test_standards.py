"""The standards engine: versioned catalogs, applicability, and honest coverage.

These tests hold the two claims that make the ledger trustworthy:

* the catalog is the published standard (exact ids, chapters, levels) and the
  evidence mapping may only name requirements that exist in it;
* a requirement is only ever accounted for by a check that really covers it, so a
  partial check reports `partial_evidence` and an unexecuted requirement is never
  counted as assessed.
"""
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from libella import check_mapping, coverage, standards  # noqa: E402
from libella.api import App, create_api  # noqa: E402

WEB_SCOPE = {"targets": [{"kind": "url", "value": "http://127.0.0.1:8801"}],
             "categories": ["web"], "rate_limit_rps": 20}


def _app(tmp_path, categories=("web",), level=None):
    app = App(tmp_path / "data")
    scope = {**WEB_SCOPE, "categories": list(categories)}
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, auth_json, budgets_json, "
        "created_at, standards_json) VALUES(?,?,?,?,?,?,?,?,?)",
        ("eng_s", "standards", "safe_active", "draft", json.dumps(scope), "{}", "{}",
         time.time(), json.dumps({"asvs": {"level": level}} if level else {})))
    return app


@pytest.fixture
def app(tmp_path):
    return _app(tmp_path)


@pytest.fixture
def client(app):
    c = TestClient(create_api(app))
    c.headers.update({"Authorization": f"Bearer {app.token}"})
    return c


def exchange(app, eid, tool):
    app.db.execute(
        "INSERT INTO exchanges(id, engagement_id, method, url, status, tool, created_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (eid, "eng_s", "GET", "http://127.0.0.1:8801/", 200, tool, time.time()))


def finding(app, fid, cwe, state):
    app.db.execute(
        "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
        "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (fid, "eng_s", "x", cwe, "high", "high", state, time.time(), time.time()))


def item(ws, rid):
    return next(t for c in ws["categories"] for t in c["tests"] if t["id"] == rid)


# ---- the catalog is the published standard ---------------------------------

def test_asvs_catalog_is_the_official_5_0_0_export():
    reqs = standards.requirements("asvs")
    assert len(reqs) == 345 and len(set(reqs)) == 345
    by = {rid: standards.requirement("asvs", rid) for rid in reqs}
    assert by["V1.1.1"]["level"] == 2
    assert by["V1.2.1"]["level"] == 1
    assert by["V1.2.10"]["level"] == 3
    assert by["V1.2.4"]["chapter"] == "V1" and by["V1.2.4"]["section"] == "V1.2"
    assert by["V1.2.4"]["title"].startswith("Verify that data selection or database queries")
    assert "parameterized queries" in by["V1.2.4"]["title"]
    assert len({r["chapter"] for r in by.values()}) == 17
    fw = standards.framework("asvs")
    assert (fw["id"], fw["version"], fw["license"]) == ("ASVS", "5.0.0", "CC BY-SA 4.0")
    assert fw["upstream_sha"] == "82fb2f41cdb623e0b11e4d9a6b97c4306c1d119c"


def test_levels_are_cumulative_and_match_the_published_counts():
    assert [len(standards.requirements("asvs", lv)) for lv in (1, 2, 3)] == [70, 253, 345]


def test_wstg_keeps_its_4_2_identity_in_the_same_shape():
    assert standards.framework("wstg")["version"] == "4.2"
    assert len(standards.requirements("wstg")) == 96
    assert standards.levels("wstg") == []


def test_every_mapping_row_names_a_real_requirement_and_unit():
    for fid in ("wstg", "asvs"):
        spec = standards.spec(fid)
        assert spec["units"], fid
        for unit, row in spec["units"].items():
            assert row["why"], f"{fid}/{unit} claims requirements without a reason"
            for rid in row["ids"]:
                assert rid in spec["requirements"], f"{fid}/{unit} names unknown {rid}"
                assert row["strength"].get(rid) in (None, "direct", "partial", "indirect")
    # units named by the mapping are units the engine can actually record
    wstg_units = set(standards.spec("wstg")["units"])
    assert set(check_mapping.CHECKS) == wstg_units
    asvs_units = set(standards.spec("asvs")["units"])
    assert {"security_headers", "sqli", "tls_audit", "api_audit", "graphql_audit"} <= asvs_units


def test_requirement_ids_do_not_collide_across_standards():
    # coverage_entries is keyed by (engagement, test_id); that only holds because
    # each standard namespaces its ids
    a = set(standards.requirements("asvs"))
    w = set(standards.requirements("wstg"))
    assert not a & w


# ---- applicability ----------------------------------------------------------

def test_a_non_web_engagement_marks_asvs_not_applicable(app):
    app.db.execute("UPDATE engagements SET scope_json=? WHERE id=?",
                   (json.dumps({**WEB_SCOPE, "categories": ["repo"]}), "eng_s"))
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    assert ws["summary"]["applicable"] == 0
    assert ws["summary"]["statuses"]["not_applicable"] == ws["summary"]["total"]


def test_selected_level_limits_the_ledger_and_says_what_it_excluded(tmp_path):
    app = _app(tmp_path, level=1)
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    assert ws["summary"]["total"] == 70
    assert ws["summary"]["level"] == 1
    assert ws["summary"]["excluded_by_level"] == 345 - 70
    assert len(ws["categories"]) == 17


def test_unmapped_requirements_keep_their_reason(app):
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    v16 = item(ws, "V16.5.1")
    assert v16["automatic"]["status"] == "requires_manual"
    assert "log pipeline" in v16["automatic"]["reason"]
    # WebRTC is catalogued, has no check, and must not be silently dropped
    assert item(ws, "V17.1.1")["automatic"]["status"] == "requires_manual"


# ---- honest derivation ------------------------------------------------------

def test_direct_check_that_ran_is_not_a_requirement_pass_but_is_recorded(app):
    exchange(app, "ex_hdr", "headers_check")
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    hsts = item(ws, "V3.4.1")
    assert hsts["automatic"]["status"] == "completed_no_issue"
    assert hsts["automatic"]["strength"] == "direct"
    assert hsts["evidence"]["exchanges"] == ["ex_hdr"]
    csp = item(ws, "V3.4.3")  # header presence only: cannot pass the directive requirement
    assert csp["automatic"]["status"] == "partial_evidence"
    assert csp["automatic"]["strength"] == "partial"


def test_verified_finding_fails_the_requirement_and_unverified_only_raises_it(app):
    _finding_from(app, "f1", "CWE-89", "SQL injection", "sqli_check", state="suspected")
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    assert item(ws, "V1.2.4")["automatic"]["status"] == "finding_unverified"
    app.db.execute("UPDATE findings SET state='validated' WHERE id='f1'")
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    v = item(ws, "V1.2.4")
    assert v["automatic"]["status"] == "finding_verified"
    assert v["evidence"]["findings"] == ["f1"]
    # a SQL injection finding says nothing about the encoding requirement
    assert item(ws, "V1.2.1")["automatic"]["status"] not in (
        "finding_verified", "finding_unverified")


def test_one_exchange_accounts_for_both_standards_without_duplicating_work(app):
    exchange(app, "ex_hdr", "headers_check")
    wstg = coverage.workspace(app.db, "eng_s", "wstg")
    asvs = coverage.workspace(app.db, "eng_s", "asvs")
    assert item(wstg, "WSTG-CONF-07")["automatic"]["status"] == "completed_no_issue"
    assert item(asvs, "V3.4.1")["automatic"]["status"] == "completed_no_issue"
    assert "ex_hdr" in item(wstg, "WSTG-CONF-07")["evidence"]["exchanges"]
    assert "ex_hdr" in item(asvs, "V3.4.1")["evidence"]["exchanges"]
    assert wstg["summary"]["total"] == 96 and asvs["summary"]["total"] == 345


def test_a_mitigated_target_is_inconclusive_not_secure(app):
    exchange(app, "ex_hdr", "headers_check")
    app.db.emit("eng_s", "degradation",
                {"code": "target_mitigated", "units": ["headers_check"]})
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    assert item(ws, "V3.4.1")["automatic"]["status"] == "inconclusive"


# ---- recording a review ----------------------------------------------------

def test_recording_a_review_needs_evidence_or_a_reason(app):
    with pytest.raises(ValueError):
        coverage.record(app.db, "eng_s", "V3.4.1", "covered", framework="asvs")
    with pytest.raises(ValueError):
        coverage.record(app.db, "eng_s", "V3.4.1", "manual", framework="asvs")
    ws = coverage.record(app.db, "eng_s", "V3.4.1", "manual",
                            "verified in the operator console", framework="asvs")
    assert item(ws, "V3.4.1")["status"] == "manual"
    assert ws["summary"]["manual_required"] + ws["summary"]["statuses"]["requires_manual"] >= 1
    with pytest.raises(LookupError):
        coverage.record(app.db, "eng_s", "V9.9.9", "manual", "nope", framework="asvs")


def test_evidence_from_another_engagement_is_refused(app):
    app.db.execute(
        "INSERT INTO engagements(id, name, profile, status, scope_json, created_at) "
        "VALUES(?,?,?,?,?,?)", ("eng_other", "o", "safe_active", "draft", json.dumps(WEB_SCOPE),
                                time.time()))
    app.db.execute(
        "INSERT INTO evidence(id, engagement_id, sha256, kind, path, bytes, created_at, "
        "prev_hash, chain_hash) VALUES(?,?,?,?,?,?,?,?,?)",
        ("ev_foreign", "eng_other", "x" * 64, "http", "blob/x", 1, time.time(), "p", "c"))
    with pytest.raises(ValueError):
        coverage.record(app.db, "eng_s", "V3.4.1", "covered", None, "ev_foreign",
                        framework="asvs")


def test_api_selects_a_level_and_serves_that_ledger(client):
    assert client.get("/api/standards").json()["standards"]
    r = client.put("/api/engagements/eng_s/standards", json={"asvs": {"level": 3}})
    assert r.status_code == 200 and r.json() == {"asvs": {"level": 3}}
    ws = client.get("/api/engagements/eng_s/coverage/asvs").json()
    assert ws["summary"]["total"] == 345 and ws["summary"]["level"] == 3
    assert client.put("/api/engagements/eng_s/standards",
                      json={"asvs": {"level": 9}}).status_code == 400
    assert client.put("/api/engagements/eng_s/standards",
                      json={"wstg": {"level": 1}}).status_code == 400
    assert client.get("/api/engagements/eng_s/coverage/nosuch").status_code == 404
    assert client.put("/api/engagements/eng_s/coverage/asvs/V9.9.9",
                      json={"status": "manual", "note": "x"}).status_code == 404


def test_a_recorded_asvs_review_survives_the_wstg_ledger(app, client):
    exchange(app, "ex_hdr", "headers_check")
    client.put("/api/engagements/eng_s/coverage/asvs/V3.4.1",
               json={"status": "manual", "note": "checked in the browser console"})
    asvs = client.get("/api/engagements/eng_s/coverage/asvs").json()
    wstg = client.get("/api/engagements/eng_s/coverage/wstg").json()
    assert item(asvs, "V3.4.1")["status"] == "manual"
    assert item(wstg, "WSTG-CONF-07")["status"] == "completed_no_issue"
    rows = app.db.query(
        "SELECT test_id, framework FROM coverage_entries WHERE engagement_id='eng_s'")
    assert rows == [{"test_id": "V3.4.1", "framework": "asvs"}]


def _finding_from(app, fid, cwe, title, tool, state="validated", controls=()):
    """A finding bound to evidence captured by a named check, as the pipeline writes it."""
    ev = f"ev_{fid}"
    app.db.execute(
        "INSERT INTO evidence(id, engagement_id, sha256, kind, path, bytes, created_at, "
        "prev_hash, chain_hash) VALUES(?,?,?,?,?,?,?,?,?)",
        (ev, "eng_s", "x" * 64, "http", "blob/" + ev, 1, time.time(), "p", "c"))
    app.db.execute(
        "INSERT INTO exchanges(id, engagement_id, evidence_id, method, url, status, tool, "
        "created_at) VALUES(?,?,?,?,?,?,?,?)",
        (f"ex_{fid}", "eng_s", ev, "GET", "http://127.0.0.1:8801/", 200, tool, time.time()))
    app.db.execute(
        "INSERT INTO findings(id, engagement_id, title, cwe, severity, confidence, state, "
        "evidence_ids_json, controls_json, controls_source, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (fid, "eng_s", title, cwe, "high", "high", state, json.dumps([ev]),
         json.dumps(list(controls)), "check" if controls else "none", time.time(), time.time()))


def test_a_finding_only_fails_requirements_its_own_check_maps_to(app):
    # CWE-200 is emitted by both the path probe and the GraphQL audit; a debug
    # endpoint found by the path probe is not GraphQL introspection evidence
    _finding_from(app, "f_debug", "CWE-200", "Debug endpoint exposes configuration",
                  "path_probe")
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    assert item(ws, "V13.4.5")["automatic"]["status"] == "finding_verified"
    assert item(ws, "V4.3.2")["automatic"]["status"] not in (
        "finding_verified", "finding_unverified")


def test_a_header_finding_only_fails_the_headers_it_names(app):
    # deliberately MISLEADING title: attribution must follow the asserted controls only
    _finding_from(app, "f_hdr", "CWE-693", "Missing security headers (HSTS, X-Content-Type-Options)",
                  "headers_check", controls=("header.csp", "header.referrer_policy"))
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    assert item(ws, "V3.4.3")["automatic"]["status"] == "finding_verified"  # CSP
    assert item(ws, "V3.4.5")["automatic"]["status"] == "finding_verified"  # Referrer-Policy
    hsts = item(ws, "V3.4.1")  # HSTS was present: the check ran and found nothing
    assert hsts["automatic"]["status"] == "completed_no_issue"
    assert item(ws, "V3.4.4")["automatic"]["status"] == "completed_no_issue"


def test_report_carries_every_selected_standard_and_real_chapter_counts(tmp_path):
    from libella.report import render_report
    from libella.report_kinds import coverage_md
    app = _app(tmp_path, level=2)
    _finding_from(app, "f_hdr", "CWE-693", "Missing security headers (HSTS)", "headers_check",
                  controls=("header.hsts",))
    out = render_report(app.db, app.evidence, "eng_s", tmp_path / "rep")
    doc = json.loads((Path(out["outdir"]) / "report.json").read_text())
    md = (Path(out["outdir"]) / "report.md").read_text()
    asvs = next(s for s in doc["standards"] if s["framework"]["id"] == "ASVS")
    assert asvs["summary"]["total"] == 253 and asvs["summary"]["level"] == 2
    assert asvs["summary"]["with_findings"] >= 1
    assert "5.0.0 Level 2 coverage" in md and "WSTG" in md
    # the by-chapter table must count what ran, not read keys that never exist
    view = coverage_md(doc)
    row = next(line for line in view.splitlines() if line.startswith("| Configuration and"))
    assert row.split("|")[3].strip() != "0"
    assert "ASVS" in view or "Application Security Verification Standard" in view


def test_a_header_finding_without_control_ids_fails_no_header_requirement(app):
    # a header finding that asserts no control cannot be pinned to a header: it must
    # not fail any of them by default, and it is listed for analyst review
    _finding_from(app, "f_vague", "CWE-693", "Missing security headers (HSTS)", "headers_check")
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    for rid in ("V3.4.1", "V3.4.3", "V3.4.4", "V3.4.5", "V3.4.6"):
        assert "f_vague" not in item(ws, rid)["evidence"]["findings"], rid
    assert any(f["id"] == "f_vague" for f in ws["unattributed_findings"])


def test_cookie_controls_are_requirement_specific(app):
    _finding_from(app, "f_ck", "CWE-614", "Session cookie 'sid' missing flags", "cookie_check",
                  controls=("cookie.samesite",))
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    assert item(ws, "V3.3.2")["automatic"]["status"] == "finding_verified"   # SameSite
    assert "f_ck" not in item(ws, "V3.3.1")["evidence"]["findings"]          # Secure
    assert "f_ck" not in item(ws, "V3.3.4")["evidence"]["findings"]          # HttpOnly


def test_wrong_category_and_wrong_cwe_never_attribute(app):
    # a TLS finding (tls_audit, CWE-326) and a CORS finding must not fail an injection
    # requirement, and an injection-unit finding with an unrelated CWE fails nothing
    _finding_from(app, "f_cors", "CWE-942", "CORS", "cors_check")
    _finding_from(app, "f_odd", "CWE-1021", "odd", "sqli_check")
    ws = coverage.workspace(app.db, "eng_s", "asvs")
    assert item(ws, "V3.4.2")["evidence"]["findings"] == ["f_cors"]
    assert "f_cors" not in item(ws, "V1.2.4")["evidence"]["findings"]
    assert all("f_odd" not in t["evidence"]["findings"] for c in ws["categories"] for t in c["tests"])


def test_analyst_can_add_and_remove_an_attribution_with_history(app, client):
    _finding_from(app, "f_vague", "CWE-693", "headers", "headers_check")
    url = "/api/engagements/eng_s/coverage/asvs/V3.4.1/links"
    assert client.post(url, json={"finding_id": "f_vague", "action": "add"}).status_code == 400
    r = client.post(url, json={"finding_id": "f_vague", "action": "add",
                               "note": "response confirms HSTS absent on every page"})
    assert r.status_code == 200
    ws = client.get("/api/engagements/eng_s/coverage/asvs").json()
    assert item(ws, "V3.4.1")["evidence"]["findings"] == ["f_vague"]
    client.post(url, json={"finding_id": "f_vague", "action": "remove", "note": "duplicate"})
    ws = client.get("/api/engagements/eng_s/coverage/asvs").json()
    assert "f_vague" not in item(ws, "V3.4.1")["evidence"]["findings"]
    hist = client.post(url, json={"finding_id": "f_vague", "action": "add",
                                  "note": "re-added after review"}).json()["history"]
    assert [h["action"] for h in hist] == ["add", "remove", "add"]
    assert client.post(url, json={"finding_id": "f_nope", "action": "add",
                                  "note": "x"}).status_code == 404


def test_legacy_findings_get_controls_from_the_check_quote_not_the_title(app):
    from libella import controls
    assert controls.from_quote("missing: CSP, HSTS", "header_fact") == ["header.csp", "header.hsts"]
    assert controls.from_quote("sid|Secure,SameSite", "cookie_fact") == [
        "cookie.samesite", "cookie.secure"]
    assert controls.from_quote("Missing security headers (HSTS)", "body") == []


def test_pipeline_persists_controls_and_migrates_legacy_rows(app):
    from libella.checks import _candidate
    ev = app.evidence.put_json("eng_s", {"status": 200}, "http")["id"]
    cand = _candidate("Missing security headers (HSTS)", "CWE-693", None, "medium", "high",
                      "http://127.0.0.1:8801", "d", "i", "r", ev, "missing: HSTS",
                      {"method": "GET", "url": "http://127.0.0.1:8801"}, "headers:x",
                      quote_in="header_fact", controls=["header.hsts"])
    fid = app.pipeline.submit_candidate("eng_s", cand)["id"]
    row = app.db.one("SELECT controls_json, controls_source FROM findings WHERE id=?", (fid,))
    assert (json.loads(row["controls_json"]), row["controls_source"]) == (["header.hsts"], "check")
    # a pre-upgrade finding: same proof spec, no controls recorded
    legacy = app.pipeline.submit_candidate("eng_s", {**cand, "dedup_key": "headers:old",
                                                     "controls": []})["id"]
    app.db.execute("UPDATE findings SET controls_json='[]', controls_source=NULL WHERE id=?",
                   (legacy,))
    coverage.workspace(app.db, "eng_s", "asvs", app.evidence)
    row = app.db.one("SELECT controls_json, controls_source FROM findings WHERE id=?", (legacy,))
    assert (json.loads(row["controls_json"]), row["controls_source"]) == (["header.hsts"], "migrated")


# ---- OWASP API Security Top 10 2023 ----------------------------------------

def test_every_packaged_standard_is_listed_under_the_id_spec_resolves():
    ids = {s["id"]: s for s in standards.available()}
    assert set(ids) == {"wstg", "asvs", "api-top10"}
    for fid in ids:
        assert standards.spec(fid)["order"]


def test_api_top10_is_the_published_2023_list():
    fw = standards.framework("api-top10")
    assert (fw["version"], fw["license"]) == ("2023", "CC BY-SA 4.0")
    assert fw["upstream_sha"] == "33cea37b2ffde3e2e62f6b5d79a029a22a846633"
    titles = [standards.requirement("api-top10", r)["title"]
              for r in standards.requirements("api-top10")]
    assert standards.requirements("api-top10") == [f"API{i}:2023" for i in range(1, 11)]
    assert titles[0] == "Broken Object Level Authorization"
    assert titles[5] == "Unrestricted Access to Sensitive Business Flows"
    assert titles[9] == "Unsafe Consumption of APIs"
    assert all("][" not in standards.requirement("api-top10", r)["summary"]
               for r in standards.requirements("api-top10"))


def test_api_top10_needs_an_api_category(app):
    ws = coverage.workspace(app.db, "eng_s", "api-top10")  # web-only scope
    assert ws["summary"]["applicable"] == 0


def test_same_cwe_from_two_api_checks_lands_on_two_different_risks(tmp_path):
    app = _app(tmp_path, categories=("web", "api"))
    _finding_from(app, "f_expo", "CWE-200", "Excessive data exposure", "api_check")
    _finding_from(app, "f_intro", "CWE-200", "GraphQL introspection", "graphql_check")
    ws = coverage.workspace(app.db, "eng_s", "api-top10")
    assert item(ws, "API3:2023")["evidence"]["findings"] == ["f_expo"]
    assert item(ws, "API8:2023")["evidence"]["findings"] == ["f_intro"]
    for rid in ("API6:2023", "API10:2023"):
        assert item(ws, rid)["automatic"]["status"] == "requires_manual"
    # an inventory-only check can never pass API9
    _finding_from(app, "f_none", "CWE-79", "x", "crawl")
    assert item(coverage.workspace(app.db, "eng_s", "api-top10"), "API9:2023")[
        "automatic"]["status"] != "completed_no_issue"


def test_standards_without_levels_can_be_selected_and_reach_the_report(tmp_path, client, app):
    from libella.report import render_report
    app.db.execute("UPDATE engagements SET scope_json=? WHERE id='eng_s'",
                   (json.dumps({**WEB_SCOPE, "categories": ["web", "api"]}),))
    r = client.put("/api/engagements/eng_s/standards",
                   json={"asvs": {"level": 1}, "api-top10": {}})
    assert r.status_code == 200 and r.json() == {"asvs": {"level": 1}, "api-top10": {}}
    assert client.put("/api/engagements/eng_s/standards",
                      json={"api-top10": {"level": 2}}).status_code == 400
    assert client.put("/api/engagements/eng_s/standards",
                      json={"nope": {}}).status_code == 404
    out = render_report(app.db, app.evidence, "eng_s", tmp_path / "rep")
    doc = json.loads((Path(out["outdir"]) / "report.json").read_text())
    assert [s["framework"]["id"] for s in doc["standards"]] == ["ASVS", "API-Top10"]
    assert "API-Top10 2023 coverage" in (Path(out["outdir"]) / "report.md").read_text()


def test_every_set_cookie_is_inspected_not_just_the_last(app):
    """dict(resp.headers) keeps one Set-Cookie; the insecure second one must not vanish."""
    from libella.checks import WebChecks
    seen = []

    class TwoCookies:
        def request(self, *a, **kw):
            seen.append(kw)
            return {"ok": True, "status": 200,
                    "headers": {"set-cookie": "sessionid=abc; Path=/",
                                "set-cookie-all": ("csrftoken=xyz; Secure; SameSite=Lax\n"
                                                   "sessionid=abc; Path=/")},
                    "body": "", "evidence_id": "ev_x", "exchange_id": "ex_x", "url": "u"}

    cands = WebChecks(TwoCookies(), "eng_s", None).cookie_flags("http://127.0.0.1:8801/")
    # both cookies set on the page are judged, not only the one the dict kept
    by_name = {c["title"].split("'")[1]: set(c["controls"]) for c in cands}
    assert by_name == {"csrftoken": {"cookie.httponly"},
                       "sessionid": {"cookie.httponly", "cookie.secure", "cookie.samesite"}}
