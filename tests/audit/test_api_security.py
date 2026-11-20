"""API surface: auth on every route, SSE, IDOR, error handling."""
import json

from fastapi.routing import APIRoute


def _routes(api):
    return [r for r in api.routes if isinstance(r, APIRoute)]


def _fill(path: str) -> str:
    return (path.replace("{eid}", "x").replace("{fid}", "x")
            .replace("{xid}", "x"))


def test_every_route_requires_a_token(client, app):
    api = client.app
    public = {"/api/health"}
    checked = 0
    for route in _routes(api):
        if route.path in public:
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            r = client.request(method, _fill(route.path), json={})
            assert r.status_code == 401, (method, route.path, r.status_code)
            checked += 1
    assert checked >= 20


def test_health_is_public_and_others_are_not(client, app):
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/tools").status_code == 401
    assert client.get("/api/tools", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/tools", headers={"Authorization": f"Bearer {app.token}"}).status_code == 200


def test_token_of_wrong_length_is_rejected_cleanly(client, app):
    r = client.get("/api/tools", headers={"Authorization": "Bearer " + "x" * 5000})
    assert r.status_code == 401


def test_sse_requires_a_single_use_ticket(client, app, mk_eng, lab):
    eid = mk_eng(lab.base)
    url = f"/api/engagements/{eid}/stream"
    assert client.get(url).status_code == 401
    # the long-lived token must never travel in a URL
    assert client.get(f"{url}?token={app.token}").status_code == 401
    assert client.get(f"{url}?ticket=forged").status_code == 401
    assert client.post("/api/ticket").status_code == 401

    h = {"Authorization": f"Bearer {app.token}"}
    ticket = client.post("/api/ticket", headers=h).json()["ticket"]
    with client.stream("GET", f"{url}?ticket={ticket}") as r:
        assert r.status_code == 200
        first = next(r.iter_lines())
        assert first.startswith(":") or first.startswith("id:")
    assert client.get(f"{url}?ticket={ticket}").status_code == 401  # single use


def test_ticket_expires(client, app, mk_eng, lab, monkeypatch):
    eid = mk_eng(lab.base)
    h = {"Authorization": f"Bearer {app.token}"}
    ticket = client.post("/api/ticket", headers=h).json()["ticket"]
    monkeypatch.setattr("libella.api.time.time", lambda: 9_999_999_999.0)
    assert client.get(f"/api/engagements/{eid}/stream?ticket={ticket}").status_code == 401


def test_report_download_accepts_bearer_header(client, app, mk_eng, lab):
    eid = mk_eng(lab.base)
    h = {"Authorization": f"Bearer {app.token}"}
    assert client.get(f"/api/engagements/{eid}/report?format=md").status_code == 401
    assert client.get(f"/api/engagements/{eid}/report?format=md&token={app.token}").status_code == 401
    r = client.get(f"/api/engagements/{eid}/report?format=md", headers=h)
    assert r.status_code == 200 and r.text.startswith("#")
    assert client.get(f"/api/engagements/{eid}/report?format=sarif", headers=h).status_code == 200


def test_resume_refuses_an_already_running_engagement(client, app, mk_eng, lab, monkeypatch):
    calls = []

    class Stub:
        def start(self, *a, **k):
            calls.append(a)

        def pause(self, *a, **k):
            pass

        def cancel(self, *a, **k):
            pass

    eid = mk_eng(lab.base)
    app.db.execute("UPDATE engagements SET status='running' WHERE id=?", (eid,))
    monkeypatch.setattr(app, "orchestrator", lambda: Stub())
    r = client.post(f"/api/engagements/{eid}/resume", headers={"Authorization": f"Bearer {app.token}"})
    assert r.status_code == 409, r.text
    assert not calls  # no second orchestrator for the same engagement


def test_verify_and_retest_still_work_on_real_finding(client, app, mk_eng, lab):
    eid = mk_eng(lab.base)
    ev = app.evidence.put_json(eid, {"request": {"url": lab.base + "/ok"}}, "http_exchange")
    f = app.pipeline.submit_candidate(eid, {
        "title": "t", "cwe": "CWE-79", "severity": "low", "endpoint": lab.base + "/ok",
        "evidence_ids": [ev["id"]], "quote": "hello libella",
        "proof_request": {"method": "GET", "url": lab.base + "/ok"}, "dedup_key": "d1"})
    h = {"Authorization": f"Bearer {app.token}"}
    r = client.post(f"/api/findings/{f['id']}/verify", headers=h)
    assert r.status_code == 200 and r.json()["verdict"] == "reproduced"


def test_unknown_ids_are_404_not_tracebacks(client, app):
    h = {"Authorization": f"Bearer {app.token}"}
    assert client.get("/api/evidence/ev_nope", headers=h).status_code == 404
    assert client.get("/api/exchanges/ex_nope", headers=h).status_code == 404
    assert client.get("/api/findings/f_nope", headers=h).status_code == 404
    assert client.get("/api/engagements/eng_nope/report", headers=h).status_code == 404
    assert client.post("/api/findings/f_nope/verify", headers=h).status_code == 404
    assert client.get("/api/evidence/ev_nope/chain", headers=h).status_code == 404


def test_tampered_evidence_is_refused_by_api(client, app, mk_eng, lab):
    eid = mk_eng(lab.base)
    ev = app.evidence.put(eid, b"original", "http_exchange")
    (app.evidence.root / ev["path"]).write_bytes(b"forged")
    h = {"Authorization": f"Bearer {app.token}"}
    assert client.get(f"/api/evidence/{ev['id']}", headers=h).status_code == 409


def test_tampered_exchange_evidence_is_refused_by_api(client, app, mk_eng, lab):
    eid = mk_eng(lab.base)
    r = app.probe.request(eid, app_scope(app, eid), lab.base + "/ok")
    assert r["ok"]
    ev = app.db.one("SELECT * FROM evidence WHERE id=?", (r["evidence_id"],))
    (app.evidence.root / ev["path"]).write_bytes(b"{}")
    h = {"Authorization": f"Bearer {app.token}"}
    resp = client.get(f"/api/exchanges/{r['exchange_id']}", headers=h)
    assert resp.status_code == 409, resp.text


def test_exchange_api_does_not_leak_session_cookies(client, app, mk_eng, lab):
    eid = mk_eng(lab.base)
    cookie = "se" + "ssion=" + ("abcdef0123456789" * 2)
    r = app.probe.request(eid, app_scope(app, eid), lab.base + "/ok",
                          headers={"Cookie": cookie})
    assert r["ok"]
    h = {"Authorization": f"Bearer {app.token}"}
    body = client.get(f"/api/exchanges/{r['exchange_id']}", headers=h).text
    assert "abcdef0123456789abcdef" not in body
    body2 = client.get(f"/api/evidence/{r['evidence_id']}", headers=h).text
    assert "abcdef0123456789abcdef" not in body2


def test_engagement_lists_do_not_cross_engagements(client, app, mk_eng, lab):
    a, b = mk_eng(lab.base), mk_eng(lab.base)
    for eid, title in ((a, "in-a"), (b, "in-b")):
        ev = app.evidence.put_json(eid, {}, "http_exchange")
        app.pipeline.submit_candidate(eid, {"title": title, "severity": "low",
                                            "endpoint": lab.base, "evidence_ids": [ev["id"]],
                                            "dedup_key": title})
    h = {"Authorization": f"Bearer {app.token}"}
    titles = {f["title"] for f in client.get(f"/api/engagements/{a}/findings", headers=h).json()}
    assert titles == {"in-a"}
    rep = client.get(f"/api/engagements/{a}/report", headers=h).text
    assert "in-b" not in rep


def test_settings_never_returns_the_api_key(client, app):
    h = {"Authorization": f"Bearer {app.token}"}
    client.put("/api/settings", headers=h, json={"llm": {"api_key": "sk-live-very-secret", "base_url": "http://127.0.0.1:1"}})
    body = client.get("/api/settings", headers=h).json()
    assert body["llm"]["api_key"] == "[SET]"
    assert "sk-live-very-secret" not in json.dumps(body)


def app_scope(app, eid):
    s = app.db.one("SELECT scope_json FROM engagements WHERE id=?", (eid,))
    from libella.scope import Scope
    spec = json.loads(s["scope_json"])
    spec["rate_limit_rps"] = 1000
    return Scope(spec)
