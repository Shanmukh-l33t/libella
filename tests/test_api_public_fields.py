"""Public API responses expose display fields, never stored auth material.

Synthetic credentials in a temp DB only; no scanners, no browser.
"""
import json

from fastapi.testclient import TestClient

from libella.api import App, create_api

PW = "SI_SECRET_PASSWORD_7Q4M2XW9"
TOKEN="***" + "RET_TOKEN_NW3X72B4"  # synthetic sentinel split so scanners see no literal key
COOKIE = "SI_SECRET_COOKIE_3K8N5VZ1"
SCOPE = {"targets": [{"kind": "url", "value": "http://127.0.0.1:9"}]}


def _client(app):
    c = TestClient(create_api(app))
    c.headers["Authorization"] = f"Bearer {app.token}"
    return c


def _engagement(app, auth):
    r = _client(app).post("/api/engagements", json={"name": "n", "scope": SCOPE, "auth": auth})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _leaks(text):
    return [s for s in (PW, TOKEN, COOKIE) if s in text]


def test_engagement_reads_return_usernames_only(tmp_path):
    app = App(tmp_path)
    auth = {
        "identities": [{"username": "alice", "password": PW, "api_token": TOKEN,
                        "session_cookie": COOKIE,
                        "login_url": f"https://alice:{PW}@lab.example/login?token={TOKEN}"}],
        "openapi": "/tmp/openapi-secret.json",
        "graphql": f"https://lab.example/graphql?token={TOKEN}",
        "test_hints": {"ssrf": {"url": f"https://lab.example/?key={TOKEN}",
                                "internal_url": TOKEN, "param": "q", "marker": "m"}},
        "future_field": TOKEN,
    }
    eid = _engagement(app, auth)
    c = _client(app)

    detail = c.get(f"/api/engagements/{eid}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["auth"] == {"identities": [{"username": "alice"}]}
    assert not _leaks(detail.text) and "test_hints" not in detail.text

    listed = c.get("/api/engagements").json()
    row = next(r for r in listed if r["id"] == eid)
    assert row["auth"] == {"identities": [{"username": "alice"}]}
    assert not _leaks(c.get("/api/engagements").text)

    # projection is response-only: the stored engagement still has what scanners need
    stored = app.db.one("SELECT auth_json FROM engagements WHERE id=?", (eid,))
    assert stored is not None and json.loads(stored["auth_json"]) == auth


def test_auth_context_list_scrubs_login_flow(tmp_path):
    app = App(tmp_path)
    eid = _engagement(app, {})
    aid = "ac_test"
    flow = {"base_url": f"https://alice:{PW}@lab.example/app?access_token={TOKEN}",
            "login_url": f"https://lab.example/login?token={TOKEN}#frag",
            "selectors": {"username": "#u", "password": "#p", "submit": "#go"},
            "success_assertion": "#dash", "password": PW}
    app.db.execute(
        "INSERT INTO auth_contexts(id, engagement_id, name, username, login_flow_json, "
        "cookies_json, status, last_verified_at, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (aid, eid, "alice", "alice", json.dumps(flow),
         app.db.seal(json.dumps([{"name": "session", "value": COOKIE}])), "active", 1.0, 1.0))

    r = _client(app).get(f"/api/engagements/{eid}/auth-contexts")
    assert r.status_code == 200, r.text
    ctx = r.json()[0]
    assert ctx["login_flow"]["base_url"] == "https://lab.example/app"
    assert ctx["login_flow"]["login_url"] == "https://lab.example/login"
    assert ctx["login_flow"]["selectors"]["username"] == "#u"
    assert ctx["cookie_count"] == 1
    assert not _leaks(r.text) and "cookies" not in r.text


def test_finding_and_exchange_reads_redact_raw_traffic(tmp_path):
    app = App(tmp_path)
    eid = _engagement(app, {})
    ev = app.evidence.put_json(eid, {
        "request": {"url": "https://lab.example/login", "method": "POST",
                    "headers": {"Cookie": f"session={COOKIE}"},
                    "body": f"username=alice&password={PW}"},
        "response": {"status": 200, "headers": {"Set-Cookie": f"session={COOKIE}"},
                     "body": f"access_token={TOKEN}"}}, "http_exchange")
    fid, xid = "f_test", "ex_test"
    app.db.execute("INSERT INTO findings(id, engagement_id, title, severity, evidence_ids_json, "
                   "created_at) VALUES(?,?,?,?,?,?)",
                   (fid, eid, "t", "low", json.dumps([ev["id"]]), 1.0))
    app.db.execute("INSERT INTO exchanges(id, engagement_id, evidence_id, method, url, status, "
                   "req_headers_json, resp_headers_json, req_body, duration_ms, tool, peer_ip, "
                   "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (xid, eid, ev["id"], "POST", "https://lab.example/login", 200,
                    json.dumps({"Authorization": f"Bearer {TOKEN}", "X-Api-Key": TOKEN}),
                    json.dumps({"Set-Cookie": f"session={COOKIE}"}),
                    f"username=alice&password={PW}", 12.0, "test", "127.0.0.1", 1.0))
    c = _client(app)

    found = c.get(f"/api/findings/{fid}")
    assert found.status_code == 200, found.text
    assert not _leaks(found.text)
    ex = found.json()["exchanges"][0]
    assert set(ex) == {"id", "engagement_id", "evidence_id", "method", "url", "status",
                       "duration_ms", "tool", "peer_ip", "created_at"}

    detail = c.get(f"/api/exchanges/{xid}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert not _leaks(detail.text)
    assert body["req_headers"]["Authorization"] == "[REDACTED]"
    assert body["resp_headers"]["Set-Cookie"] == "[REDACTED]"
    assert PW not in body["req_body"]
    assert PW not in body["blob"]["request"]["body"]
    assert TOKEN not in body["blob"]["response"]["body"]
