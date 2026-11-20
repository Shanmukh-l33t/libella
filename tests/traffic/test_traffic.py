"""Traffic workspace: search, correlation, authorized replay (positive + negative)."""
import json

from libella.traffic import correlate, replay, search_exchanges


def _capture(app, eid, scope, lab, path="/static", **kw):
    r = app.probe.request(eid, scope, lab.base + path, tool="test", **kw)
    assert r["ok"], r
    return r


def _events(app, eid, kind):
    return app.db.query("SELECT payload_json FROM events WHERE engagement_id=? AND kind=?",
                        (eid, kind))


# ---------------------------------------------------------------- search
def test_search_returns_captured_exchanges(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    _capture(app, eid, scope, lab, "/static")
    _capture(app, eid, scope, lab, "/echo", method="POST", body="hello")
    res = search_exchanges(app.db, eid)
    assert res["total"] == 2, res
    assert res["pages"] == 1
    assert {i["method"] for i in res["items"]} == {"GET", "POST"}
    assert all(i["evidence_id"] for i in res["items"])
    assert res["items"][0]["url"].endswith("/echo")  # newest first


def test_search_filters_by_url_method_status_and_tool(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    _capture(app, eid, scope, lab, "/static")
    _capture(app, eid, scope, lab, "/404")
    _capture(app, eid, scope, lab, "/echo", method="POST", body="x")
    assert search_exchanges(app.db, eid, {"url_substring": "/echo"})["total"] == 1
    assert search_exchanges(app.db, eid, {"method": "post"})["total"] == 1
    only404 = search_exchanges(app.db, eid, {"status": "404"})
    assert only404["total"] == 1 and only404["items"][0]["url"].endswith("/404")
    assert search_exchanges(app.db, eid, {"tool": "test"})["total"] == 3
    assert search_exchanges(app.db, eid, {"tool": "nope"})["total"] == 0
    assert search_exchanges(app.db, eid, {"url_substring": "100%"})["total"] == 0  # LIKE escaped


def test_search_paginates_without_dropping_or_duplicating(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    for i in range(5):
        _capture(app, eid, scope, lab, f"/p{i}")
    seen, page = [], 1
    while True:
        res = search_exchanges(app.db, eid, None, page=page, page_size=2)
        assert res["pages"] == 3 and res["total"] == 5
        seen += [i["id"] for i in res["items"]]
        if page >= res["pages"]:
            break
        page += 1
    assert len(seen) == 5 == len(set(seen))


def test_body_text_searches_evidence_blobs(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    _capture(app, eid, scope, lab, "/static")
    _capture(app, eid, scope, lab, "/echo", method="POST", body="needle-in-request")
    hit = search_exchanges(app.db, eid, {"body_text": "STATIC-LAB-MARKER"})  # response body
    assert hit["total"] == 1 and hit["items"][0]["url"].endswith("/static")
    assert "static-lab-marker" in hit["items"][0]["match"]
    req = search_exchanges(app.db, eid, {"body_text": "needle-in-request"})  # request body
    assert req["total"] == 1 and req["items"][0]["method"] == "POST"
    assert search_exchanges(app.db, eid, {"body_text": "absent-needle-xyz"})["total"] == 0


def test_search_is_engagement_scoped(app, mk_eng, lab, scope_for):
    eid_a, eid_b, scope = mk_eng(lab.base), mk_eng(lab.base), scope_for(lab.base)
    _capture(app, eid_a, scope, lab)
    assert search_exchanges(app.db, eid_a)["total"] == 1
    assert search_exchanges(app.db, eid_b)["total"] == 0  # never leaks across engagements


# ---------------------------------------------------------------- replay
def test_replay_reproduces_links_and_diffs(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    original = _capture(app, eid, scope, lab, "/static")["exchange_id"]
    res = replay(app.db, app.evidence, app.probe, scope, eid, original)
    assert res["ok"], res
    assert res["exchange_id"] != original and res["replay_of"] == original
    assert res["diff"]["body_identical"] is True
    assert res["diff"]["similarity"] == 1.0 and res["diff"]["length_delta"] == 0
    assert res["diff"]["status_original"] == res["diff"]["status_replay"] == 200
    new = app.db.one("SELECT * FROM exchanges WHERE id=?", (res["exchange_id"],))
    assert new["replay_of"] == original and json.loads(new["tags_json"]) == ["replay"]
    assert app.db.one("SELECT replay_of FROM exchanges WHERE id=?", (original,))["replay_of"] is None
    audit = _events(app, eid, "traffic_replay")
    assert audit and json.loads(audit[0]["payload_json"])["replay_exchange_id"] == res["exchange_id"]


def test_replay_applies_overrides_to_the_real_request(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    original = _capture(app, eid, scope, lab, "/echo", method="POST", body="original-body")["exchange_id"]
    res = replay(app.db, app.evidence, app.probe, scope, eid, original,
                 {"body": "overridden-body", "headers": {"x-label": "patched"}})
    assert res["ok"], res
    assert lab.bodies[-1] == b"overridden-body"  # the override reached the target
    echoed = app.evidence.read_json(res["evidence_id"])["response"]["body"]
    assert echoed == "overridden-body|echo|patched"  # body + header override both applied
    assert res["diff"]["body_identical"] is False and res["diff"]["similarity"] < 1.0
    assert res["diff"]["status_changed"] is False


def test_replay_out_of_scope_is_refused_before_egress_and_audited(app, mk_eng, lab, scope_for):
    eid = mk_eng(lab.base)
    original = _capture(app, eid, scope_for(lab.base), lab)["exchange_id"]
    elsewhere = scope_for("http://127.0.0.1:1")  # lab url is out of this scope
    hits = list(lab.hits)
    res = replay(app.db, app.evidence, app.probe, elsewhere, eid, original)
    assert res["ok"] is False and res["error"].startswith("out_of_scope"), res
    assert lab.hits == hits  # nothing left the process
    assert app.db.query("SELECT id FROM exchanges WHERE replay_of=?", (original,)) == []
    refused = _events(app, eid, "traffic_replay_refused")
    assert refused and "not in engagement scope" in refused[0]["payload_json"]


def test_replay_refuses_a_redirect_hop_out_of_scope(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    original = _capture(app, eid, scope, lab, "/redir-out", follow_redirects=False)["exchange_id"]
    res = replay(app.db, app.evidence, app.probe, scope, eid, original)
    assert res["ok"] is False and "out_of_scope" in res["error"], res
    assert _events(app, eid, "scope_refusal")  # probe audited the refused hop
    assert app.db.query("SELECT id FROM exchanges WHERE replay_of=?", (original,)) == []
    assert _events(app, eid, "traffic_replay_failed")


def test_replay_never_fabricates_a_missing_captured_request(app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    app.db.execute("INSERT INTO exchanges(id, engagement_id, evidence_id, method, url, status, "
                   "tool, created_at) VALUES('ex_ghost',?,?,?,?,?,?,?)",
                   (eid, "ev_missing", "GET", lab.base + "/static", 200, "test", 0.0))
    hits = list(lab.hits)
    res = replay(app.db, app.evidence, app.probe, scope, eid, "ex_ghost")
    assert res["ok"] is False and "unavailable" in res["error"], res
    assert lab.hits == hits
    assert replay(app.db, app.evidence, app.probe, scope, eid, "ex_nope")["ok"] is False
    other = mk_eng(lab.base)
    assert replay(app.db, app.evidence, app.probe, scope, other, "ex_ghost")["ok"] is False


# ---------------------------------------------------------------- correlate
def test_correlate_groups_endpoints_and_links_findings_and_observations(
        app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    first = _capture(app, eid, scope, lab, "/q?a=1")
    _capture(app, eid, scope, lab, "/q?a=2")
    _capture(app, eid, scope, lab, "/static")
    fid = app.pipeline.submit_candidate(eid, {
        "title": "Reflected input", "severity": "low", "endpoint": lab.base + "/q?a=1",
        "evidence_ids": [first["evidence_id"]], "quote": "static-lab-marker"})["id"]
    oid = app.pipeline.record_observation(eid, None, "info", "q answered twice",
                                          evidence_id=first["evidence_id"])
    app.pipeline.submit_candidate(eid, {"title": "sibling path", "severity": "low",
                                        "endpoint": lab.base + "/s",
                                        "evidence_ids": [first["evidence_id"]]})
    res = correlate(app.db, eid)
    assert res["exchanges"] == 3 and res["endpoints"] == 2
    by_path = {g["endpoint"].rsplit("/", 1)[-1]: g for g in res["groups"]}
    q = by_path["q"]
    assert q["requests"] == 2 and q["statuses"] == {"200": 2} and q["methods"] == ["GET"]
    assert len(q["exchange_ids"]) == 2
    assert [f["id"] for f in q["findings"]] == [fid]
    assert [o["id"] for o in q["observations"]] == [oid]
    assert by_path["static"]["requests"] == 1 and by_path["static"]["findings"] == []
    # /s is only a string prefix of /static, never an endpoint match
    assert all(f["title"] != "sibling path" for g in res["groups"] for f in g["findings"])
    assert res["groups"][0]["requests"] == 2  # most active endpoint first


def test_correlate_does_not_link_other_engagements_data(app, mk_eng, lab, scope_for):
    eid_a, eid_b, scope = mk_eng(lab.base), mk_eng(lab.base), scope_for(lab.base)
    ex = _capture(app, eid_a, scope, lab, "/q")
    app.pipeline.submit_candidate(eid_b, {"title": "other", "severity": "low",
                                          "endpoint": lab.base + "/q",
                                          "evidence_ids": [ex["evidence_id"]]})
    assert correlate(app.db, eid_a)["groups"][0]["findings"] == []
    assert correlate(app.db, eid_b)["exchanges"] == 0


# ---------------------------------------------------------------- API
def test_traffic_routes_require_auth(client, app, mk_eng, lab, scope_for):
    eid = mk_eng(lab.base)
    xid = _capture(app, eid, scope_for(lab.base), lab)["exchange_id"]
    assert client.get(f"/api/engagements/{eid}/traffic").status_code == 401
    assert client.get(f"/api/engagements/{eid}/traffic/correlate").status_code == 401
    assert client.post(f"/api/exchanges/{xid}/replay").status_code == 401


def test_api_traffic_search_replay_correlate(client, app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    xid = _capture(app, eid, scope, lab, "/static")["exchange_id"]
    h = {"Authorization": f"Bearer {app.token}"}
    search = client.get(f"/api/engagements/{eid}/traffic",
                        params={"body_text": "static-lab-marker", "method": "get"}, headers=h)
    assert search.status_code == 200 and search.json()["total"] == 1, search.text
    assert client.get(f"/api/engagements/{eid}/traffic", params={"status": "abc"},
                      headers=h).status_code == 400
    rp = client.post(f"/api/exchanges/{xid}/replay", json={}, headers=h)
    assert rp.status_code == 200 and rp.json()["replay_of"] == xid, rp.text
    assert rp.json()["diff"]["body_identical"] is True
    cor = client.get(f"/api/engagements/{eid}/traffic/correlate", headers=h)
    assert cor.status_code == 200 and cor.json()["endpoints"] == 1
    assert client.get("/api/engagements/eng_missing/traffic", headers=h).status_code == 404
    assert client.post("/api/exchanges/ex_missing/replay", json={}, headers=h).status_code == 404


def test_api_replay_out_of_scope_returns_403_and_audits(client, app, mk_eng, lab, scope_for):
    eid, scope = mk_eng(lab.base), scope_for(lab.base)
    xid = _capture(app, eid, scope, lab, "/q")["exchange_id"]
    spec = json.loads(app.db.one("SELECT scope_json FROM engagements WHERE id=?", (eid,))["scope_json"])
    spec["exclusions"] = [{"kind": "url_prefix", "value": lab.base + "/q"}]
    app.db.execute("UPDATE engagements SET scope_json=? WHERE id=?", (json.dumps(spec), eid))
    r = client.post(f"/api/exchanges/{xid}/replay", json={},
                    headers={"Authorization": f"Bearer {app.token}"})
    assert r.status_code == 403 and "out_of_scope" in r.json()["detail"], r.text
    assert _events(app, eid, "traffic_replay_refused")
    assert app.db.query("SELECT id FROM exchanges WHERE replay_of=?", (xid,)) == []
