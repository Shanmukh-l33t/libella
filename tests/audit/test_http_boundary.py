"""HTTP boundary: DNS-rebinding defense and the verification scope gate."""

from libella.scope import Scope


class _FakeStream:
    def get_extra_info(self, name):
        return ("203.0.113.7", 443)  # connected peer differs from resolved DNS


class _FakeResp:
    status_code = 200
    headers = {"content-type": "text/html"}
    url = "http://127.0.0.1/"
    extensions = {"network_stream": _FakeStream()}

    def iter_bytes(self):
        yield b"hello libella"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _RebindingClient:
    def stream(self, *a, **k):
        return _FakeResp()


def _scope(lab, categories=("web",)):
    return Scope({"targets": [{"kind": "url", "value": lab.base}],
                  "categories": list(categories), "rate_limit_rps": 1000})


def test_dns_rebinding_peer_is_refused(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    r = app.probe.request(eid, _scope(lab), lab.base + "/ok", client=_RebindingClient())
    assert r["ok"] is False
    assert "peer_ip_mismatch" in r["error"], r
    # nothing was captured from the rebinding peer
    assert app.db.query("SELECT * FROM exchanges WHERE engagement_id=?", (eid,)) == []


def test_verification_of_an_out_of_scope_proof_is_inconclusive(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    ev = app.evidence.put_json(eid, {"request": {}}, "http_exchange")
    fid = app.pipeline.submit_candidate(eid, {
        "title": "forged", "severity": "critical", "endpoint": "http://127.0.0.1:1/",
        "evidence_ids": [ev["id"]], "quote": "root:",
        "proof_request": {"method": "GET", "url": "http://127.0.0.1:1/etc/passwd"},
        "dedup_key": "forged"})["id"]
    res = app.verifier.verify(eid, _scope(lab), fid)
    assert res["verdict"] == "inconclusive", res
    assert app.pipeline.list(eid)[0]["state"] != "validated"


def test_evidence_path_cannot_escape_the_store(app, mk_eng, lab):
    eid = mk_eng(lab.base)
    secret = app.evidence.root.parent / "outside-secret.txt"
    secret.write_text("top secret")
    data = secret.read_bytes()
    import hashlib
    app.db.execute(
        "INSERT INTO evidence(id, engagement_id, sha256, kind, path, bytes, created_at, prev_hash, chain_hash) "
        "VALUES('ev_evil', ?, ?, 'http_exchange', '../../../outside-secret.txt', ?, 0, '', '')",
        (eid, hashlib.sha256(data).hexdigest(), len(data)))
    try:
        app.evidence.read("ev_evil")
        raise AssertionError("evidence store served a file outside its root")
    except ValueError as e:
        assert "escape" in str(e) or "tamper" in str(e)
