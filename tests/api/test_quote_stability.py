"""Quote stability: every proof survives an independent replay, twice."""
from libella.verifier import Verifier


def _proof_specs(eng):
    out = []
    for f in eng.findings():
        for eid in f["evidence_ids"]:
            row = eng.app.db.one("SELECT kind FROM evidence WHERE id=?", (eid,))
            if row and row["kind"] == "proof_spec":
                out.append((f, eng.app.evidence.read_json(eid)))
    return out


def test_verifier_reproduces_every_finding(results):
    eng, _ = results["vuln"]
    verifier = Verifier(eng.app.db, eng.app.evidence, eng.app.probe, eng.app.pipeline)
    verdicts = {f["cwe"]: verifier.verify(eng.eid, eng.scope, f["id"])["verdict"]
                for f, _ in _proof_specs(eng)}
    assert verdicts and all(v == "reproduced" for v in verdicts.values()), verdicts


def test_quotes_hold_across_two_consecutive_replays(results):
    eng, _ = results["vuln"]
    for finding, spec in _proof_specs(eng):
        pr = spec["proof_request"]
        for _ in range(2):
            r = eng.app.probe.request(eng.eid, eng.scope, pr["url"], method=pr.get("method", "GET"),
                                      headers=pr.get("headers"), body=pr.get("body"),
                                      follow_redirects=False)
            assert r["ok"] and r["status"] in (200, 201), (finding["cwe"], r.get("status"), r.get("error"))
            assert spec["quote"] in r["body"], finding["cwe"]


def test_lab_json_is_compact_and_key_sorted(results):
    """The quotes are byte-stable because responses are compact, sorted JSON."""
    eng, _ = results["vuln"]
    body = quote = None
    for finding, spec in _proof_specs(eng):
        if finding["cwe"] == "CWE-639":
            pr = spec["proof_request"]
            r = eng.app.probe.request(eng.eid, eng.scope, pr["url"], headers=pr["headers"],
                                      follow_redirects=False)
            body, quote = r["body"].strip(), spec["quote"]
    assert body and quote
    assert body.startswith("{") and body.endswith("}")
    assert '": ' not in body and '", "' not in body
    assert quote in body
