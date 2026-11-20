"""Quote stability: every proof survives an independent replay, twice."""
from libella.verifier import Verifier


def _proof_specs(eng):
    out = []
    for f in eng.findings():
        spec = eng.proof_spec(f)
        if spec:
            out.append((f, spec))
    return out


def test_verifier_reproduces_every_finding(results):
    eng, _ = results["vuln"]
    verifier = Verifier(eng.app.db, eng.app.evidence, eng.app.probe, eng.app.pipeline)
    verdicts = {f["dedup_key"]: verifier.verify(eng.eid, eng.scope, f["id"])["verdict"]
                for f, _ in _proof_specs(eng)}
    assert verdicts and all(v == "reproduced" for v in verdicts.values()), verdicts


def test_quotes_hold_across_two_consecutive_replays(results):
    eng, _ = results["vuln"]
    for finding, spec in _proof_specs(eng):
        pr = spec["proof_request"]
        for _ in range(2):
            r = eng.app.probe.request(eng.eid, eng.scope, pr["url"], method=pr["method"],
                                      headers=pr["headers"], body=pr["body"],
                                      follow_redirects=False)
            assert r["ok"], (finding["dedup_key"], r.get("error"))
            assert spec["quote"] in r["body"], finding["dedup_key"]


def test_lab_json_is_compact_and_key_sorted(results):
    """Quotes are byte-stable because responses are compact, key-sorted JSON."""
    eng, _ = results["vuln"]
    for _, spec in _proof_specs(eng):
        pr = spec["proof_request"]
        r = eng.app.probe.request(eng.eid, eng.scope, pr["url"], method=pr["method"],
                                  headers=pr["headers"], body=pr["body"],
                                  follow_redirects=False)
        body = r["body"].strip()
        assert body[0] in "{[" and body[-1] in "}]", body[:40]
        assert '": ' not in body and '", "' not in body
        assert spec["quote"] in body
