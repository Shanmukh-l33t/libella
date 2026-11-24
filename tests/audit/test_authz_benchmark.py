"""Ground-truth benchmark for the authorization oracle (labs/authzlab).

Each case has a vulnerable route and a /hard twin. Ground truth is declared up front;
TP/FP/FN are measured, not assumed. Mandatory: a universally-accessible PRIVATE
resource is detected, a genuinely PUBLIC one is not, and a detector that flags every
shared response provably fails on the public fixture.
"""
import importlib.util
import sys
import threading
import time
from pathlib import Path

import pytest
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from libella.authorization import norm  # noqa: E402
from libella.db import DB  # noqa: E402
from libella.evidence import EvidenceStore  # noqa: E402
from libella.findings import FindingPipeline  # noqa: E402
from libella.privesc_audit import audit_role_matrix  # noqa: E402
from libella.scope import Scope  # noqa: E402
from libella.tools.http_probe import HttpProbe  # noqa: E402

spec = importlib.util.spec_from_file_location("authzlab_app", ROOT / "labs/authzlab/app.py")
LAB = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LAB)

# (label, path, expected access, vulnerable twin really leaks?)
CASES = [
    ("B other user reads note", "/api/notes/{id}", "owner_only", True),
    ("E1 universally open private vault", "/api/vault/{id}", "owner_only", True),
    ("E2 everyone served alice's profile", "/api/profile", "owner_only", True),
    ("C other tenant reads report", "/api/tenant/acme/report", "tenant:acme", True),
    ("D anonymous reads protected", "/api/account/settings", "authenticated", True),
    ("R non-admin reads admin stats", "/api/admin/stats", "admin_only", True),
    ("F genuinely public", "/api/public/announcements", "public", False),
    ("L anonymous gets 200 login page", "/api/account/billing", "authenticated", False),
]
UNPOLICED = "/api/misc/ledger"  # H


@pytest.fixture(scope="module")
def base():
    srv = make_server("127.0.0.1", 0, LAB.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


class Engine:
    def __init__(self, tmp_path, base, name):
        self.base = base
        self.db = DB(tmp_path / f"{name}.db")
        self.ev = EvidenceStore(self.db, tmp_path / f"ev-{name}")
        self.probe = HttpProbe(self.db, self.ev)
        self.pipe = FindingPipeline(self.db, self.ev)
        self.scope = Scope({"targets": [{"kind": "url", "value": base}],
                            "categories": ["web", "api"], "rate_limit_rps": 1000})

    def run(self, prefix="", policy=True, source="operator", password=None, users=None):
        users = users or list(LAB.USERS)
        policy_list = [{"path": prefix + p, "access": a, "source": source} for _l, p, a, _v in CASES] if policy else []
        auth = {"base_url": self.base,
                "identities": [{"username": u, "password": password or LAB.USERS[u][1], "role": LAB.USERS[u][2],
                                "tenant": LAB.USERS[u][3], "login_url": self.base + "/api/login"} for u in users],
                "test_hints": {"authz_policy": policy_list}}
        eps = [{"method": "GET", "path": prefix + p} for _l, p, _a, _v in CASES] + [
            {"method": "GET", "path": prefix + UNPOLICED}]
        return audit_role_matrix(self.db, self.ev, self.probe, self.scope, "eng", auth, self.pipe, endpoints=eps)

    def flagged(self):
        return {f["dedup_key"] for f in self.pipe.list("eng") if f["dedup_key"].startswith("authz:")}


def key(prefix, path):
    return f"authz:GET:{norm(prefix + path)}"


def test_ground_truth_tp_fp_fn(tmp_path, base):
    tp = fp = fn = tn = 0
    for prefix, name in (("", "vuln"), ("/hard", "hard")):
        e = Engine(tmp_path, base, name)
        out = e.run(prefix)
        assert out["verdict"] == "assessed" and len(out["identities"]) == 4
        flagged = e.flagged()
        for label, path, _a, vulnerable in CASES:
            should = vulnerable and prefix == ""
            did = key(prefix, path) in flagged
            tp += should and did
            fn += should and not did
            fp += did and not should
            tn += (not should) and (not did)
            assert did == should, f"{label} [{name}]: flagged={did} expected={should}"
        assert key(prefix, UNPOLICED) not in flagged  # H: never a finding
    assert (tp, fp, fn, tn) == (6, 0, 0, 10)


def test_universally_accessible_private_resource_is_detected(tmp_path, base):
    e = Engine(tmp_path, base, "e")
    out = e.run()
    v = out["authorization"]["verdicts"]["GET /api/vault/{id}"]
    assert v["verdict"] == "violation" and v["confirmable"] and "anonymous" in v["violations"]
    # the blind spot is real: every identity got identical access, and the matrix alone sees no contradiction
    vault_rows = [r for r in out["matrix"] if r["path"] == "/api/vault/{id}"]
    assert {r["class"] for r in vault_rows} == {"ALLOWED"}
    f = next(f for f in e.pipe.list("eng") if f["dedup_key"] == key("", "/api/vault/{id}"))
    assert "operator" in f["description"] and "control" in f["description"]
    # quote bound to captured evidence + replayable proof carrying the requester's cookie
    proof = next(e.ev.read_json(i) for i in f["evidence_ids"] if _is_proof(e, i))
    assert proof["derived_source"] == "captured_exchange" and proof["proof_request"]["url"].endswith("/api/vault/1")
    assert proof["proof_request"]["headers"]["Cookie"].startswith("session=")  # first violator is bob, logged in
    assert proof["quote"] in e.ev.read_json(f["evidence_ids"][0])["response"]["body"]


def _is_proof(e, evidence_id):
    row = e.db.one("SELECT kind FROM evidence WHERE id=?", (evidence_id,))
    return bool(row and row["kind"] == "proof_spec")


def test_public_resource_is_not_flagged_and_naive_detector_would_fail(tmp_path, base):
    e = Engine(tmp_path, base, "f")
    out = e.run()
    assert out["authorization"]["verdicts"]["GET /api/public/announcements"]["verdict"] == "compliant"
    assert key("", "/api/public/announcements") not in e.flagged()
    # naive detector: "several identities got the same 2xx -> private data shared"
    allowed = {}
    for r in out["matrix"]:
        if r["class"] == "ALLOWED":
            allowed.setdefault(r["path"], set()).add(r["identity"])
    naive = {p for p, who in allowed.items() if len(who) > 1}
    assert "/api/public/announcements" in naive  # it would flag the public fixture...
    naive_fp = len(naive - {p for _l, p, _a, v in CASES if v})
    assert naive_fp >= 1 and not (e.flagged() & {key("", "/api/public/announcements")})  # ...we do not


def test_per_case_verdicts(tmp_path, base):
    want = {"vuln": {"/api/notes/{id}": "violation", "/api/vault/{id}": "violation", "/api/profile": "violation",
                     "/api/tenant/acme/report": "violation", "/api/account/settings": "violation",
                     "/api/admin/stats": "violation", "/api/public/announcements": "compliant",
                     "/api/account/billing": "compliant", UNPOLICED: "unknown_policy"}}
    want["hard"] = {p: ("compliant" if v != "unknown_policy" else v) for p, v in want["vuln"].items()}
    for prefix, name in (("", "vuln"), ("/hard", "hard")):
        e = Engine(tmp_path, base, "v" + name)
        got = {k.split(" ", 1)[1].removeprefix(prefix): v["verdict"]
               for k, v in e.run(prefix)["authorization"]["verdicts"].items()}
        assert got == want[name], name


def test_unknown_policy_is_an_observation_not_a_finding(tmp_path, base):
    e = Engine(tmp_path, base, "h")
    out = e.run(policy=False)
    assert out["authorization"]["verdicts"]["GET " + UNPOLICED]["verdict"] == "unknown_policy"
    obs = e.db.query("SELECT summary FROM observations WHERE kind='authz_unknown_policy'")
    assert any("ledger" in o["summary"] and "Supply a policy" in o["summary"] for o in obs)
    assert not any(f["dedup_key"] == key("", UNPOLICED) for f in e.pipe.list("eng"))


def test_inferred_expectation_is_a_hypothesis_never_a_finding(tmp_path, base):
    e = Engine(tmp_path, base, "i")
    out = e.run(policy=False)  # only inferred owner_only on {id} routes
    assert e.flagged() == set()
    hyp = " ".join(out["authorization"]["hypotheses"])
    assert "/api/vault/{id}" in hyp and "inferred" in hyp
    assert e.db.query("SELECT id FROM observations WHERE kind='authz_hypothesis'")
    # the same facts stated by an inferred-source policy entry are also not confirmable
    e2 = Engine(tmp_path, base, "i2")
    e2.run(source="inferred")
    assert e2.flagged() == set()


def test_unauthenticatable_identities_are_inconclusive_not_clean(tmp_path, base):
    e = Engine(tmp_path, base, "g")
    out = e.run(password="wrong")
    assert out["verdict"] == "inconclusive" and out["status"] == "limited" and not out["candidates"]
    assert e.db.query("SELECT payload_json FROM events WHERE kind='degradation' AND payload_json LIKE '%audit_blocked%'")
    assert e.flagged() == set()
