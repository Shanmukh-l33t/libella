"""Independent verification: replay the proof request, compare observed vs claimed.

'validated' means REPRODUCED NOW, not 'matched a string captured earlier'.
The verifier re-issues the bound request through the scoped probe and checks
the verbatim quote against the fresh response. Fail-closed on any doubt.
"""
import json
import re
import time

from .db import DB, new_id
from .evidence import EvidenceStore
from .findings import FindingPipeline
from .tools.http_probe import HttpProbe

HEADER_NAME_MAP = {
    "CSP": "content-security-policy",
    "X-Content-Type-Options": "x-content-type-options",
    "X-Frame-Options": "x-frame-options",
    "HSTS": "strict-transport-security",
    "Referrer-Policy": "referrer-policy",
}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


class Verifier:
    def __init__(self, db: DB, evidence: EvidenceStore, probe: HttpProbe,
                 pipeline: FindingPipeline):
        self.db = db
        self.evidence = evidence
        self.probe = probe
        self.pipeline = pipeline

    def _proof_spec(self, finding: dict) -> dict | None:
        for eid in reversed(json.loads(finding["evidence_ids_json"])):
            row = self.db.one("SELECT * FROM evidence WHERE id=?", (eid,))
            if row and row["kind"] == "proof_spec":
                try:
                    return self.evidence.read_json(eid)
                except (ValueError, KeyError, OSError):
                    return None  # tampered/unreadable proof is not proof
        return None

    def verify(self, engagement_id: str, scope, finding_id: str) -> dict:
        f = self.db.one("SELECT * FROM findings WHERE id=? AND engagement_id=?",
                        (finding_id, engagement_id))
        if f is None:
            return {"verdict": "error", "detail": "finding not found"}
        spec = self._proof_spec(f)
        attempt = (self.db.one(
            "SELECT COALESCE(MAX(attempt),0)+1 AS n FROM verifications WHERE finding_id=?",
            (finding_id,)) or {"n": 1})["n"]
        if not spec or not spec.get("proof_request"):
            return self._record(finding_id, attempt, "no_proof_spec", None,
                                "inconclusive", "no replayable proof request bound")
        pr = spec["proof_request"]
        if not isinstance(pr, dict) or not isinstance(pr.get("url"), str) or not pr["url"]:
            return self._record(finding_id, attempt, "no_proof_spec", None,
                                "inconclusive", "malformed proof request")
        r = self.probe.request(
            engagement_id, scope, pr["url"], method=pr.get("method", "GET"),
            headers=pr.get("headers"), body=pr.get("body"), tool="verifier_replay",
            follow_redirects=False,
        )
        if not r.get("ok"):
            return self._record(finding_id, attempt, "replay", None,
                                "inconclusive", f"replay request failed: {r.get('error')}")
        quote = spec.get("quote") or ""
        quote_in = spec.get("quote_in", "body")
        reproduced, detail = self._compare(quote, quote_in, r)
        verdict = "reproduced" if reproduced else "not_reproduced"
        self._record(finding_id, attempt, "replay", r["exchange_id"], verdict, detail)
        try:
            if reproduced:
                self.pipeline.transition(finding_id, "validated", reason="independent replay reproduced")
            elif f["state"] == "validated":
                self.pipeline.transition(finding_id, "observed", reason="replay failed to reproduce")
        except ValueError:
            pass  # verdict is recorded; the state machine may not allow the move
        return {"verdict": verdict, "detail": detail, "replay_exchange_id": r["exchange_id"],
                "finding_id": finding_id, "state": "validated" if reproduced else f["state"]}

    def _compare(self, quote: str, quote_in: str, r: dict) -> tuple[bool, str]:
        if not isinstance(quote, str) or not quote.strip():
            return False, "empty proof quote: nothing to reproduce"
        headers = {k.lower(): v for k, v in r["headers"].items()}
        if quote_in == "cookie_fact":
            name, _, flags = quote.partition("|")
            want_missing = [f.strip().lower() for f in flags.split(",") if f.strip()]
            cookies = [v for k, v in r["headers"].items() if k.lower() == "set-cookie"]
            target_cookie = next((c for c in cookies if c.split("=", 1)[0] == name), None)
            if target_cookie is None:
                return False, f"cookie '{name}' not set on replay"
            low = target_cookie.lower()
            still_missing = [f for f in want_missing if f not in low]
            ok = len(still_missing) == len(want_missing)
            return ok, (f"cookie '{name}' still missing {still_missing}" if ok
                        else f"flags now present: {set(want_missing) - set(still_missing)}")
        if quote_in == "header_fact":
            if quote.startswith("missing:"):
                names = [n.strip() for n in quote[len("missing:"):].split(",")]
                still_missing = []
                for n in names:
                    hk = HEADER_NAME_MAP.get(n, n.lower())
                    if hk not in headers:
                        still_missing.append(n)
                ok = len(still_missing) == len(names)
                return ok, f"headers still missing: {still_missing}" if ok else f"headers now present: {set(names)-set(still_missing)}"
            if ":" in quote:
                hk, _, hv = quote.partition(":")
                hk, hv = hk.strip().lower(), hv.strip()
                actual = headers.get(hk, "")
                if hk == "set-cookie":
                    ok = hv.split(";")[0] in actual
                else:
                    ok = actual.startswith(hv) or actual == hv
                return ok, f"{hk}: expected '{hv}', observed '{actual}'"
            ok = _norm(quote) in _norm(str(headers))
            return ok, "header fact substring check"
        # body quote: verbatim (whitespace-normalized) substring of fresh body
        ok = _norm(quote) in _norm(r["body"])
        return ok, "verbatim quote present in replay body" if ok else "quote absent from replay body"

    def _record(self, finding_id, attempt, method, exchange_id, verdict, detail):
        vid = new_id("v")
        self.db.execute(
            "INSERT INTO verifications(id, finding_id, attempt, method, replay_exchange_id, "
            "verdict, detail, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (vid, finding_id, attempt, method, exchange_id, verdict, detail, time.time()),
        )
        f = self.db.one("SELECT engagement_id FROM findings WHERE id=?", (finding_id,))
        if f:
            self.db.emit(f["engagement_id"], "verification", {
                "finding_id": finding_id, "verdict": verdict, "detail": detail,
                "attempt": attempt,
            })
        return {"verdict": verdict, "detail": detail, "verification_id": vid}

    def retest(self, engagement_id: str, scope, finding_id: str) -> dict:
        """Retest after remediation: replay proof; fixed/persists/inconclusive."""
        f = self.db.one("SELECT * FROM findings WHERE id=? AND engagement_id=?",
                        (finding_id, engagement_id))
        if f is None:
            return {"verdict": "error", "detail": "finding not found"}
        spec = self._proof_spec(f)
        if not spec or not spec.get("proof_request"):
            return {"verdict": "inconclusive", "detail": "no replayable proof request"}
        pr = spec["proof_request"]
        r = self.probe.request(engagement_id, scope, pr["url"], method=pr.get("method", "GET"),
                               headers=pr.get("headers"), body=pr.get("body"),
                               tool="retest", follow_redirects=False)
        if not r.get("ok"):
            verdict, detail = "inconclusive", f"request failed: {r.get('error')}"
        else:
            reproduced, detail = self._compare(spec.get("quote", ""), spec.get("quote_in", "body"), r)
            verdict = "persists" if reproduced else "fixed"
        rid = new_id("rt")
        self.db.execute(
            "INSERT INTO retests(id, finding_id, exchange_id, verdict, detail, created_at) "
            "VALUES(?,?,?,?,?,?)",
            (rid, finding_id, r.get("exchange_id"), verdict, detail, time.time()),
        )
        if verdict == "fixed":
            self.pipeline.transition(finding_id, "retested_fixed", reason="retest: proof no longer reproduces")
        elif verdict == "persists":
            self.pipeline.transition(finding_id, "retested_persists", reason="retest: proof still reproduces")
        return {"verdict": verdict, "detail": detail, "finding_id": finding_id}