"""Independent verification: replay the proof request, compare observed vs claimed.

'validated' means REPRODUCED NOW, not 'matched a string captured earlier'.
The verifier re-issues the bound request through the scoped probe and checks
the verbatim quote against the fresh response. Fail-closed on any doubt.
"""
import json
import re
import time
from urllib.parse import urlparse

from . import proof
from .assessment_window import stored_window_refusal
from .db import DB, new_id
from .evidence import EvidenceStore
from .findings import FindingPipeline
from .tools.http_probe import HttpProbe

# Interstitials that answer with a status the engine did not expect. A block page
# is not remediation, so a class change must not read as fixed through one.
BLOCK_SIGNATURES = (
    "just a moment", "attention required", "access denied", "request blocked",
    "request unsuccessful", "the requested url was rejected",
    "web application firewall", "incapsula incident id", "sucuri website firewall",
)
BLOCK_HEADERS = ("cf-ray", "cf-mitigated", "x-sucuri-id", "x-iinfo")

HEADER_NAME_MAP = {
    "CSP": "content-security-policy",
    "X-Content-Type-Options": "x-content-type-options",
    "X-Frame-Options": "x-frame-options",
    "HSTS": "strict-transport-security",
    "Referrer-Policy": "referrer-policy",
}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _control_request(benign: dict) -> dict:
    """The negative control as a replayable request: same route, no credential."""
    pr = {"method": benign.get("method", "GET"), "url": benign["url"]}
    for key in ("body", "headers"):
        if benign.get(key):
            # drop the capability being tested, keep the request otherwise identical
            pr[key] = ({k: v for k, v in benign[key].items()
                        if k.lower() not in ("cookie", "authorization")}
                       if key == "headers" else benign[key])
    return pr


def _json_field(body: str, field: str):
    """Owner field from a response body: top level, one-record list, or GraphQL data.

    Absent means the body does not state an owner, which is a refusal to judge: the
    caller must not substitute the endpoint, a title, or a model's prose for it.
    """
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        for value in data["data"].values():  # {"data": {"user": {"id": 2}}}
            if isinstance(value, dict) and field in value:
                return value[field]
    if isinstance(data, dict):
        return data.get(field)
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
        return data[0].get(field)  # one-record envelope: {"items":[{"user_id":2}]}
    return None


def _looks_blocked(r: dict) -> str | None:
    """Name the block-page signal in this response, if there is one."""
    lower_headers = {k.lower() for k in r.get("headers", {})}
    for h in BLOCK_HEADERS:
        if h in lower_headers:
            return f"header {h}"
    low = (r.get("body") or "")[:8192].lower()
    for sig in BLOCK_SIGNATURES:
        if sig in low:
            return f"signature '{sig}'"
    return None


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

    @staticmethod
    def _replay_category(scope) -> str:
        """Replay under a category the engagement actually permits."""
        for c in ("web", "api", "infra", "recon"):
            if c in scope.categories:
                return c
        return next(iter(scope.categories), "web")

    def verify(self, engagement_id: str, scope, finding_id: str) -> dict:
        f = self.db.one("SELECT * FROM findings WHERE id=? AND engagement_id=?",
                        (finding_id, engagement_id))
        if f is None:
            return {"verdict": "error", "detail": "finding not found"}
        spec = self._proof_spec(f)
        attempt = (self.db.one(
            "SELECT COALESCE(MAX(attempt),0)+1 AS n FROM verifications WHERE finding_id=?",
            (finding_id,)) or {"n": 1})["n"]
        refusal = stored_window_refusal(self.db, engagement_id)
        if refusal:
            return self._record(finding_id, attempt, "policy_refusal", None, "inconclusive", refusal)
        if not spec or not spec.get("proof_request"):
            return self._record(finding_id, attempt, "no_proof_spec", None,
                                "inconclusive", "no replayable proof request bound")
        pr = spec["proof_request"]
        if not isinstance(pr, dict) or not isinstance(pr.get("url"), str) or not pr["url"]:
            return self._record(finding_id, attempt, "no_proof_spec", None,
                                "inconclusive", "malformed proof request")
        if pr.get("method") == "TLS":
            return self._verify_tls(engagement_id, scope, f, spec, pr, attempt)
        r = self._replay(engagement_id, scope, pr, "verifier_replay")
        if not r.get("ok"):
            return self._record(finding_id, attempt, "replay", None,
                                "inconclusive", f"replay request failed: {r.get('error')}")
        if r.get("mitigated"):
            # a challenge page proves nothing about the finding either way
            return self._record(finding_id, attempt, "replay", r["exchange_id"], "inconclusive",
                                f"replay was answered by a {r['mitigated']} challenge, not the "
                                f"application: verification is inconclusive")
        quote = spec.get("quote") or ""
        quote_in = spec.get("quote_in", "body")
        reproduced, detail = self._compare(quote, quote_in, r)
        if not reproduced:
            self._record(finding_id, attempt, "replay", r["exchange_id"], "not_reproduced", detail)
            if f["state"] == "validated":
                self._demote(finding_id, "replay failed to reproduce")
            return {"verdict": "not_reproduced", "detail": detail,
                    "replay_exchange_id": r["exchange_id"], "finding_id": finding_id,
                    "state": f["state"]}
        # The quote came back. That alone is NOT the claim: the contract says what the
        # observation has to mean, and its controls say what would also be true if the
        # weakness were absent. Reproducing the same flawed test twice proves only that
        # the test is repeatable -- the exact failure that let an empty-marker SSRF and a
        # public-page IDOR reach 'validated'.
        kind = proof.kind_for(f["cwe"])
        gaps = proof.missing(kind, spec.get("proof"), pr, f["title"] or "")
        if gaps:
            return self._record(finding_id, attempt, "proof_contract", r["exchange_id"],
                                "unsupported",
                                f"observation reproduced ({detail}) but the proof contract for "
                                f"{kind} is incomplete: missing {', '.join(gaps)}. A repeated "
                                f"observation without these prerequisites does not establish "
                                f"the weakness, so it is not confirmed.")
        ok, why = self._corroborate(engagement_id, scope, kind, spec.get("proof") or {}, r,
                                    pr, quote)
        if not ok:
            return self._record(finding_id, attempt, "proof_contract", r["exchange_id"],
                                "unsupported",
                                f"observation reproduced ({detail}) but the differential does "
                                f"not support the claim: {why}")
        self._record(finding_id, attempt, "replay", r["exchange_id"], "reproduced", detail)
        try:
            self.pipeline.transition(finding_id, "validated", reason="independent replay reproduced")
        except ValueError:
            pass  # verdict is recorded; the state machine may not allow the move
        return {"verdict": "reproduced", "detail": detail, "replay_exchange_id": r["exchange_id"],
                "finding_id": finding_id, "state": "validated"}

    def _demote(self, finding_id: str, reason: str):
        try:
            self.pipeline.transition(finding_id, "observed", reason=reason)
        except ValueError:
            pass

    def _corroborate(self, engagement_id, scope, kind: str, contract: dict, r: dict,
                     pr: dict, quote: str = "") -> tuple[bool, str]:
        """Does the observation mean what the finding claims? One control per class.

        Each check asks the question that separates the weakness from the benign
        explanation for the same response: the resource is public, the marker is the
        target's own text, the payload was simply echoed, the document is another page.
        """
        if kind == proof.AUTHORIZATION:
            return self._corroborate_authz(engagement_id, scope, contract, r)
        if kind == proof.SSRF:
            return self._corroborate_ssrf(engagement_id, scope, contract, pr)
        if kind in (proof.SQL_ERROR, proof.BLIND_COMMAND) or \
                contract.get("signal") == "union_marker":
            return self._corroborate_injection(engagement_id, scope, contract, r, quote)
        if kind == proof.HEADERS:
            want, got = proof.canonical_document(contract.get("document")), \
                proof.canonical_document(pr.get("url"))
            if want and want != got:
                return False, f"proof document {want} is not the assessed resource {got}"
            lowered = {k.lower() for k in (r.get("headers") or {})}
            present = [c for c in contract.get("controls") or () if c.lower() in lowered]
            return (not present), (f"controls already present on replay: {present}" if present
                                   else "control ids still absent from the served response")
        if kind == proof.SESSION:
            jars = [v for k, v in (r.get("headers") or {}).items() if k.lower() == "set-cookie"]
            name = contract["cookie"]
            jar = next((c for c in jars if c.split("=", 1)[0].strip() == name), None)
            if jar is None:
                return False, f"cookie '{name}' is not set by the replayed response"
            still = [f for f in contract["missing"] if f.lower() not in jar.lower()]
            return (len(still) == len(contract["missing"])), \
                f"flags now present on '{name}': {sorted(set(contract['missing']) - set(still))}"
        return True, ""

    def _corroborate_authz(self, engagement_id, scope, contract: dict, r: dict) -> tuple[bool, str]:
        """An access-control claim needs BOTH: another owner's record, and a denial without the identity."""
        identity = contract.get("identity") or {}
        name = identity.get("name") or ""
        mine = str(identity.get("value"))
        if contract.get("privilege"):
            # function/role-level: the claim is that a caller without the privilege got the
            # data, so the differential is the same request with no identity at all
            return self._authz_control(engagement_id, scope, contract, name, "privilege")
        field = contract["owner_field"]
        owner = _json_field(r.get("body") or "", field)
        if owner is None:
            return False, f"the replayed body carries no '{field}' field, so ownership is unshown"
        if str(owner) == mine:
            return False, (f"'{field}' is {owner!r}, the requesting identity itself: this is the "
                           f"caller's own object, not another user's")
        if str(owner) != str(contract["owner_value"]):
            return False, (f"'{field}' is {owner!r} but the recorded owner was "
                           f"{contract['owner_value']!r}: the object answered differently")
        ok, why = self._authz_control(engagement_id, scope, contract, name, "ownership")
        if not ok:
            return False, why
        return True, f"{name} read {owner}'s record; {why}"

    def _authz_control(self, engagement_id, scope, contract: dict, name: str,
                       what: str) -> tuple[bool, str]:
        """The same request with no credential must be refused for the claim to hold."""
        benign = contract["benign_request"]
        b = self._replay(engagement_id, scope, _control_request(benign), "verifier_control")
        if not b.get("ok"):
            return False, f"the unauthenticated control request failed ({b.get('error')})"
        if b.get("mitigated"):
            return False, "the control request hit a challenge page, so the denial is unshown"
        if b["status"] < 400:
            return False, (f"the same request WITHOUT {name}'s credential answered {b['status']}: "
                           f"the resource is readable anonymously, so no access-control decision "
                           f"(by {what}) was demonstrated")
        return True, f"anonymous got {b['status']}"

    def _corroborate_ssrf(self, engagement_id, scope, contract: dict, pr: dict) -> tuple[bool, str]:
        """The marker must come from the server-side fetch, not from the target's own text."""
        marker = contract["marker"]
        benign = contract["benign_request"]
        b = self._replay(engagement_id, scope, _control_request(benign), "verifier_control")
        if not b.get("ok"):
            return False, f"the control request failed ({b.get('error')})"
        if b.get("mitigated"):
            return False, "the control request hit a challenge page"
        if marker in (b.get("body") or ""):
            return False, (f"the marker {marker!r} also appears when the parameter carries no "
                           f"internal URL: the response is not evidence of a server-side fetch")
        return True, "marker present only when the parameter names the internal URL"

    def _corroborate_injection(self, engagement_id, scope, contract: dict, r: dict,
                              quote: str) -> tuple[bool, str]:
        """The claimed signal must be absent when the parameter carries a benign value."""
        if contract.get("signal") == "reflection":
            # the payload came back verbatim in an HTML response: that is the finding
            return True, "payload reflected verbatim; unescaped output is the claim"
        benign = contract["benign_request"]
        b = self._replay(engagement_id, scope, _control_request(benign), "verifier_control")
        if not b.get("ok"):
            return False, f"the control request failed ({b.get('error')})"
        if b.get("mitigated"):
            return False, "the control request hit a challenge page"
        body = b.get("body") or ""
        signal = _norm(quote or contract.get("marker") or "")
        if signal and signal in _norm(body):
            return False, (f"the claimed signal {quote[:60]!r} also appears for the benign value: "
                           f"the response does not distinguish the injected input")
        return True, f"benign control answered {b['status']} without the claimed signal"

    def _replay(self, engagement_id: str, scope, pr: dict, tool: str) -> dict:
        """Replay a proof over the transport that captured it (browser when challenged)."""
        category = self._replay_category(scope)
        if pr.get("via") == "browser":
            return self.probe.browser_request(engagement_id, scope, pr["url"],
                                              category=category, tool=tool)
        return self.probe.request(
            engagement_id, scope, pr["url"], method=pr.get("method", "GET"),
            headers=pr.get("headers"), body=pr.get("body"), tool=tool,
            follow_redirects=False, category=category,
        )

    def _verify_tls(self, engagement_id: str, scope, f: dict, spec: dict, pr: dict,
                    attempt: int) -> dict:
        """Independent re-verification for TLS findings: re-scan, compare facts."""
        from .tls_audit import recheck_tls_fact
        u = urlparse(pr["url"])
        host, port = u.hostname, u.port or 443
        if not host:
            return self._record(f["id"], attempt, "tls_recheck", None,
                                "inconclusive", "malformed tls proof url")
        ok, detail = recheck_tls_fact(host, port, spec.get("quote", ""), scope, self.db, engagement_id)
        if ok is None:  # refused before any dial, or the scan could not judge
            if not detail.startswith("refused"):
                # Egress already audited a policy refusal as egress_denied + scope_refusal
                self._refusal_event(engagement_id, f"tls://{host}:{port}", detail)
            return self._record(f["id"], attempt, "tls_recheck", None, "inconclusive", detail)
        verdict = "reproduced" if ok else "not_reproduced"
        self._record(f["id"], attempt, "tls_recheck", None, verdict, detail)
        try:
            if ok:
                self.pipeline.transition(f["id"], "validated", reason="independent TLS recheck reproduced")
            elif f["state"] == "validated":
                self.pipeline.transition(f["id"], "observed", reason="TLS recheck failed to reproduce")
        except ValueError:
            pass
        return {"verdict": verdict, "detail": detail, "finding_id": f["id"],
                "state": "validated" if ok else f["state"]}

    def _refusal_event(self, engagement_id: str, url: str, detail: str):
        if detail.startswith("refused:"):
            self.db.emit(engagement_id, "scope_refusal",
                         {"url": url, "reason": detail, "tool": "verifier_tls_recheck"})

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

    # a retest verdict says something only about a finding that reproduced
    RETESTABLE = ("validated", "reported", "remediated", "retested_fixed", "retested_persists")

    def retest(self, engagement_id: str, scope, finding_id: str) -> dict:
        """Retest after remediation: replay proof; fixed/persists/inconclusive."""
        f = self.db.one("SELECT * FROM findings WHERE id=? AND engagement_id=?",
                        (finding_id, engagement_id))
        if f is None:
            return {"verdict": "error", "detail": "finding not found"}
        if f["state"] not in self.RETESTABLE:
            return {"verdict": "inconclusive", "finding_id": finding_id,
                    "detail": f"finding is '{f['state']}'; retest requires a validated finding"}
        refusal = stored_window_refusal(self.db, engagement_id)
        if refusal:
            self.db.emit(engagement_id, "retest_refused", {"finding_id": finding_id, "detail": refusal})
            return {"verdict": "inconclusive", "detail": refusal, "finding_id": finding_id}
        spec = self._proof_spec(f)
        if not spec or not spec.get("proof_request"):
            return {"verdict": "inconclusive", "detail": "no replayable proof request"}
        pr = spec["proof_request"]
        if pr.get("method") == "TLS":
            from .tls_audit import recheck_tls_fact
            u = urlparse(pr["url"])
            host, port = u.hostname, u.port or 443
            if not host:
                return {"verdict": "inconclusive", "detail": "malformed tls proof url",
                        "finding_id": finding_id}
            ok, detail = recheck_tls_fact(host, port, spec.get("quote", ""), scope, self.db, engagement_id)
            if ok is None:
                if not detail.startswith("refused"):  # Egress already audited that refusal
                    self._refusal_event(engagement_id, f"tls://{host}:{port}", detail)
                verdict = "inconclusive"
            else:
                verdict = "persists" if ok else "fixed"
            rid = new_id("rt")
            self.db.execute(
                "INSERT INTO retests(id, finding_id, exchange_id, verdict, detail, created_at) "
                "VALUES(?,?,?,?,?,?)", (rid, finding_id, None, verdict, detail, time.time()))
            if verdict != "inconclusive":
                try:
                    self.pipeline.transition(
                        finding_id, "retested_persists" if ok else "retested_fixed",
                        reason=f"TLS retest: {detail}")
                except ValueError:
                    pass
            self.db.emit(engagement_id, "retest", {"finding_id": finding_id, "verdict": verdict})
            return {"verdict": verdict, "detail": detail, "finding_id": finding_id}
        category = self._replay_category(scope)

        def replay() -> dict:
            return self._replay(engagement_id, scope, pr, "retest")

        r = replay()
        if r.get("mitigated"):
            verdict, detail = ("inconclusive",
                               f"retest was answered by a {r['mitigated']} challenge, not the "
                               f"application: a fix cannot be claimed from it")
        elif not r.get("ok"):
            verdict, detail = "inconclusive", f"request failed: {r.get('error')}"
        else:
            verdict, detail = self._retest_verdict(spec, r)
            if verdict == "class_changed":
                # a status the proof never saw is not a fix by itself: corroborate
                verdict, detail = self._corroborate_fixed(
                    engagement_id, scope, category, spec, pr, r, detail, replay)
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
        self.db.emit(engagement_id, "retest", {"finding_id": finding_id, "verdict": verdict})
        return {"verdict": verdict, "detail": detail, "finding_id": finding_id}

    def _retest_verdict(self, spec: dict, r: dict) -> tuple[str, str]:
        """'fixed' only from a comparable, unblocked response. Everything else is inconclusive."""
        reproduced, detail = self._compare(spec.get("quote", ""), spec.get("quote_in", "body"), r)
        if reproduced:
            return "persists", detail
        status = r["status"]
        if status in (401, 403) or status >= 500:
            return "inconclusive", f"status {status} is an auth/error response: {detail}"
        location = {k.lower(): v for k, v in r["headers"].items()}.get("location", "")
        if 300 <= status < 400 and re.search(r"(?i)(login|signin|sign-in|auth|sso)", location):
            return "inconclusive", f"redirected to authentication ({location}): {detail}"
        want = self._prior_status(spec)
        if want is None:
            return "inconclusive", "original proof status unknown; cannot tell remediation from a changed response"
        if status // 100 != want // 100:
            # not a verdict yet: a class change needs corroboration in retest()
            return "class_changed", f"status class changed {want} -> {status}: {detail}"
        return "fixed", f"fixed (input rejected): {detail}"

    @staticmethod
    def _prior_status(spec: dict) -> int | None:
        """Status the proof was recorded at, or None when it is unknown/unreadable."""
        want = spec.get("proof_status")
        if not isinstance(want, (int, str)):
            return None
        try:
            return int(want)
        except ValueError:
            return None

    def _corroborate_fixed(self, engagement_id, scope, category, spec, pr, first,
                           quote_detail, replay) -> tuple[str, str]:
        """A removed route (200 -> 404) is a fix only if the target is up and it repeats.

        Signals, all through the same scope-checked transport: the response is not a
        block page; a second replay agrees; a known-good same-origin URL still answers
        as it did during the engagement. Anything missing is inconclusive.
        """
        prior, status = self._prior_status(spec), first["status"]
        if prior is None:  # _changed_class never routes here without one
            return "inconclusive", "original proof status unknown; cannot tell remediation from a changed response"
        changed = f"status class changed {prior} -> {status}"
        blocked = _looks_blocked(first)
        if blocked:
            return "inconclusive", f"{changed} but the response looks like a block page ({blocked}); {quote_detail}"
        again = replay()
        if not again.get("ok"):
            return "inconclusive", f"{changed}; the repeat replay failed: {again.get('error')}"
        reproduced, again_detail = self._compare(spec.get("quote", ""), spec.get("quote_in", "body"), again)
        if reproduced:
            return "persists", f"quote still reproduced on the repeat replay: {again_detail}"
        if again["status"] != status:
            return "inconclusive", f"replays disagree ({status} then {again['status']}): no stable result"
        picked = self._pick_control(engagement_id, scope, category, pr["url"])
        if picked is None:
            return "inconclusive", (f"{changed} but no in-scope control URL from this engagement "
                                    f"can show the target is still up")
        control_url, control_prior = picked
        c = self.probe.request(engagement_id, scope, control_url, tool="retest_control",
                               follow_redirects=False, category=category)
        if not c.get("ok"):
            return "inconclusive", f"{changed} but the target looks down: control {control_url} failed ({c.get('error')})"
        if control_prior is not None and c["status"] // 100 != control_prior // 100:
            return "inconclusive", (f"{changed} but the target is unhealthy: control {control_url} "
                                    f"was {control_prior}, now {c['status']}")
        if control_prior is None and c["status"] // 100 != 2:
            return "inconclusive", (f"{changed} but control {control_url} answered {c['status']} "
                                    f"instead of 2xx: target may be degraded")
        return "fixed", (f"fixed (route removed): quote absent; {prior} -> {status} on 2 replays; "
                         f"control {control_url} still {c['status']}; no block page; "
                         f"evidence {c['evidence_id']}, {first['evidence_id']}, {again['evidence_id']}")

    def _pick_control(self, engagement_id, scope, category, proof_url) -> tuple[str, int | None] | None:
        """A same-origin URL this engagement already saw answer 2xx, else the root."""
        u = urlparse(proof_url)
        if not u.scheme or not u.netloc:
            return None
        origin = f"{u.scheme}://{u.netloc}".lower()
        seen = {proof_url.split("?")[0]}
        for row in self.db.query(
                "SELECT url, status FROM exchanges WHERE engagement_id=? "
                "AND status BETWEEN 200 AND 299 ORDER BY created_at DESC LIMIT 500",
                (engagement_id,)):
            url = row["url"]
            if url.split("?")[0] in seen:
                continue
            seen.add(url.split("?")[0])
            p = urlparse(url)
            if f"{p.scheme}://{p.netloc}".lower() != origin:
                continue
            if scope.check_url(url, category).allowed:
                return url, row["status"]
        root = f"{u.scheme}://{u.netloc}/"
        if root not in seen and scope.check_url(root, category).allowed:
            return root, None  # no prior status recorded: only a 2xx proves it is up
        return None
