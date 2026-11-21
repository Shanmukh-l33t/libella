"""In-process HTTP probe: the platform's own HTTP client.

Scope checked before every request AND on every redirect hop. Peer IP
verified after connect (closes DNS-rebinding at observation time). Every
exchange is captured as evidence with full request/response.
"""
import json
import time
import threading
from urllib.parse import urljoin

import httpx

from ..assessment_window import stored_stop_refusal
from ..db import DB, new_id
from ..evidence import EvidenceStore
from ..report import redact_headers
from ..scope import Scope

BODY_CAP = 256 * 1024
MAX_HOPS = 6

# A WAF/CDN interstitial ("checking your browser", Vercel challenge, captcha) is a
# NON-ANSWER: it carries none of the application's real headers or content. Treating
# it as the application produced a false "missing security headers" finding.
MITIGATION_HEADERS = {"x-vercel-mitigated": "vercel", "cf-mitigated": "cloudflare",
                      "x-amzn-waf-action": "aws-waf", "x-sucuri-block": "sucuri",
                      "x-datadome": "datadome", "x-iinfo": "imperva"}
MITIGATION_MARKERS = ("vercel security checkpoint", "verifying you are human",
                      "checking your browser before accessing", "enable javascript and cookies to continue",
                      "just a moment...", "attention required! | cloudflare", "challenge-platform",
                      "checking if the site connection is secure", "ddos protection by")


def mitigation(status: int, headers: dict, body: bytes) -> str | None:
    """Name the interstitial when the response is a challenge, not the application."""
    lower = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    for header, vendor in MITIGATION_HEADERS.items():
        value = lower.get(header)
        if value and ("challenge" in value or "captcha" in value or header == "cf-mitigated"
                      or header == "x-sucuri-block" or header == "x-datadome" or header == "x-iinfo"):
            return f"{vendor}:challenge"
    if status in (403, 429, 503):
        text = body[:8192].decode(errors="replace").lower()
        if "captcha" in text:
            return "captcha"
        if any(marker in text for marker in MITIGATION_MARKERS):
            return "waf:checkpoint"
    return None


def _peer_ip(resp) -> str | None:
    stream = resp.extensions.get("network_stream")
    if stream is None:
        return None
    try:
        peer = stream.get_extra_info("peername")
        return peer[0] if peer else None
    except Exception:
        return None


def _read_capped(resp, cap: int = BODY_CAP) -> tuple[bytes, bool]:
    """Read at most cap bytes; never buffer the whole response.

    One extra byte is read so "body was longer" is detectable without
    trusting Content-Length.
    """
    limit = cap + 1
    buf = bytearray()
    for chunk in resp.iter_bytes():
        if not chunk:
            continue
        buf += chunk[:limit - len(buf)]
        if len(buf) >= limit:
            return bytes(buf[:cap]), True
    return bytes(buf), False


class RateLimiter:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / max(rps, 0.1)
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.time()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.time()


class HttpProbe:
    def __init__(self, db: DB, evidence: EvidenceStore):
        self.db = db
        self.evidence = evidence
        self._limiters: dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

    def _limiter(self, engagement_id: str, rps: float) -> RateLimiter:
        with self._lock:
            if engagement_id not in self._limiters:
                self._limiters[engagement_id] = RateLimiter(rps)
            return self._limiters[engagement_id]

    def request(
        self,
        engagement_id: str,
        scope: Scope,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        body: str | bytes | None = None,
        category: str = "web",
        client: httpx.Client | None = None,
        intent_id: str | None = None,
        tool: str = "http_probe",
        follow_redirects: bool = True,
        body_cap: int = BODY_CAP,
    ) -> dict:
        """Issue one scoped request (following redirects with per-hop checks).

        Returns {ok, exchange_id, status, headers, body, url, peer_ip, ...}.
        A scope refusal returns ok=False with error=out_of_scope and is audited.
        """
        self._limiter(engagement_id, scope.rate_limit_rps).wait()
        method = method.upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            return {"ok": False, "error": f"method {method} not permitted"}
        own_client = client is None
        if own_client:
            client = httpx.Client(timeout=15, verify=False, trust_env=False)
        try:
            current = url
            hops = 0
            last = None
            while True:
                refusal = stored_stop_refusal(self.db, engagement_id)
                if refusal:
                    self.db.emit(engagement_id, "scope_refusal", {"reason": refusal, "tool": tool})
                    return {"ok": False, "error": refusal}
                decision = scope.check_url(current, category)
                if not decision.allowed:
                    self.db.emit(engagement_id, "scope_refusal",
                                 {"url": current, "reason": decision.reason, "tool": tool})
                    return {"ok": False, "error": f"out_of_scope: {decision.reason}",
                            "url": current, "decision": decision.reason}
                started = time.time()
                try:
                    with client.stream(method, current, headers=headers, content=body) as resp:
                        duration_ms = (time.time() - started) * 1000
                        peer_ip = _peer_ip(resp)
                        # post-connect peer verification (rebinding defense)
                        if peer_ip and decision.resolved_ips and peer_ip not in decision.resolved_ips:
                            recheck = scope.check_url(current, category)
                            if not recheck.allowed or peer_ip not in recheck.resolved_ips:
                                return {"ok": False, "error": "peer_ip_mismatch (possible DNS rebinding)",
                                        "url": current, "peer_ip": peer_ip}
                        content, truncated = _read_capped(resp, body_cap)
                        status_code = resp.status_code
                        resp_headers = dict(resp.headers)
                        final_url = str(resp.url)
                        location = resp.headers.get("location")
                        exchange = self._record(
                            engagement_id, intent_id, tool, method, current, resp,
                            content, headers, body, duration_ms, peer_ip,
                        )
                except httpx.HTTPError as e:
                    return {"ok": False, "error": f"request_failed: {type(e).__name__}: {e}",
                            "url": current}
                last = {
                    "ok": True, "exchange_id": exchange["id"], "evidence_id": exchange["evidence_id"],
                    "status": status_code,
                    "headers": resp_headers, "body": content.decode(errors="replace"),
                    "url": final_url, "peer_ip": peer_ip,
                    "duration_ms": round(duration_ms, 1),
                    "truncated": truncated,
                    # a challenge page is not the application: callers must not judge it
                    "mitigated": mitigation(status_code, resp_headers, content),
                }
                if (follow_redirects and status_code in (301, 302, 303, 307, 308)
                        and hops < MAX_HOPS and location):
                    current = urljoin(current, location)
                    hops += 1
                    if status_code == 303:
                        method = "GET"
                        body = None
                    continue
                return last
        finally:
            if own_client:
                client.close()

    def browser_request(self, engagement_id: str, scope: Scope, url: str,
                        category: str = "web", intent_id: str | None = None,
                        tool: str = "browser_fetch") -> dict:
        """Read one page through Chromium, for when the HTTP client is challenged.

        Same gates as request(): stop state, scope, evidence. The result is marked
        via="browser" so a proof replayed later uses the same transport.
        """
        from . import browser_fetch

        refusal = stored_stop_refusal(self.db, engagement_id)
        if refusal:
            self.db.emit(engagement_id, "scope_refusal", {"reason": refusal, "tool": tool})
            return {"ok": False, "error": refusal}
        decision = scope.check_url(url, category)
        if not decision.allowed:
            self.db.emit(engagement_id, "scope_refusal",
                         {"url": url, "reason": decision.reason, "tool": tool})
            return {"ok": False, "error": f"out_of_scope: {decision.reason}"}
        self._limiter(engagement_id, scope.rate_limit_rps).wait()
        try:
            got = browser_fetch.fetch(url)
        except Exception as exc:  # browser missing, navigation timeout, TLS error
            return {"ok": False, "error": f"browser_fetch failed: {type(exc).__name__}: {exc}",
                    "via": "browser"}

        class _Shim:
            status_code = got["status"]
            headers = got["headers"]

        exchange = self._record(engagement_id, intent_id, tool, "GET", url, _Shim(),
                                got["body"], {}, None, got["duration_ms"], None)
        return {"ok": True, "via": "browser", "exchange_id": exchange["id"],
                "evidence_id": exchange["evidence_id"], "status": got["status"],
                "headers": got["headers"], "body": got["body"].decode(errors="replace"),
                "url": got["url"], "duration_ms": got["duration_ms"], "truncated": False,
                "mitigated": mitigation(got["status"], got["headers"], got["body"])}

    def _record(self, engagement_id, intent_id, tool, method, url, resp,
                content, req_headers, body, duration_ms, peer_ip) -> dict:
        req_body = body.decode(errors="replace") if isinstance(body, bytes) else (body or "")
        # The blob on disk keeps only redacted header values; the live values live
        # in the sealed exchanges columns, which replay reads back through DB.
        req_h = redact_headers(dict(req_headers or {}))
        resp_h = redact_headers(dict(resp.headers))
        blob = {
            "request": {"method": method, "url": url,
                        "headers": req_h, "body": req_body[:BODY_CAP]},
            "response": {"status": resp.status_code, "headers": resp_h,
                         "body": content.decode(errors="replace"),
                         "body_sha256": __import__("hashlib").sha256(content).hexdigest()},
            "peer_ip": peer_ip, "duration_ms": round(duration_ms, 1),
        }
        ev = self.evidence.put_json(engagement_id, blob, "http_exchange")
        eid = new_id("ex")
        self.db.execute(
            "INSERT INTO exchanges(id, engagement_id, evidence_id, method, url, status, "
            "req_headers_json, resp_headers_json, req_body, duration_ms, tool, peer_ip, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, engagement_id, ev["id"], method, url, resp.status_code,
             self.db.seal(json.dumps(dict(req_headers or {}))),
             self.db.seal(json.dumps(dict(resp.headers))),
             req_body[:8192], round(duration_ms, 1), tool, peer_ip, time.time()),
        )
        return {"id": eid, "evidence_id": ev["id"]}
