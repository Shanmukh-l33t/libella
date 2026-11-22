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
from ..egress import Egress, PinnedTransport
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


def _read_capped(resp, cap: int = BODY_CAP, should_stop=None) -> tuple[bytes, bool, bool]:
    """Read at most cap bytes; never buffer the whole response.

    One extra byte is read so "body was longer" is detectable without
    trusting Content-Length. A pause, cancel or closed window mid-response
    aborts the read: the socket must not keep delivering a target's body.
    """
    limit = cap + 1
    buf = bytearray()
    for chunk in resp.iter_bytes():
        if should_stop is not None and should_stop():
            return bytes(buf[:cap]), False, True
        if not chunk:
            continue
        buf += chunk[:limit - len(buf)]
        if len(buf) >= limit:
            return bytes(buf[:cap]), True, False
    return bytes(buf), False, False


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
        egress = Egress(self.db, scope, engagement_id, tool=tool, category=category)
        current = url
        hops = 0
        last = None
        while True:
            refusal = stored_stop_refusal(self.db, engagement_id)
            if refusal:
                self.db.emit(engagement_id, "scope_refusal", {"reason": refusal, "tool": tool})
                return {"ok": False, "error": refusal}
            # one decision per hop, on exactly the address this hop dials
            decision = egress.decide_url(current, category=category)
            if not decision.allowed:
                return {"ok": False, "error": f"out_of_scope: {decision.reason}",
                        "url": current, "decision": decision.reason}
            hop = client
            if hop is None:
                # the transport dials decision.ip: a DNS answer that changes
                # between the check and the connect cannot move the socket
                hop = httpx.Client(timeout=15, verify=False, trust_env=False,
                                   transport=PinnedTransport(decision.host, decision.ip,
                                                             verify=False, trust_env=False))
            started = time.time()
            try:
                with hop.stream(method, current, headers=headers, content=body) as resp:
                    duration_ms = (time.time() - started) * 1000
                    peer_ip = _peer_ip(resp)
                    # post-connect peer verification (rebinding defense)
                    if peer_ip and decision.ips and peer_ip not in decision.ips:
                        return {"ok": False, "error": "peer_ip_mismatch (possible DNS rebinding)",
                                "url": current, "peer_ip": peer_ip}
                    content, truncated, stopped = _read_capped(
                        resp, body_cap,
                        should_stop=lambda: stored_stop_refusal(self.db, engagement_id))
                    if stopped:
                        refusal = stored_stop_refusal(self.db, engagement_id) or "stopped"
                        self.db.emit(engagement_id, "scope_refusal",
                                     {"reason": refusal, "tool": tool, "url": current})
                        return {"ok": False, "error": refusal, "url": current,
                                "partial": True}
                    status_code = resp.status_code
                    resp_headers = dict(resp.headers)
                    # dict() keeps only the LAST duplicate header, which for
                    # Set-Cookie means every cookie but one goes unchecked
                    try:
                        jars = resp.headers.get_list("set-cookie")
                    except AttributeError:  # pragma: no cover - older httpx
                        jars = []
                    if len(jars) > 1:
                        resp_headers["set-cookie-all"] = "\n".join(jars)
                    # the record keeps the AUTHORIZED url: the transport dials the
                    # pinned IP, so resp.url would name an address nobody authorized
                    # (peer_ip records the address that actually answered)
                    final_url = current
                    location = resp.headers.get("location")
                    exchange = self._record(
                        engagement_id, intent_id, tool, method, current, resp,
                        content, headers, body, duration_ms, peer_ip,
                    )
            except httpx.HTTPError as e:
                return {"ok": False, "error": f"request_failed: {type(e).__name__}: {e}",
                        "url": current}
            finally:
                if client is None:
                    hop.close()
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

    def browser_request(self, engagement_id: str, scope: Scope, url: str,
                        category: str = "web", intent_id: str | None = None,
                        tool: str = "browser_fetch") -> dict:
        """Read one page through Chromium, for when the HTTP client is challenged.

        Same gates as request(): stop state, scope, evidence. Navigation, every
        subresource it pulls and everything it opens in this context go through
        the same egress policy (browser_crawl.fetch_scoped). The result is marked
        via="browser" so a proof replayed later uses the same transport.
        """
        from ..browser_crawl import fetch_scoped

        egress = Egress(self.db, scope, engagement_id, tool=tool, category=category)
        decision = egress.decide_url(url, category=category)
        if not decision.allowed:
            return {"ok": False, "error": f"out_of_scope: {decision.reason}", "via": "browser"}
        self._limiter(engagement_id, scope.rate_limit_rps).wait()
        try:
            got = fetch_scoped(url, egress)
        except Exception as exc:  # browser missing, navigation timeout, TLS error
            if egress.denied:
                return {"ok": False, "via": "browser",
                        "error": f"out_of_scope: {egress.summary()['blocked_hosts']} refused "
                                 "by the egress policy"}
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
