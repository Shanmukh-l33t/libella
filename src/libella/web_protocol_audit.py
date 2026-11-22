"""Web protocol-level checks: host header injection, cache poisoning, HPP, verbs.

Every vector is opt-in through `auth_json['test_hints']['web_protocol']`; a key
that is absent means "not declared", so that vector sends no request and says so
as a limitation. A candidate always carries the control exchange that proves the
difference and a verbatim quote, so the verifier can replay it.

Request smuggling is detection only and strictly opt-in: it fires only when the
hint asks for it, uses a raw socket that must pass Egress.decide, and reports a
finding only on an unambiguous desync (the canary request answered on a
connection it was not sent on). Otherwise it is an observation with timings.
"""
import json
import re
import time
import uuid
from socket import create_connection as _connect
from urllib.parse import quote_plus, urljoin, urlparse

from .checks import _candidate
from .egress import Egress

HOST_HEADERS = ("X-Forwarded-Host", "X-Host")
METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
CACHE_INDICATORS = ("x-cache", "age", "cf-cache-status", "x-proxy-cache", "x-served-by")
DENIED = (401, 403)   # a protection refused this verb; 405 is "not implemented"
RAW_CAP = 65536


def _canary() -> str:
    return "libella" + uuid.uuid4().hex[:10]


def _hdr(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return None


def _quote(text: str, needle: str | None = None, pad: int = 40) -> str:
    """A verbatim window of `text` around `needle`: readable and replayable."""
    body = (text or "").strip()
    if needle and needle in body:
        i = body.index(needle)
        return body[max(0, i - pad):i + len(needle) + pad].strip()
    return body[:160]


def _abs_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s\"'<>]+", text or "")


def _url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _raw(decision, payload: bytes, timeout: float = 5.0) -> tuple[bytes, dict]:
    """One raw connection, dialing the address the egress policy authorized."""
    started = time.time()
    sock = _connect((decision.ip, decision.port), timeout=timeout)
    try:
        sock.settimeout(1.5)
        sock.sendall(payload)
        buf = bytearray()
        try:
            while len(buf) < RAW_CAP:
                chunk = sock.recv(RAW_CAP)
                if not chunk:
                    break
                buf += chunk
        except OSError:  # a timeout is a normal end for a kept-open connection
            pass
    finally:
        sock.close()
    return bytes(buf), {"duration_ms": round((time.time() - started) * 1000, 1),
                        "bytes": len(buf)}


def audit_web_protocol(db, evidence, probe, scope, engagement_id: str, auth_json: dict,
                       pipeline, intent_id: str | None = None) -> dict:
    """Probe the declared URL for protocol-level weaknesses. See module docstring."""
    hints = ((auth_json or {}).get("test_hints") or {}).get("web_protocol") or {}
    url = hints.get("url")
    out = {"status": "assessed", "url": url, "candidates": [], "observations": [],
           "limitations": [], "errors": []}

    def limit(summary: str):
        out["limitations"].append(summary)
        pipeline.record_observation(engagement_id, intent_id, "web_protocol_limitation", summary)

    def observe(kind: str, summary: str, evidence_id: str | None = None, quote: str | None = None):
        out["observations"].append({"kind": kind, "summary": summary, "evidence_id": evidence_id})
        pipeline.record_observation(engagement_id, intent_id, kind, summary,
                                    evidence_id=evidence_id, quote=quote)

    def submit(cand, extra_evidence=()):
        cand["evidence_ids"] = [*cand["evidence_ids"], *[e for e in extra_evidence if e]]
        res = pipeline.submit_candidate(engagement_id, cand, intent_id=intent_id)
        out["candidates"].append({**cand, "finding_id": res["id"], "deduped": res["deduped"]})

    def req(target, method="GET", headers=None, tool="protocol_check"):
        return probe.request(engagement_id, scope, target, method=method, headers=headers,
                             category="web", intent_id=intent_id, tool=tool,
                             follow_redirects=False)

    if not url:
        out["status"] = "not_configured"
        limit("web protocol audit not run: auth_json['test_hints']['web_protocol']['url'] is "
              "not declared (no request was sent)")
        return out
    decision = scope.check_url(url, "web")
    if not decision.allowed:
        out["status"] = "blocked"
        limit(f"web protocol audit not run: {url} is out of scope ({decision.reason}); "
              "no request was sent")
        return out

    # ---- host header injection -------------------------------------------
    def host_injection():
        host = hints.get("host_header")
        if not host:
            limit("host header injection not tested: test_hints.web_protocol.host_header "
                  "is not declared (no request was sent)")
            return
        targets = [(url, "declared url")]
        if hints.get("reset_path"):
            targets.append((urljoin(url, hints["reset_path"]),
                            f"declared password-reset link {hints['reset_path']}"))
        attempts = [(name, {name: host}) for name in HOST_HEADERS]
        attempts += [("Forwarded", {"Forwarded": f"host={host}"}), ("Host", {"Host": host})]
        for target, label in targets:
            reflected_bare = proven = None
            for name, headers in attempts:
                r = req(target, headers=headers, tool="protocol_host")
                if not r.get("ok"):
                    out["errors"].append(f"host header {name} on {target}: {r.get('error')}")
                    continue
                location = _hdr(r["headers"], "location") or ""
                body = r["body"] or ""
                if host.lower() in location.lower():
                    submit(_candidate(
                        f"Host header injection: {name} controls the redirect at {target}",
                        "CWE-601", "A01:2021 Broken Access Control", "medium", "high", target,
                        f"{label}: {name}: {host} was reflected into the redirect Location by the "
                        "server; the client-chosen host is trusted when building an absolute URL.",
                        "Any unauthenticated caller steers the victim's redirect (and any "
                        "absolute link built from it) to a host they own.",
                        "Never build absolute URLs from request headers: use a configured "
                        "canonical origin, and ignore X-Forwarded-Host unless a trusted proxy "
                        "sets it.",
                        r["evidence_id"], f"Location: {location}",
                        {"method": "GET", "url": target, "headers": headers},
                        f"hostheader:{target}:{name}", quote_in="header_fact"))
                    proven = name
                    break
                absolute = next((u for u in _abs_urls(body) if _url_host(u) == host.lower().rstrip(".")),
                                None)
                if absolute:
                    submit(_candidate(
                        f"Host header injection: {name} injected into an absolute link at {target}",
                        "CWE-601", "A01:2021 Broken Access Control", "medium", "high", target,
                        f"{label}: {name}: {host} produced the absolute URL {absolute} in the "
                        "response body; the client-chosen host is trusted in a generated link.",
                        "An attacker poisons links the application hands to its own users "
                        "(password reset, invites, absolute redirects) toward their host.",
                        "Build links from a configured canonical origin; never from a request "
                        "header.",
                        r["evidence_id"], absolute,
                        {"method": "GET", "url": target, "headers": headers},
                        f"hostheader:{target}:{name}"))
                    proven = name
                    break
                if not reflected_bare and host in body:
                    reflected_bare = (name, r)
            if reflected_bare:
                name, r = reflected_bare
                observe("web_protocol_host", f"{label}: {name} value appears in the response body "
                        "of " + target + " without forming a link; reflection alone is not "
                        "injection and is not reported", r["evidence_id"], _quote(r["body"], host))
            elif not proven:
                observe("web_protocol_host", f"{label}: no injected host value reached a Location "
                        "header or an absolute URL at " + target + "; nothing is claimed")

    # ---- web cache poisoning ---------------------------------------------
    def cache_poisoning():
        header = hints.get("cache_probe")
        if not header:
            limit("web cache poisoning not tested: test_hints.web_protocol.cache_probe "
                  "is not declared (no request was sent)")
            return
        name = (header.get("header") if isinstance(header, dict) else header) or ""
        if not name:
            limit("web cache poisoning not tested: the cache_probe hint names no header "
                  "(no request was sent)")
            return
        canary = _canary()
        poison = req(url, headers={name: canary}, tool="protocol_cache_poison")
        read = req(url, tool="protocol_cache_read")
        if not poison.get("ok") or not read.get("ok"):
            out["errors"].append(f"cache probe on {url}: "
                                 f"{poison.get('error') or read.get('error')}")
            return
        low = {k.lower(): str(v) for k, v in read["headers"].items()}
        flags = {k: low[k] for k in CACHE_INDICATORS if k in low}
        note = {k: low[k] for k in ("cache-control", "vary", *CACHE_INDICATORS) if k in low}
        hit = canary in (read["body"] or "") or canary in str(read["headers"])
        if hit:
            submit(_candidate(
                f"Web cache poisoning: unkeyed '{name}' served to a request that did not send it",
                "CWE-349", "A05:2021 Security Misconfiguration", "high", "high", url,
                f"A response carrying {name}: {canary} was stored and then served to a second "
                f"request that did not send that header (cache headers: "
                f"{json.dumps(note) or 'none'}).",
                "One caller's input is served to every other caller of the path; the injected "
                "value reaches users who never sent it (stored XSS, link poisoning, data bleed).",
                "Key the cache on every input that shapes the response (or strip it); never "
                "store a response that varies on client headers without Vary.",
                read["evidence_id"], _quote(read["body"], canary),
                {"method": "GET", "url": url},
                f"cachepoison:{url}:{name}"), extra_evidence=[poison["evidence_id"]])
            observe("web_protocol_cache", f"cache served the poisoned representation for {url} "
                    f"({json.dumps(note) or 'no cache identity header'})", read["evidence_id"])
        elif flags:
            observe("web_protocol_cache", f"cache headers present on {url} ({json.dumps(note)}) "
                    "but the canary from the first request was not served to the second")
        else:
            limit(f"web cache poisoning not testable at {url}: no cache identity header "
                  f"({', '.join(CACHE_INDICATORS)}) on either response and no canary was "
                  "retained; a cacheless response is not a pass")

    # ---- HTTP parameter pollution ----------------------------------------
    def hpp():
        spec = hints.get("param")
        if not spec:
            limit("HTTP parameter pollution not tested: test_hints.web_protocol.param "
                  "is not declared (no request was sent)")
            return
        if isinstance(spec, str):
            name, valid, invalid = spec, _canary() + "a", _canary() + "b"
        else:
            name, valid, invalid = spec.get("name"), spec.get("valid"), spec.get("invalid")
        if not (name and valid and invalid):
            limit("HTTP parameter pollution not tested: the param hint needs a name, a valid "
                  "and an invalid value (no request was sent)")
            return
        sep = "&" if "?" in url else "?"
        q = lambda v: f"{url}{sep}{name}={quote_plus(str(v))}"  # noqa: E731
        control_ok = req(q(valid), tool="protocol_hpp_control")
        control_bad = req(q(invalid), tool="protocol_hpp_control")
        dup = req(f"{url}{sep}{name}={quote_plus(str(valid))}&{name}={quote_plus(str(invalid))}",
                  tool="protocol_hpp_dup")
        if not dup.get("ok"):
            out["errors"].append(f"HPP probe on {url}: {dup.get('error')}")
            return
        dup_body = dup["body"] or ""
        bad_status = int(control_bad.get("status") or 0)
        bypassed = (dup["status"] in (200, 201, 202, 204) and str(invalid) in dup_body
                    and 400 <= bad_status < 500
                    and (control_bad.get("body") or "") != dup_body
                    and (control_ok.get("body") or "") != dup_body)
        if bypassed:
            submit(_candidate(
                f"HTTP parameter pollution: duplicated '{name}' bypasses validation",
                "CWE-235", "A03:2021 Injection", "high", "high", url,
                f"{url} refused the single value {name}={invalid} "
                f"(status {control_bad.get('status')}) but answered "
                f"{dup['status']} for {name}={valid}&{name}={invalid}, and the action used the "
                f"second copy: the validated first copy and the executed last copy differ.",
                "Any caller smuggles a value past input validation: the check sees one value, "
                "the business action applies another.",
                "Parse duplicate parameters once, reject ambiguous repeats, and validate the "
                "exact value the action uses.",
                dup["evidence_id"], _quote(dup["body"], str(invalid)),
                {"method": "GET", "url": f"{url}{sep}{name}={quote_plus(str(valid))}"
                                          f"&{name}={quote_plus(str(invalid))}"},
                f"hpp:{url}:{name}"),
                extra_evidence=[control_bad["evidence_id"], control_ok["evidence_id"]])
        else:
            observe("web_protocol_hpp", f"duplicated '{name}' did not change the outcome on {url} "
                    f"(control {control_bad.get('status')}, duplicate {dup['status']})",
                    dup["evidence_id"])

    # ---- method / verb tampering -----------------------------------------
    def method_tampering():
        spec = hints.get("methods")
        if not spec:
            limit("method tampering not tested: test_hints.web_protocol.methods "
                  "is not declared (no request was sent)")
            return
        if isinstance(spec, dict):
            target, marker = urljoin(url, spec.get("path") or ""), spec.get("protected_marker")
        else:
            target, marker = (urljoin(url, spec) if isinstance(spec, str) else url), None
        benign = req(target, tool="protocol_method_control")
        if not benign.get("ok"):
            out["errors"].append(f"method control on {target}: {benign.get('error')}")
            return
        if benign["status"] not in DENIED:
            limit(f"method tampering not tested at {target}: the benign GET answered "
                  f"{benign['status']}, not 401/403, so a reachable verb proves nothing")
            return
        reached = None
        for method in METHODS:
            if method == "GET":
                continue
            r = req(target, method=method, tool="protocol_method")
            if not r.get("ok"):
                out["errors"].append(f"{method} {target}: {r.get('error')}")
                continue
            if method == "HEAD" or method == "OPTIONS":
                if r["status"] not in DENIED:
                    # no body to prove protected content: a difference, not a finding
                    observe("web_protocol_method",
                            f"{method} {target} answered {r['status']} where GET was refused "
                            f"{benign['status']}; no body content, so nothing is claimed",
                            r["evidence_id"])
                continue
            if (r["status"] in (200, 201, 202, 204) and (r["body"] or "").strip()
                    and r["body"] != benign["body"]
                    and (marker is None or marker in r["body"])):
                reached = (method, r)
                break
        if reached:
            method, r = reached
            submit(_candidate(
                f"Method tampering: {method} reaches a protected action refused to GET at {target}",
                "CWE-650", "API5:2023 Broken Function Level Authorization", "high", "high", target,
                f"GET {target} was refused {benign['status']} while {method} returned "
                f"{r['status']} with the protected content: the protection is attached to the "
                "benign method, not to the action.",
                "Anyone switching the verb reaches the same action the GET path protects, "
                "bypassing the authorization or method allowlist.",
                "Authorize the action behind every verb that routes to it; reject methods the "
                "route does not implement.",
                r["evidence_id"], _quote(r["body"]),
                {"method": method, "url": target},
                f"method:{target}"), extra_evidence=[benign["evidence_id"]])
        override_method = reached[0] if reached else "PUT"
        over = req(target, headers={"X-HTTP-Method-Override": override_method},
                   tool="protocol_method_override")
        if over.get("ok") and over["status"] in (200, 201, 202, 204) and (over["body"] or "").strip() \
                and over["body"] != benign["body"] and (marker is None or marker in over["body"]):
            submit(_candidate(
                f"Method override: X-HTTP-Method-Override reaches {override_method} at {target}",
                "CWE-650", "API5:2023 Broken Function Level Authorization", "high", "high", target,
                f"GET {target} was refused {benign['status']}, but GET carrying "
                f"X-HTTP-Method-Override: {override_method} returned {over['status']} with the "
                "protected content: the override header is honoured before authorization.",
                "A client that cannot send the verb still reaches the protected action through "
                "a plain GET a proxy or WAF will let through.",
                "Ignore X-HTTP-Method-Override unless a trusted gateway sets it, and authorize "
                "the resolved method.",
                over["evidence_id"], _quote(over["body"]),
                {"method": "GET", "url": target,
                 "headers": {"X-HTTP-Method-Override": override_method}},
                f"methodoverride:{target}"), extra_evidence=[benign["evidence_id"]])
        else:
            observe("web_protocol_method", f"X-HTTP-Method-Override was not honoured at {target} "
                    f"(status {over.get('status')})", over.get("evidence_id"))

    # ---- request smuggling: detection only, opt-in -----------------------
    def smuggling():
        if not hints.get("smuggling"):
            limit("request smuggling not attempted: opt-in test_hints.web_protocol.smuggling "
                  "is not set (no raw socket was opened)")
            return
        p = urlparse(url)
        scheme, host = (p.scheme or "http").lower(), p.hostname or ""
        port = p.port or (443 if scheme == "https" else 80)
        if scheme != "http":
            limit("request smuggling detection skipped: only plain-http raw sockets are "
                  "implemented (no TLS wrap); no payload was sent")
            return
        egress = Egress(db, scope, engagement_id, tool="protocol_smuggle", category="web")
        decision = egress.decide(host, port, "http")
        if not decision.allowed:
            limit(f"request smuggling detection refused by egress: {decision.reason} "
                  "(no connection was opened)")
            return
        canary = _canary()
        chunk = f"0\r\n\r\nGET /{canary} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(chunk.encode())}\r\nTransfer-Encoding: chunked\r\n\r\n"
                   f"{chunk}").encode()
        probe_req = (f"GET /probe-{canary} HTTP/1.1\r\nHost: {host}\r\n"
                     "Connection: close\r\n\r\n").encode()
        sock = None
        try:
            started = time.time()
            sock = _connect((decision.ip, decision.port), timeout=5)
            sock.settimeout(1.5)
            sock.sendall(payload)
            try:
                first = sock.recv(RAW_CAP)
            except OSError:
                first = b""
            keepalive_ms = round((time.time() - started) * 1000, 1)
            # the probe goes on its own connection, while the poisoned one stays open
            second, second_t = _raw(decision, probe_req)
        except OSError as exc:
            limit(f"request smuggling detection not performed: {decision.ip}:{decision.port} "
                  f"did not accept the raw connection ({exc})")
            return
        finally:
            if sock is not None:
                sock.close()
        blob = {"request": {"payload": payload.decode(errors="replace"),
                            "probe": probe_req.decode(errors="replace")},
                "response": {"poisoned": first.decode(errors="replace"),
                             "probe": second.decode(errors="replace")},
                "timings": {"keepalive_ms": keepalive_ms, **second_t}}
        ev = evidence.put_json(engagement_id, blob, "http_raw")
        if canary.encode() in second:
            submit(_candidate(
                f"HTTP request smuggling: desync canary answered on an unrelated connection at {url}",
                "CWE-444", "A03:2021 Injection", "high", "high", url,
                f"A CL.TE preamble left a request for /{canary} queued; the next connection, "
                f"which sent /probe-{canary}, received the response for /{canary} instead "
                f"(timings {json.dumps(blob['timings'])}).",
                "Client requests cross connections: one user can capture another's response or "
                "bypass front-end access controls.",
                "Reject requests carrying both Transfer-Encoding and Content-Length, normalize "
                "before routing, and keep the connection model consistent across hops.",
                ev["id"], _quote(second.decode(errors="replace").split("\r\n\r\n", 1)[-1], canary),
                {"method": "RAW", "url": url,
                 "headers": {"Transfer-Encoding": "chunked", "Content-Length": str(len(chunk))}},
                f"smuggling:{url}"))
        else:
            observe("web_protocol_smuggling",
                    f"request smuggling detection at {url}: CL.TE preamble sent to "
                    f"{decision.ip}:{decision.port}; the probe connection was answered on its "
                    f"own (timings {json.dumps(blob['timings'])}), so no desync is claimed",
                    ev["id"])

    host_injection()
    cache_poisoning()
    hpp()
    method_tampering()
    smuggling()

    db.emit(engagement_id, "web_protocol_audit_complete",
            {"url": url, "candidates": len(out["candidates"]),
             "observations": len(out["observations"]), "limitations": len(out["limitations"])})
    return out
