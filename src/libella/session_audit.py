"""Authenticated session-lifecycle audit: fixation, logout invalidation, re-auth.

One operator-supplied identity, real requests. Each finding is a replayed
request whose response proves the claim, quoted verbatim from that response,
with the session cookie carried in the proof_request so the verifier can
reproduce it.
"""
import re
import secrets
from urllib.parse import urlencode

from .checks import _candidate

TOKEN_IN_URL = re.compile(r"(?i)(^|[?&])(sid|session|sessionid|token|access_token)=")


def _set_cookie(headers) -> str | None:
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie" and v.split("=", 1)[0].strip():
            return v
    return None


def _pair(set_cookie: str) -> tuple[str, str]:
    pair = set_cookie.split(";", 1)[0].strip()
    name, _, value = pair.partition("=")
    return name.strip(), value


def _quote(body: str, needle: str | None = None) -> str:
    body = body or ""
    if needle and needle in body:
        return needle
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    return (lines[0] if lines else body.strip())[:120]


def audit_session(db, evidence, probe, scope, engagement_id, auth_json, pipeline,
                  intent_id=None) -> dict:
    """Probe one identity's session lifecycle. See module docstring."""
    cfg = dict((auth_json or {}).get("session") or {})
    out = {"status": "assessed", "login_url": cfg.get("login_url"), "login": {},
           "candidates": [], "observations": [], "limitations": [], "errors": []}

    def limit(summary):
        out["limitations"].append(summary)
        pipeline.record_observation(engagement_id, intent_id, "session_audit_limitation", summary)

    def observe(kind, summary, evidence_id, quote=None, quote_in="body"):
        out["observations"].append({"kind": kind, "summary": summary,
                                    "evidence_id": evidence_id})
        pipeline.record_observation(engagement_id, intent_id, kind, summary,
                                    evidence_id=evidence_id, quote=quote)

    def submit(cand):
        res = pipeline.submit_candidate(engagement_id, cand, intent_id=intent_id)
        out["candidates"].append({**cand, "finding_id": res["id"], "deduped": res["deduped"]})

    def req(url, method="GET", headers=None, body=None, tool="session_audit"):
        return probe.request(engagement_id, scope, url, method=method, headers=headers,
                             body=body, category="web", intent_id=intent_id, tool=tool,
                             follow_redirects=False)

    missing = [k for k in ("login_url", "username", "password", "protected_url") if not cfg.get(k)]
    if missing:
        out["status"] = "not_configured"
        limit(f"session audit not run: auth_json['session'] lacks {', '.join(missing)} "
              "(no request was sent)")
        return out

    login_url, protected = cfg["login_url"], cfg["protected_url"]
    user_field = cfg.get("username_field", "username")
    pass_field = cfg.get("password_field", "password")
    username, password = cfg["username"], cfg["password"]
    form = {"Content-Type": "application/x-www-form-urlencoded"}

    def login(cookie: str | None = None):
        headers = dict(form)
        if cookie:
            headers["Cookie"] = cookie
        return req(login_url, method="POST", headers=headers,
                   body=urlencode({user_field: username, pass_field: password}),
                   tool="session_login")

    def cookie_header(name, value):
        return {"Cookie": f"{name}={value}"}

    # ---- control login: without a working session, nothing below is provable
    r = login()
    if not r.get("ok"):
        out["status"] = "blocked"
        out["errors"].append(f"login: {r.get('error')}")
        limit(f"session audit stopped at the login request: {r.get('error')} "
              "(scope refusal or transport failure: nothing was tested or claimed)")
        return out
    set_cookie = _set_cookie(r.get("headers"))
    if not set_cookie:
        out["status"] = "no_session_cookie"
        limit(f"the login response set no session cookie (status {r.get('status')}): "
              "fixation and logout replay are unprovable")
        return out
    name, value = _pair(set_cookie)
    login_ev = r["evidence_id"]
    out["login"] = {"status": r.get("status"), "cookie_name": name, "cookie_set": True}

    auth = req(protected, headers=cookie_header(name, value), tool="session_protected")
    anon = req(protected, tool="session_protected_anon")
    if not auth.get("ok") or auth.get("status") != 200 or (anon.get("ok") and anon.get("status") == 200):
        out["status"] = "protected_url_unverified"
        limit(f"the protected URL {protected} answers {auth.get('status')} with the session "
              f"cookie and {anon.get('status')} without it: authenticated vs anonymous cannot "
              "be told apart, so no session finding is claimed")
        return out
    marker = username if username in auth["body"] else _quote(auth["body"])

    # ---- session fixation: a chosen id must still be the authenticated one after login
    chosen = f"libella{secrets.token_hex(8)}"
    r = login(f"{name}={chosen}")
    after = _set_cookie(r.get("headers"))
    adopted = after is None or _pair(after)[1] == chosen
    if r.get("ok") and adopted:
        replay = req(protected, headers=cookie_header(name, chosen), tool="session_fixation_replay")
        if replay.get("ok") and replay.get("status") == 200:
            quote = _quote(replay["body"], marker)
            submit(_candidate(
                "Session fixation: the login accepts a client-chosen session id",
                "CWE-384", "A07:2021 Identification and Authentication Failures", "high", "high",
                login_url,
                f"With the pre-set cookie '{name}={chosen}' the login did not rotate the "
                f"session id, and {protected} returned 200 ('{quote}') for that id: an attacker "
                "who plants a session id controls the victim's authenticated session.",
                "The attacker fixes a known id, the victim logs in on it, and the attacker "
                "reuses the same id to act as the victim without any credential.",
                "Generate a fresh session id on every successful login and discard any "
                "client-supplied id; never trust a session token that existed before auth.",
                replay["evidence_id"], quote,
                {"method": "GET", "url": protected, "headers": cookie_header(name, chosen)},
                "session_fixation"))
            out["login"]["fixed_id"] = chosen

    # ---- re-authentication: a credential change must ask for the current password
    change_url = cfg.get("password_change_url")
    if change_url:
        body = urlencode({"new_password": password})  # same value: nothing changes, ever
        r = req(change_url, method="POST", body=body,
                headers={**form, **cookie_header(name, value)}, tool="session_reauth")
        if r.get("ok") and r.get("status") in (200, 201, 204, 302, 303):
            quote = _quote(r["body"])
            submit(_candidate(
                "Password change accepted without the current password",
                "CWE-620", "A07:2021 Identification and Authentication Failures", "medium", "high",
                change_url,
                f"POST {change_url} with only 'new_password' (no current-password field) "
                f"returned {r['status']} ('{quote}') for the logged-in session: possession of "
                "the session is enough to change the credential.",
                "A hijacked or fixated session is escalated to permanent account takeover: the "
                "attacker sets a password and keeps the account after the session is closed.",
                "Require the current password (and a fresh authentication) for any credential "
                "or email change; re-authenticate before sensitive actions.",
                r["evidence_id"], quote,
                {"method": "POST", "url": change_url, "headers": {**form, **cookie_header(name, value)},
                 "body": body}, "session_reauth"))
        elif r.get("ok") and r.get("status") in (400, 401, 403):
            pass  # the flow requires re-authentication: that is the control passing

    # ---- logout: the server-side session must die with the logout
    logout_url = cfg.get("logout_url")
    if logout_url:
        r = req(logout_url, headers=cookie_header(name, value), tool="session_logout")
        if r.get("ok") and r.get("status") in (404, 405):  # method differs per app
            r = req(logout_url, method="POST", headers=cookie_header(name, value),
                    tool="session_logout")
        loc = next((v for k, v in (r.get("headers") or {}).items() if k.lower() == "location"), None)
        replay = req(protected, headers=cookie_header(name, value), tool="session_logout_replay")
        if replay.get("ok") and replay.get("status") == 200:
            quote = _quote(replay["body"], marker)
            submit(_candidate(
                "Logout does not invalidate the server-side session",
                "CWE-613", "A07:2021 Identification and Authentication Failures", "medium", "high",
                logout_url,
                f"After POST/GET {logout_url} the old cookie '{name}' still returned 200 at "
                f"{protected} ('{quote}'): only the client-side cookie was dropped, the "
                "server-side session stayed valid.",
                "Anyone who captured the cookie (shared machine, proxy, XSS, fixated id) keeps "
                "a working session after the user logs out.",
                "Destroy the server-side session record on logout and reject its id afterwards; "
                "expire the cookie and set an idle/absolute timeout.",
                replay["evidence_id"], quote,
                {"method": "GET", "url": protected, "headers": cookie_header(name, value)},
                "session_logout"))
        elif not replay.get("ok") or replay.get("status") != 200:
            pass  # invalidated: the control passing
        if loc and (value in loc or TOKEN_IN_URL.search(loc)):
            observe("session_token_in_url",
                    f"logout redirects to a URL carrying the session token ({loc})",
                    r.get("evidence_id") or login_ev, quote=loc, quote_in="header_fact")

    # ---- cookie scope: observation only (the header checks own the finding)
    low = set_cookie.lower()
    # shortcut: Secure is skipped because a plain-http lab could never send it back;
    # checks.cookie_flags judges the Secure flag where the transport allows it.
    lacking = [f for f in ("HttpOnly", "SameSite") if f.lower() not in low]
    if lacking:
        observe("session_cookie_scope",
                f"session cookie '{name}' is set without {', '.join(lacking)}",
                login_ev, quote=f"{name}|{','.join(lacking)}", quote_in="cookie_fact")

    db.emit(engagement_id, "session_audit_complete",
            {"login_url": login_url, "candidates": len(out["candidates"]),
             "observations": len(out["observations"])})
    return out
