"""Diagnostic for a target application's API credentials.

Answers "can Libella reach this endpoint and does this credential work?" without
assuming a 200 proves authorization. One bounded request, scope-enforced, TLS
verified, redirects refused, and the credential value is never returned or logged.
This is a setup-time check against an explicitly authorized target, not an assessment.
"""
import base64

import httpx

from .scope import Scope

TIMEOUT = 10.0
TYPES = {"bearer", "header", "basic", "cookie", "none"}


def _auth_headers(cred: dict) -> dict:
    kind = cred.get("type", "none")
    if kind == "bearer":
        return {"Authorization": f"Bearer {cred.get('token', '')}"}
    if kind == "header":
        name = cred.get("name") or "Authorization"
        return {name: cred.get("value", "")}
    if kind == "basic":
        raw = f"{cred.get('username', '')}:{cred.get('password', '')}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    if kind == "cookie":
        return {"Cookie": cred.get("value", "")}
    return {}


def check_target_credentials(scope: Scope, url: str, credential: dict,
                            expect_substring: str | None = None) -> dict:
    """Return a redacted, honest diagnostic. Never includes the credential value."""
    out = {"url": url, "reachable": False, "tls": "n/a", "status": None,
           "auth": "error", "identity_confirmed": False, "detail": ""}
    if not isinstance(credential, dict) or credential.get("type", "none") not in TYPES:
        out["detail"] = "Unknown credential type; use bearer, header, basic, cookie or none."
        return out
    if not isinstance(url, str) or not url:
        out["detail"] = "A target URL is required."
        return out
    category = "api" if "api" in scope.categories else next(iter(scope.categories), "web")
    decision = scope.check_url(url, category)
    if not decision.allowed:
        out["auth"] = "refused"
        out["detail"] = f"Target is outside the authorized scope: {decision.reason}"
        return out
    try:
        headers = _auth_headers(credential)
        with httpx.Client(timeout=TIMEOUT, verify=True, trust_env=False,
                          follow_redirects=False) as client:
            resp = client.get(url, headers=headers)
        out["reachable"] = True
        out["status"] = resp.status_code
        out["tls"] = "valid" if url.startswith("https://") else "n/a"
        code = resp.status_code
        if code in (401, 403):
            out["auth"] = "rejected"
            out["detail"] = "The endpoint rejected the credential (401/403). Check the key, token or scope."
        elif 300 <= code < 400:
            out["auth"] = "redirect"
            out["detail"] = "The endpoint redirected (often to a login). The credential may be missing or expired."
        elif 200 <= code < 300:
            body = resp.text[:20000]
            if expect_substring and expect_substring in body:
                out["auth"] = "accepted"
                out["identity_confirmed"] = True
                out["detail"] = "The endpoint returned success and the expected identity evidence."
            else:
                out["auth"] = "responded_success"
                out["detail"] = ("The endpoint returned success, but identity was not confirmed. "
                                 "A 200 alone does not prove the credential is authorized; supply an "
                                 "expected identity marker to confirm.")
        elif code >= 500:
            out["auth"] = "server_error"
            out["detail"] = "The endpoint returned a server error; this is not an authentication result."
        else:
            out["auth"] = "unknown"
            out["detail"] = f"Unexpected status {code}; could not determine authentication."
    except httpx.HTTPError as exc:
        text = str(exc).lower()
        if "ssl" in text or "certificate" in text or "tls" in text:
            out["tls"] = "invalid"
            out["detail"] = "TLS certificate verification failed; the credential was not sent."
        else:
            out["detail"] = f"Could not reach the endpoint: {type(exc).__name__}."
    return out
