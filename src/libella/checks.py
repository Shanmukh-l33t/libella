"""Deterministic web checks. Code performs the test; evidence is captured.

Each check returns candidate findings with a replayable proof_request and
a verbatim quote. Nothing here trusts scanner banners or model prose.
"""
import json
import re
import uuid
from urllib.parse import parse_qsl, urlparse

from .controls import COOKIE_CONTROLS, HEADER_CONTROLS
from .proof import canonical_document, with_param
from .tools.http_probe import HttpProbe

CANARY = "libella" + uuid.uuid4().hex[:6]

SQLI_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "sqlstate[", "sqlite3.operationalerror",
    "sqlite_error", "pg_query():", "psqlexception", "ora-01756", "microsoft ole db provider for sql server",
    "odbc sql server driver", "syntax error at or near", "unterminated string",
]

SENSITIVE_PATHS = [
    "/debug", "/.env", "/.git/config", "/server-status", "/actuator", "/actuator/env",
    "/phpinfo.php", "/elmah.axd", "/trace.axd", "/web.config", "/.DS_Store",
    "/api/users", "/uploads/", "/backup.zip", "/.svn/entries", "/config.php.bak",
    "/wp-config.php.bak", "/api/v1/users", "/graphql", "/.well-known/security.txt",
]

SEC_HEADERS = {
    "content-security-policy": ("CSP", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "low"),
    "x-frame-options": ("X-Frame-Options", "medium"),
    "strict-transport-security": ("HSTS", "medium"),
    "referrer-policy": ("Referrer-Policy", "low"),
}


def _candidate(title, cwe, owasp, severity, confidence, endpoint, description,
               impact, remediation, evidence_id, quote, proof_request, dedup_key,
               quote_in="body", controls=(), proof=None):
    return {
        "title": title, "cwe": cwe, "owasp": owasp, "severity": severity,
        "confidence": confidence, "endpoint": endpoint, "description": description,
        "impact": impact, "remediation": remediation,
        "evidence_ids": [evidence_id], "quote": quote, "quote_in": quote_in,
        "proof_request": proof_request, "dedup_key": dedup_key,
        # what this check actually established, as typed prerequisites (proof.py).
        # A finding whose contract is incomplete is refused by the verifier, never
        # filled in with a guessed value.
        "proof": {**({"assertion": description}), **(proof or {})},
        # structured control ids this candidate asserts failed (controls.py)
        "controls": sorted(set(controls)),
    }


class WebChecks:
    def __init__(self, probe: HttpProbe, engagement_id: str, scope, db=None):
        self.probe = probe
        # optional: reading the engagement's own traffic needs the store, and a check
        # without it simply has less evidence to work from
        self.db = db
        self.eng = engagement_id
        self.scope = scope
        self.mitigated: list[str] = []  # challenges seen: those checks are inconclusive
        self.browser_urls: set[str] = set()  # pages read through the browser fallback

    def _proof(self, url: str, **extra) -> dict:
        """Proof request for a candidate, replayed later over the same transport."""
        proof = {"method": "GET", "url": url, **extra}
        if url in self.browser_urls:
            proof["via"] = "browser"
        return proof

    def _req(self, url, method="GET", headers=None, body=None, client=None, tool="check"):
        r = self.probe.request(self.eng, self.scope, url, method=method,
                               headers=headers, body=body, client=client, tool=tool)
        if r.get("ok") and r.get("mitigated") and method.upper() == "GET":
            # the CDN challenged the HTTP client; read the same page as a browser would
            alt = self.probe.browser_request(self.eng, self.scope, url, tool=f"{tool}_browser")
            if alt.get("ok") and not alt.get("mitigated"):
                self.browser_urls.add(url)
                return alt
        if r.get("mitigated"):
            # the target answered with a WAF/CDN challenge: judge nothing from it
            self.mitigated.append(f"{tool}: {r['mitigated']}")
            return {**r, "ok": False, "error": f"target_mitigated: {r['mitigated']}"}
        return r

    def security_headers(self, url: str) -> list[dict]:
        r = self._req(url, tool="headers_check")
        if not r.get("ok"):
            return []
        missing = [(name, sev) for h, (name, sev) in SEC_HEADERS.items()
                   if h not in {k.lower() for k in r["headers"]}]
        if not missing:
            return []
        names = ", ".join(n for n, _ in missing)
        sev = "medium" if any(s == "medium" for _, s in missing) else "low"
        quote = f"missing: {names}"
        # "" and "/" are the same document: keying on the raw URL produced two findings for
        # one missing-header condition when an agent probed both forms.
        return [_candidate(
            f"Missing security headers ({names})", "CWE-693", "A05:2021 Security Misconfiguration",
            sev, "high", url,
            f"Response lacks: {names}.",
            "Increased exposure to clickjacking, MIME sniffing, protocol downgrade, and XSS impact.",
            "Set the missing headers at the server or application layer.",
            r["evidence_id"], quote, self._proof(url),
            f"headers:{canonical_document(url)}", quote_in="header_fact",
            controls=[HEADER_CONTROLS[h] for h in SEC_HEADERS
                      if h not in {k.lower() for k in r["headers"]}],
            proof={"document": canonical_document(url),
                   "controls": [h for h in SEC_HEADERS if h not in {k.lower() for k in r["headers"]}]},
        )]

    def cookie_flags(self, url: str, method="GET", body=None, headers=None) -> list[dict]:
        r = self._req(url, method=method, body=body, headers=headers, tool="cookie_check")
        if not r.get("ok"):
            return []
        out = []
        # every Set-Cookie the response carried, not just the last one the
        # headers dict kept (http_probe records the full list as set-cookie-all)
        all_jars = next((v for k, v in r["headers"].items() if k.lower() == "set-cookie-all"), "")
        raw_cookies = ([x for x in all_jars.split("\n") if x.strip()] or
                       [v for k, v in r["headers"].items() if k.lower() == "set-cookie"])
        for c in raw_cookies:
            low = c.lower()
            if "session" not in low and "token" not in low and "auth" not in low:
                continue
            problems = []
            if "httponly" not in low:
                problems.append("HttpOnly")
            if "secure" not in low:
                problems.append("Secure")
            if "samesite" not in low:
                problems.append("SameSite")
            if problems:
                name = c.split("=", 1)[0]
                out.append(_candidate(
                    f"Session cookie '{name}' missing flags ({', '.join(problems)})",
                    "CWE-614", "A05:2021 Security Misconfiguration", "medium", "high", url,
                    f"Cookie '{name}' is set without: {', '.join(problems)}.",
                    "Session theft via XSS (no HttpOnly), interception (no Secure), or CSRF (no SameSite).",
                    "Set HttpOnly, Secure, and SameSite=Strict/Lax on session cookies.",
                    r["evidence_id"], f"{name}|{','.join(problems)}",
                    {"method": method, "url": url, "body": body, "headers": headers},
                    f"cookie:{url}:{name}", quote_in="cookie_fact",
                    controls=[COOKIE_CONTROLS[p] for p in problems],
                    proof={"cookie": name, "missing": problems},
                ))
        return out

    def cors(self, url: str) -> list[dict]:
        evil = "https://evil.invalid"
        r = self._req(url, headers={"Origin": evil}, tool="cors_check")
        if not r.get("ok"):
            return []
        h = {k.lower(): v for k, v in r["headers"].items()}
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            return [_candidate(
                "CORS wildcard with credentials", "CWE-942", "A05:2021 Security Misconfiguration",
                "high", "high", url,
                "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
                "Any origin can make credentialed cross-origin requests (browser permitting).",
                "Restrict ACAO to an explicit allowlist; never combine wildcard with credentials.",
                r["evidence_id"], f"access-control-allow-origin: {acao}",
                self._proof(url, headers={"Origin": evil}),
                f"cors:{url}", quote_in="header_fact",
            )]
        if acao == evil and acac.lower() == "true":
            return [_candidate(
                "CORS reflects arbitrary origin with credentials", "CWE-942",
                "A05:2021 Security Misconfiguration", "high", "high", url,
                f"Origin {evil} reflected in ACAO with credentials allowed.",
                "Any website can read authenticated responses cross-origin.",
                "Validate Origin against a strict allowlist.",
                r["evidence_id"], f"access-control-allow-origin: {acao}",
                self._proof(url, headers={"Origin": evil}),
                f"cors:{url}", quote_in="header_fact",
            )]
        return []

    def reflected_xss(self, url: str, param: str) -> list[dict]:
        payload = f"<script>/*{CANARY}*/</script>"
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{param}={payload}"
        r = self._req(target, tool="xss_check")
        if not r.get("ok"):
            return []
        ct = r["headers"].get("content-type", "")
        if payload in r["body"] and ("html" in ct or not ct):
            return [_candidate(
                f"Reflected XSS in parameter '{param}'", "CWE-79", "A03:2021 Injection",
                "high", "high", url,
                f"Payload {payload} reflected unescaped in HTML response.",
                "Arbitrary JavaScript execution in victims' browsers; session theft, actions on behalf of users.",
                "Context-aware output encoding; apply a strict Content-Security-Policy.",
                r["evidence_id"], payload, self._proof(target),
                f"xss:{url}:{param}",
                proof={"signal": "reflection",
                       "benign_request": self._proof(with_param(target, param, "libella-benign"))},
            )]
        return []

    def sqli(self, url: str, param: str) -> list[dict]:
        sep = "&" if "?" in url else "?"
        base = f"{url}{sep}{param}="
        r = self._req(base + "'", tool="sqli_check")
        if not r.get("ok"):
            return []
        low = r["body"].lower()
        hit = next((s for s in SQLI_ERRORS if s in low), None)
        if hit:
            idx = low.find(hit)
            quote = r["body"][max(0, idx - 20):idx + len(hit) + 40]
            return [_candidate(
                f"SQL injection (error-based) in parameter '{param}'", "CWE-89",
                "A03:2021 Injection", "critical", "high", url,
                f"Single quote triggers database error signature: {hit}.",
                "Full database read/write depending on privileges; authentication bypass; data exfiltration.",
                "Use parameterized queries / prepared statements; least-privilege DB account.",
                r["evidence_id"], quote, self._proof(base + "'"),
                f"sqli:{url}:{param}",
                proof={"signal": "error_signature",
                       # same parameter, a benign value: a server that fails on anything
                       # raises the same signature without any injection
                       "benign_request": self._proof(base + "1")},
            )]
        return []

    def sqli_union(self, url: str, param: str, union_payload: str, marker: str) -> list[dict]:
        """Confirm union-based extraction with an operator/lab-supplied payload."""
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{param}={union_payload}"
        r = self._req(target, tool="sqli_union_check")
        if not r.get("ok") or marker not in r["body"]:
            return []
        idx = r["body"].find(marker)
        quote = r["body"][max(0, idx - 40):idx + len(marker) + 40]
        return [_candidate(
            f"SQL injection (UNION data extraction) in parameter '{param}'", "CWE-89",
            "A03:2021 Injection", "critical", "high", url,
            f"UNION payload extracts data; marker '{marker}' present in response.",
            "Arbitrary data extraction from the database.",
            "Parameterized queries; least-privilege DB account.",
            r["evidence_id"], quote, self._proof(target),
            f"sqli:{url}:{param}",
            proof={"signal": "union_marker",
                   # the operator-supplied marker must not appear for a value that is not
                   # an injection: otherwise the marker was the page's own content
                   "benign_request": self._proof(with_param(target, param, "libellaBenign"))},
        )]

    def path_traversal(self, url: str, param: str) -> list[dict]:
        sep = "&" if "?" in url else "?"
        payloads = []
        for depth in (4, 6, 8, 10):
            up = "../" * depth
            payloads.append(up + "etc/passwd")
            payloads.append(("..%2f" * depth) + "etc%2fpasswd")
        for payload in payloads:
            target = f"{url}{sep}{param}={payload}"
            r = self._req(target, tool="traversal_check")
            if r.get("ok") and re.search(r"root:[x*!]?:0:0:", r["body"]):
                m = re.search(r"root:[^\n]*", r["body"])
                return [_candidate(
                    f"Path traversal in parameter '{param}'", "CWE-22",
                    "A01:2021 Broken Access Control", "high", "high", url,
                    f"Payload {payload} reads /etc/passwd.",
                    "Arbitrary file read on the server; source code, secrets, configuration exposure.",
                    "Canonicalize and confine paths to an allowlisted base directory; reject '..'.",
                    r["evidence_id"], m.group(0), self._proof(target),
                    f"traversal:{url}:{param}",
                )]
        return []

    def open_redirect(self, url: str, param: str) -> list[dict]:
        sep = "&" if "?" in url else "?"
        dest = "https://example.invalid/libella-redirect"
        target = f"{url}{sep}{param}={dest}"
        r = self.probe.request(self.eng, self.scope, target, tool="redirect_check",
                               follow_redirects=False)
        if not r.get("ok"):
            return []
        loc = r["headers"].get("location", "")
        if r["status"] in (301, 302, 303, 307, 308) and loc.startswith(dest):
            return [_candidate(
                f"Open redirect in parameter '{param}'", "CWE-601",
                "A01:2021 Broken Access Control", "medium", "high", url,
                f"Redirects to arbitrary external URL {dest}.",
                "Phishing via trusted domain; OAuth token theft in redirect flows.",
                "Allowlist redirect destinations; reject off-host URLs.",
                r["evidence_id"], f"location: {loc}", self._proof(target),
                f"redirect:{url}:{param}", quote_in="header_fact",
            )]
        return []

    def ssrf(self, url: str, param: str, internal_url: str, marker: str) -> list[dict]:
        """Prove server-side fetch of an in-scope internal URL by marker reflection."""
        # An empty marker is vacuously "in" every body, so an unset marker (the agent may
        # omit it) would report SSRF for any target. Refuse rather than prove nothing.
        if not (marker or "").strip():
            return []
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{param}={internal_url}"
        r = self._req(target, tool="ssrf_check")
        if not r.get("ok") or marker not in r["body"]:
            return []
        idx = r["body"].find(marker)
        quote = r["body"][max(0, idx - 30):idx + len(marker) + 30]
        return [_candidate(
            f"SSRF in parameter '{param}'", "CWE-918", "A10:2021 Server-Side Request Forgery",
            "high", "high", url,
            f"Server fetches {internal_url} and returns its content (marker '{marker}').",
            "Access to internal services and cloud metadata; potential credential theft.",
            "Allowlist outbound destinations; block link-local/metadata ranges; egress filtering.",
            r["evidence_id"], quote, self._proof(target),
            f"ssrf:{url}:{param}",
            proof={"marker": marker,
                   # the marker must arrive only when the server fetched the internal
                   # resource: ask the same endpoint for the application's own root, which
                   # cannot contain it. A control that still names the internal URL proves
                   # nothing, because the server fetches it either way.
                   "benign_request": self._proof(
                       with_param(target, param, _origin_root(internal_url)))},
        )]

    def sensitive_paths(self, base_url: str) -> list[dict]:
        out = []
        base = base_url.rstrip("/")
        for path in SENSITIVE_PATHS:
            r = self._req(base + path, tool="path_probe")
            if not r.get("ok") or r["status"] != 200:
                continue
            body = r["body"]
            low = body.lower()
            title = None
            cwe = "CWE-200"
            sev = "medium"
            quote = None
            if path == "/.env" and re.search(r"(?m)^[A-Z_]+=", body):
                title, sev, cwe = "Exposed .env configuration file", "high", "CWE-200"
                quote = re.search(r"(?m)^[A-Z_]+=.*", body).group(0)
            elif path == "/.git/config" and "[core]" in body:
                title, sev = "Exposed .git repository configuration", "high"
                quote = "[core]"
            elif path == "/debug" and ("secret" in low or "environ" in low or "config" in low):
                title, sev = "Debug endpoint exposes configuration/secrets", "high"
                quote = body[:200]
            elif path in ("/api/users", "/api/v1/users") and "password" in low:
                title, sev, cwe = "User API exposes password hashes (excessive data exposure)", "high", "CWE-200"
                m = re.search(r'"password"\s*:\s*"[^"]{0,40}', body)
                quote = m.group(0) if m else "password"
            elif path == "/uploads/" and ("<li>" in low or "index of" in low):
                title, cwe = "Directory listing enabled on /uploads/", "CWE-548"
                quote = "index of" if "index of" in low else "<li>"
            elif path == "/server-status" and "apache" in low:
                title = "Apache server-status exposed"
                quote = body[:120]
            elif path == "/phpinfo.php" and "php version" in low:
                title, sev = "phpinfo() page exposed", "medium"
                quote = "PHP Version"
            elif path == "/actuator/env" and "propertysources" in low.replace(" ", ""):
                title, sev = "Spring Actuator env endpoint exposed", "high"
                quote = body[:120]
            if title:
                out.append(_candidate(
                    title, cwe, "A05:2021 Security Misconfiguration", sev, "high",
                    base + path, f"GET {path} returns 200 with sensitive content.",
                    "Information disclosure aiding further attacks; possible secret exposure.",
                    "Remove or restrict access to the exposed resource.",
                    r["evidence_id"], quote, self._proof(base + path),
                    f"path:{base}{path}",
                ))
        return out

    def ssti(self, url: str, param: str) -> list[dict]:
        """Prove template evaluation with two distinct arithmetic payloads."""
        sep = "&" if "?" in url else "?"
        r1 = self._req(f"{url}{sep}{param}={{{{7*7}}}}", tool="ssti_check")
        if not r1.get("ok") or "49" not in r1["body"] or "7*7" in r1["body"]:
            return []
        proof_url = f"{url}{sep}{param}={{{{7*19}}}}"
        r2 = self._req(proof_url, tool="ssti_confirm")
        if not r2.get("ok") or "133" not in r2["body"]:
            return []
        idx = r2["body"].find("133")
        quote = r2["body"][max(0, idx - 20):idx + 23]
        return [_candidate(
            f"Server-side template injection in parameter '{param}'", "CWE-1336",
            "A03:2021 Injection", "critical", "high", url,
            "Payloads {{7*7}} and {{7*19}} are evaluated server-side (49, 133).",
            "Template engine execution; often escalates to remote code execution.",
            "Never render user input as template source; use sandboxed templating with autoescape.",
            r2["evidence_id"], quote, self._proof(proof_url),
            f"ssti:{url}:{param}",
        )]

    def file_upload(self, upload_url: str, base_url: str) -> list[dict]:
        """Upload a harmless marker with a dangerous extension; prove storage + reachability."""
        boundary = "----libellaprobe"
        fname = "libella_probe.php"
        marker = "libella-upload-probe-marker-9f2c"
        content = f"<?php /* {marker} */ ?>"
        body = (f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"{fname}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
                f"{content}\r\n--{boundary}--\r\n").encode()
        r = self._req(upload_url, method="POST", body=body,
                      headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                      tool="upload_check")
        if not r.get("ok") or r["status"] not in (200, 201):
            return []
        low = r["body"].lower()
        if not any(k in low for k in ("upload", "success", "path", "url", "file")):
            return []
        # try to reach the stored file via a path/url in the response
        import json as _json
        reach = None
        try:
            data = _json.loads(r["body"])
            for k in ("path", "url", "file", "location"):
                v = data.get(k)
                if isinstance(v, str) and v:
                    reach = v if v.startswith("http") else base_url.rstrip("/") + "/" + v.lstrip("/")
                    break
        except (ValueError, AttributeError):
            pass
        if reach and self.scope.check_url(reach).allowed:
            rr = self._req(reach, tool="upload_reach")
            if rr.get("ok") and marker in rr["body"]:
                return [_candidate(
                    "Unrestricted file upload (dangerous extension stored and reachable)",
                    "CWE-434", "A04:2021 Insecure Design", "high", "high", upload_url,
                    f"A .php probe was accepted and is reachable at {reach} with its content intact.",
                    "Web-shell upload potential; remote code execution if the path is script-executable.",
                    "Allowlist extensions and content types; rename uploads; store outside web root; disable script execution in upload dirs.",
                    rr["evidence_id"], marker,
                    self._proof(reach),
                    f"upload:{upload_url}",
                )]
        return []

    def version_signals(self, url: str) -> list[dict]:
        """Observations only. Version banners are NOT findings (negative control)."""
        r = self._req(url, tool="fingerprint")
        if not r.get("ok"):
            return []
        signals = []
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            v = r["headers"].get(h)
            if v:
                signals.append({"header": h, "value": v, "evidence_id": r["evidence_id"],
                                "note": "version signal only; requires configuration/exposure proof before any CVE claim"})
        return signals

    def auth_bypass(self, login_url: str, username_field: str = "username",
                    password_field: str = "password") -> list[dict]:
        payloads = ["admin'-- ", "' OR '1'='1'-- ", "admin'#"]
        for payload in payloads:
            body = f"{username_field}={payload}&{password_field}=SI_SECRET_PASSWORD_GS8264V3"
            r = self._req(login_url, method="POST", body=body,
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          tool="auth_bypass_check")
            if not r.get("ok"):
                continue
            low = r["body"].lower()
            if '"authenticated": true' in low or '"authenticated":true' in low or '"success": true' in low:
                return [_candidate(
                    "Authentication bypass via SQL injection", "CWE-89",
                    "A07:2021 Identification and Authentication Failures", "critical", "high",
                    login_url, f"Login payload '{payload}' authenticates without valid credentials.",
                    "Full authentication bypass; administrative access.",
                    "Parameterized queries; never interpolate credentials into SQL.",
                    r["evidence_id"], '"authenticated":true',
                    {"method": "POST", "url": login_url, "body": body,
                     "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
                    f"authbypass:{login_url}",
                    proof={"signal": "error_signature",
                           # the same form with a wrong password: a login that succeeds for
                           # anything is not evidence the injection worked
                           "benign_request": {
                               "method": "POST", "url": login_url,
                               "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                               "body": f"{username_field}=libellaNoUser&"
                                       f"{password_field}=libellaWrongPass"}},
                )]
        return []

    def idor(self, object_url: str, cookie_header: str, foreign_marker: str,
             identity_name: str, identity_value=None) -> list[dict]:
        """Authenticated as identity_name, read an object owned by someone else.

        Both halves of the claim must be present: an empty cookie is an unauthenticated
        request, and an empty foreign_marker is in every body. Either one missing turns the
        check into a false positive about an access control decision it never tested.
        """
        if not (cookie_header or "").strip() or not (foreign_marker or "").strip() \
                or not (identity_name or "").strip():
            return []
        r = self._req(object_url, headers={"Cookie": cookie_header}, tool="idor_check")
        if not r.get("ok") or r["status"] != 200 or foreign_marker not in r["body"]:
            return []
        idx = r["body"].find(foreign_marker)
        quote = r["body"][max(0, idx - 30):idx + len(foreign_marker) + 30]
        anon = self._req(object_url, tool="idor_check_anon")
        if anon.get("ok") and anon["status"] < 400 and foreign_marker in anon["body"]:
            # The same record is served with NO credential, so the route applies no
            # session check at all. Reporting "alice read bob's object" would describe an
            # identity comparison that never happened: this is missing authentication.
            return [_candidate(
                f"Object endpoint serves another user's record without authentication "
                f"({object_url.split('://')[-1]})", "CWE-306",
                "API2:2023 Broken Authentication", "high", "high", object_url,
                f"GET {object_url} with no credential returned a record belonging to "
                f"someone else ({foreign_marker}), so the route checks neither session nor "
                f"ownership. Every record of this type is readable by anyone who can reach "
                f"the service.",
                "Unauthenticated disclosure of other users' records; bulk enumeration of the "
                "collection and the personal data in it.",
                "Require authentication on the route, then enforce object-level ownership "
                "before serving a record.",
                anon["evidence_id"], quote, self._proof(object_url),
                f"noauth:{object_url}",
            )]
        return [_candidate(
            f"IDOR/BOLA: {identity_name} can read another user's object", "CWE-639",
            "A01:2021 Broken Access Control", "high", "high", object_url,
            f"Authenticated as {identity_name}, GET {object_url} returns foreign data ({foreign_marker}).",
            "Horizontal privilege escalation; access to other users' data.",
            "Enforce object-level ownership checks on every request.",
            r["evidence_id"], quote,
            self._proof(object_url, headers={"Cookie": cookie_header}),
            f"idor:{object_url}:{identity_name}",
            proof={"identity": {"name": identity_name, "value": identity_value},
                   "owner_field": _owner_of(r["body"])[0], "owner_value": _owner_of(r["body"])[1],
                   "benign_request": {"method": "GET", "url": object_url}},
        )]

    def object_enumeration(self, collection_url: str, cookie_header: str,
                           identity_name: str, identity_value, ids=None,
                           tool: str = "object_enum") -> list[dict]:
        """Find another identity's object by walking ids under a DISCOVERED collection.

        Nothing here is target-specific: the owner field is read from the served record,
        the claim needs the owner to differ from the caller, and anonymous access to the
        same object must be refused. An operator hint names the ids; this derives them.
        """
        if not (cookie_header or "").strip() or not (identity_name or "").strip() \
                or identity_value in (None, ""):
            return []
        for oid in (ids if ids is not None else self.collection_ids(collection_url,
                                                                   cookie_header)):
            url = f"{collection_url.rstrip('/')}/{oid}"
            r = self._req(url, headers={"Cookie": cookie_header}, tool=tool)
            if not r.get("ok") or r["status"] != 200:
                continue
            owner_field, owner = _owner_of(r["body"])
            if owner is None or str(owner) == str(identity_value):
                continue
            anon = self._req(url, tool=f"{tool}_anon")
            if not anon.get("ok"):
                continue
            if anon["status"] < 400:
                # Readable with no credential at all. That is a real defect, but it is NOT
                # an ownership failure: no authorization decision was made, so reporting
                # "alice read bob's order" would describe an identity check that never ran.
                quote = f'"{owner_field}":{json.dumps(owner)}'
                if owner != identity_value and quote in anon["body"]:
                    return [_candidate(
                        f"Object endpoint serves another user's record without authentication "
                        f"({url.split('://')[-1]})", "CWE-306",
                        "API2:2023 Broken Authentication", "high", "high", url,
                        f"GET {url} with no credential returned object {oid}, whose "
                        f"'{owner_field}' is {owner}. The route applies no session or "
                        f"ownership check at all, so every record of this type is readable "
                        f"by anyone who can reach the service.",
                        "Unauthenticated disclosure of other users' records; enables bulk "
                        "enumeration of the whole collection.",
                        "Require authentication on the route and enforce object ownership "
                        "before serving a record.",
                        anon["evidence_id"], quote, self._proof(url), f"noauth:{collection_url}")
                    ]
                continue
            quote = f'"{owner_field}":{json.dumps(owner)}'
            if quote not in r["body"]:
                continue
            return [_candidate(
                f"IDOR/BOLA: '{identity_name}' reads another user's object at "
                f"{url.split('://')[-1]}", "CWE-639",
                "API1:2023 Broken Object Level Authorization", "high", "high", url,
                f"Identity {identity_name} (id {identity_value}) read object {oid}, whose "
                f"'{owner_field}' is {owner}; the same request without the credential "
                f"returned {anon['status']}. Object ids are sequential, so every record of "
                f"this type is enumerable.",
                "Horizontal privilege escalation: any authenticated user can read every "
                "record of this type by changing the id.",
                "Enforce object-level ownership (or tenancy) on every object read; do not "
                "rely on unguessable ids.",
                r["evidence_id"], quote,
                self._proof(url, headers={"Cookie": cookie_header}),
                f"bola:{collection_url.rstrip('/')}",
                proof={"identity": {"name": identity_name, "value": identity_value},
                       "owner_field": owner_field, "owner_value": owner,
                       # the same object with no credential: a denial is what proves the
                       # record is protected and the read was an authorization failure
                       "benign_request": {"method": "GET", "url": url}},
            )]
        return []

    def is_collection(self, body: str) -> bool:
        """Does this response publish a list of records?"""
        return is_collection(body)

    def observed_param_names(self) -> list[str]:
        """Query keys and form field names this application has already shown us.

        Empty when no store was supplied: the caller keeps only what it can see.
        """
        if self.db is None:
            return []
        names: list[str] = []
        for row in self.db.query(
                "SELECT url FROM exchanges WHERE engagement_id=? AND url LIKE '%?%' "
                "ORDER BY created_at DESC LIMIT 400", (self.eng,)):
            for key, _ in parse_qsl(urlparse(row["url"]).query, keep_blank_values=True):
                if key and key not in names and len(names) < 20:
                    names.append(key)
        for row in self.db.query(
                "SELECT result_json FROM intents WHERE engagement_id=? AND role='crawl' "
                "AND result_json IS NOT NULL", (self.eng,)):
            try:
                forms = json.loads(row["result_json"]).get("forms") or []
            except (ValueError, AttributeError):
                continue
            for form in forms:
                for field in (form.get("fields") or []):
                    name = field.get("name") if isinstance(field, dict) else field
                    if isinstance(name, str) and name and name not in names and len(names) < 20:
                        names.append(name)
        return names

    def collection_ids(self, collection_url: str, cookie_header: str = "",
                       limit: int = 8) -> list[int]:
        """Candidate object ids: those the listing publishes, plus their neighbours.

        Reading the ids from the listing is what makes enumeration work when ids do not
        start at 1 (measured: 5001, 5002 in an app whose lower ids do not exist). The
        neighbours matter because ONE identity's listing only shows its own records, so
        another user's id is reachable only by stepping next to a known one.
        """
        headers = {"Cookie": cookie_header} if cookie_header else None
        r = self._req(collection_url, headers=headers, tool="collection_listing")
        seen = _record_ids(r["body"], 4) if r.get("ok") and r["status"] == 200 else []
        ids: list[int] = []
        for base in seen or [1]:
            for delta in (0, 1, 2, -1):
                cand = base + delta
                if cand > 0 and cand not in ids:
                    ids.append(cand)
        return ids[:limit]

    def live_params(self, url: str, names=None, limit: int = 4) -> list[str]:
        """Which query parameters this endpoint actually reacts to.

        Declared hints are not available on an unfamiliar target, and a fixed endpoint
        list only finds the parameters someone thought of. This asks the endpoint: send a
        benign value, keep the parameter when the response changes in a way the value
        alone does not explain (status, length, or a different document).
        """
        base = url.split("?")[0]
        bare = self._req(base, tool="param_discovery")
        if not bare.get("ok"):
            return []
        found = []
        # Names the application itself uses come first: a form field or a query key seen
        # anywhere in this engagement is evidence, where a hand-written list is a guess.
        evidence = list(names or self.observed_param_names())
        candidates = evidence + [n for n in PARAM_NAMES if n not in evidence]
        for name in candidates:
            if len(found) >= limit:
                break
            probe = self._req(f"{base}?{name}=libellaProbe", tool="param_discovery")
            if not probe.get("ok"):
                continue
            if probe["status"] != bare["status"] or abs(
                    len(probe["body"]) - len(bare["body"])) > len("libellaProbe") * 2:
                found.append(name)
        return found


# Common parameterized endpoints probed during parameter mining (generic patterns).
COMMON_PARAM_ENDPOINTS = [
    "/search?q=test", "/files?name=readme.txt", "/redirect?to=/",
    "/fetch?url=http://127.0.0.1/", "/api/products?category=tools",
    "/download?file=readme.txt", "/page?id=1", "/profile?user=1",
    "/greet?name=world",
]
COMMON_API_PATHS = ["/api/profile", "/api/users", "/api/orders", "/api/config"]

# Names worth probing on a discovered endpoint: the vocabulary applications use for the
# values these checks attack (a query, a filter, a file, a destination, an object id).
# Ordered by how often they carry user input, not by any one fixture's spelling.
PARAM_NAMES = [
    "q", "query", "search", "filter", "category", "type", "sort", "order", "id", "ids",
    "name", "file", "path", "url", "uri", "dest", "destination", "next", "redirect",
    "return", "returnUrl", "callback", "user", "username", "page", "limit", "offset",
    # values that name a destination or a subject for a server-side action
    "target", "src", "source", "link", "address", "host", "endpoint", "kind", "tag",
]

# Fields a served record uses to name its owner. Read from the response, never assumed
# from the endpoint's spelling.
OWNER_FIELDS = ("user_id", "owner_id", "userId", "ownerId", "uid", "owner", "user",
                "account_id", "tenant_id", "customer_id", "created_by")


def _origin_root(url: str) -> str:
    """scheme://host/ of a URL: the app's own root, with no path or query."""
    m = re.match(r"^(https?://[^/?#]+)", url or "")
    return (m.group(1) + "/") if m else ""


def is_collection(body: str) -> bool:
    """Does this response publish a list of records that each carry an id?"""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return False
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), None)
    return bool(isinstance(data, list) and data
                and all(isinstance(row, dict) and isinstance(row.get("id"), int) for row in data))


def _record_ids(body: str, limit: int = 5) -> list[int]:
    """Integer `id` values published by a collection response, in document order."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    rows = None
    if isinstance(data, dict):
        rows = next((v for v in data.values() if isinstance(v, list) and v), None)
        if rows is None and "id" in data:
            rows = [data]
    elif isinstance(data, list):
        rows = data
    if not rows:
        return []
    out = []
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("id"), int):
            out.append(row["id"])
        if len(out) >= limit:
            break
    return out


def record_of(body: str) -> dict | None:
    """The record in a response body, unwrapping the envelope a JSON API wraps it in.

    {"invoice": {...}}, {"data": {"user": {...}}} and a bare {...} are all one record; a
    list of them is a collection, not a record. Without this the ownership check read the
    ENVELOPE, found no owner field, and reported "ownership unshown" for a served invoice.
    """
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if isinstance(data, list):
        return data[0] if len(data) == 1 and isinstance(data[0], dict) else None
    if not isinstance(data, dict):
        return None
    # The record is the innermost object that carries an "id": an envelope key that happens
    # to be named "user" (GraphQL's {"data": {"user": {...}}}) is a wrapper, not the record.
    if "id" in data:
        return data
    for value in data.values():
        if isinstance(value, dict):
            found = record_of(json.dumps(value))
            if found is not None:
                return found
    return data if any(f in data for f in OWNER_FIELDS) else None


def _owner_of(body: str) -> tuple[str | None, object]:
    """(field, value) naming the record's owner in a JSON body, or (None, None)."""
    data = record_of(body)
    if data is None:
        return None, None
    for field in OWNER_FIELDS:
        if field in data and data[field] not in (None, "", {}):
            return field, data[field]
    return None, None
