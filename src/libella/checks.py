"""Deterministic web checks. Code performs the test; evidence is captured.

Each check returns candidate findings with a replayable proof_request and
a verbatim quote. Nothing here trusts scanner banners or model prose.
"""
import re
import uuid

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
                quote_in="body"):
    return {
        "title": title, "cwe": cwe, "owasp": owasp, "severity": severity,
        "confidence": confidence, "endpoint": endpoint, "description": description,
        "impact": impact, "remediation": remediation,
        "evidence_ids": [evidence_id], "quote": quote, "quote_in": quote_in,
        "proof_request": proof_request, "dedup_key": dedup_key,
    }


class WebChecks:
    def __init__(self, probe: HttpProbe, engagement_id: str, scope):
        self.probe = probe
        self.eng = engagement_id
        self.scope = scope

    def _req(self, url, method="GET", headers=None, body=None, client=None, tool="check"):
        return self.probe.request(self.eng, self.scope, url, method=method,
                                  headers=headers, body=body, client=client, tool=tool)

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
        return [_candidate(
            f"Missing security headers ({names})", "CWE-693", "A05:2021 Security Misconfiguration",
            sev, "high", url,
            f"Response lacks: {names}.",
            "Increased exposure to clickjacking, MIME sniffing, protocol downgrade, and XSS impact.",
            "Set the missing headers at the server or application layer.",
            r["evidence_id"], quote, {"method": "GET", "url": url},
            f"headers:{url}", quote_in="header_fact",
        )]

    def cookie_flags(self, url: str, method="GET", body=None, headers=None) -> list[dict]:
        r = self._req(url, method=method, body=body, headers=headers, tool="cookie_check")
        if not r.get("ok"):
            return []
        out = []
        raw_cookies = [v for k, v in r["headers"].items() if k.lower() == "set-cookie"]
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
                {"method": "GET", "url": url, "headers": {"Origin": evil}},
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
                {"method": "GET", "url": url, "headers": {"Origin": evil}},
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
                r["evidence_id"], payload, {"method": "GET", "url": target},
                f"xss:{url}:{param}",
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
                r["evidence_id"], quote, {"method": "GET", "url": base + "'"},
                f"sqli:{url}:{param}",
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
            r["evidence_id"], quote, {"method": "GET", "url": target},
            f"sqli:{url}:{param}",
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
                    r["evidence_id"], m.group(0), {"method": "GET", "url": target},
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
                r["evidence_id"], f"location: {loc}", {"method": "GET", "url": target},
                f"redirect:{url}:{param}", quote_in="header_fact",
            )]
        return []

    def ssrf(self, url: str, param: str, internal_url: str, marker: str) -> list[dict]:
        """Prove server-side fetch of an in-scope internal URL by marker reflection."""
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
            r["evidence_id"], quote, {"method": "GET", "url": target},
            f"ssrf:{url}:{param}",
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
                    r["evidence_id"], quote, {"method": "GET", "url": base + path},
                    f"path:{base}{path}",
                ))
        return out

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
                )]
        return []

    def idor(self, object_url: str, cookie_header: str, foreign_marker: str,
             identity_name: str) -> list[dict]:
        """Authenticated as identity_name, read an object owned by someone else."""
        r = self._req(object_url, headers={"Cookie": cookie_header}, tool="idor_check")
        if not r.get("ok") or r["status"] != 200 or foreign_marker not in r["body"]:
            return []
        idx = r["body"].find(foreign_marker)
        quote = r["body"][max(0, idx - 30):idx + len(foreign_marker) + 30]
        return [_candidate(
            f"IDOR/BOLA: {identity_name} can read another user's object", "CWE-639",
            "A01:2021 Broken Access Control", "high", "high", object_url,
            f"Authenticated as {identity_name}, GET {object_url} returns foreign data ({foreign_marker}).",
            "Horizontal privilege escalation; access to other users' data.",
            "Enforce object-level ownership checks on every request.",
            r["evidence_id"], quote,
            {"method": "GET", "url": object_url, "headers": {"Cookie": cookie_header}},
            f"idor:{object_url}:{identity_name}",
        )]


# Common parameterized endpoints probed during parameter mining (generic patterns).
COMMON_PARAM_ENDPOINTS = [
    "/search?q=test", "/files?name=readme.txt", "/redirect?to=/",
    "/fetch?url=http://127.0.0.1/", "/api/products?category=tools",
    "/download?file=readme.txt", "/page?id=1", "/profile?user=1",
]
COMMON_API_PATHS = ["/api/profile", "/api/users", "/api/orders", "/api/config"]
