"""Technology-specific assessment: identify the stack, then test what that
stack is known to leave exposed.

Fingerprinting alone is an observation, not a finding. Each module below
turns a detected technology into targeted, read-only probes whose positive
result is bound to the captured exchange that proved it. Detection is
deliberately cheap (one GET); a module only runs when its signals are
actually present, so a target is not sprayed with paths from stacks it does
not run.
"""
import re
from collections import namedtuple

from .checks import SENSITIVE_PATHS, _candidate

TECH_SIGNATURES = {
    "wordpress": ("wp-content", "wp-includes", "wp-json", "wordpress"),
    "coldfusion": ("cfid=", "cftoken=", "/cfide/", "coldfusion"),
    "java": ("jsessionid", "x-application-context", "struts", ".action", "spring"),
    "node": ("x-powered-by: express", "connect.sid"),
    "iis": ("microsoft-iis", "x-aspnet-version"),
    "php": ("x-powered-by: php", "phpsessid"),
    "apache": ("apache/",),
    "nginx": ("nginx/",),
}

# (tech, path, regex on body, title, cwe, severity, impact, fix
#  [, status, cap, owasp, control_path])
# control_path: for rows with no signature the response must differ from a plain
# miss, otherwise a normal 404 page "proves" the row.
Row = namedtuple("Row", "tech path sig title cwe sev impact fix status cap owasp ctrl",
                 defaults=[200, 0, "A05:2021 Security Misconfiguration", None])

ROWS = [
    # ---- WordPress ----
    Row("wordpress", "/wp-config.php.bak", r"DB_PASSWORD", "WordPress wp-config.php backup exposed",
        "CWE-538", "critical",
        "Database credentials and auth salts are readable; the site is fully takeable.",
        "Remove backup/save files from the web root and block *.bak, *.swp, *~ at the server."),
    Row("wordpress", "/wp-config.php~", r"DB_PASSWORD", "WordPress wp-config.php editor backup exposed",
        "CWE-538", "critical",
        "Database credentials and auth salts are readable; the site is fully takeable.",
        "Remove backup/save files from the web root and block *.bak, *.swp, *~ at the server."),
    Row("wordpress", "/wp-content/plugins/", r"(?i)index of",
        "WordPress plugin directory listing enabled", "CWE-548", "low",
        "Installed plugin inventory aids targeted exploitation of known plugin CVEs.",
        "Disable autoindex for wp-content/plugins or add an index file."),
    Row("wordpress", "/wp-json/wp/v2/users", r'"slug"', "WordPress REST API enumerates users",
        "CWE-200", "medium",
        "Usernames feed credential attacks against wp-login and xmlrpc.",
        "Restrict /wp-json/wp/v2/users to authenticated users."),
    Row("wordpress", "/xmlrpc.php", r"(?i)xml-rpc server accepts post",
        "WordPress XML-RPC endpoint reachable", "CWE-307", "low",
        "XML-RPC accepts amplified credential guessing and pingback reflection.",
        "Block xmlrpc.php at the edge unless a required integration needs it.",
        status=405),
    # ---- PHP ----
    Row("php", "/phpinfo.php", r"(?i)php version", "phpinfo() page exposed", "CWE-200", "medium",
        "Reveals PHP build, extensions, docroots and environment values.",
        "Remove phpinfo scripts; never deploy them to production."),
    Row("php", "/info.php", r"(?i)php version", "phpinfo() page exposed", "CWE-200", "medium",
        "Reveals PHP build, extensions, docroots and environment values.",
        "Remove phpinfo scripts; never deploy them to production."),
    Row("php", "/index.php.bak", r"<\?php", "PHP source backup exposed", "CWE-538", "high",
        "Source discloses logic, secrets and SQL; enables targeted injection.",
        "Delete editor/backup artifacts and deny *.bak, *.swp, *~ in the web root."),
    Row("php", "/index.php~", r"<\?php", "PHP source editor backup exposed", "CWE-538", "high",
        "Source discloses logic, secrets and SQL; enables targeted injection.",
        "Delete editor/backup artifacts and deny *.bak, *.swp, *~ in the web root."),
    Row("php", "/index.php.swp", r"(?i)b0VIM|vim", "PHP source swap file exposed", "CWE-538", "high",
        "A recoverable buffer of source code and possibly credentials.",
        "Delete swap files and deny *.swp in the web root."),
    Row("php", "/config.php.bak", r"<\?php", "PHP config backup exposed", "CWE-538", "high",
        "Configuration source with database credentials is downloadable.",
        "Delete backup artifacts and deny *.bak in the web root."),
    # ---- Java / Spring ----
    Row("java", "/actuator/env", r"(?i)propertysources", "Spring Boot Actuator env exposed",
        "CWE-200", "high",
        "Environment properties leak credentials, tokens and internal hostnames.",
        "Expose only health/info and require authentication on actuator endpoints."),
    Row("java", "/actuator/heapdump", r"JAVA PROFILE", "Spring Boot heapdump downloadable",
        "CWE-200", "critical",
        "Heap dumps contain live session tokens, passwords and keys.",
        "Disable the heapdump endpoint or restrict it to an authenticated admin network."),
    Row("java", "/actuator", r'"_links"', "Spring Boot Actuator index exposed", "CWE-200", "low",
        "Enumerates which actuator endpoints are reachable.",
        "Restrict actuator to health/info behind authentication."),
    Row("java", "/index.action", r"(?i)struts problem report", "Struts devMode error page exposed",
        "CWE-209", "medium",
        "Stack traces and OGNL details accelerate Struts exploitation.",
        "Set struts.devMode=false and struts.configuration.xml.reload=false."),
    # ---- ColdFusion ----
    Row("coldfusion", "/CFIDE/administrator/", r"(?i)coldfusion administrator",
        "ColdFusion Administrator exposed", "CWE-284", "critical",
        "Admin console reachable; historical CF admin bypasses lead to RCE.",
        "Block /CFIDE from untrusted networks and restrict the admin console by IP."),
    Row("coldfusion", "/CFIDE/componentutils/cfcexplorer.cfc", r"(?i)cfcexplorer|componentutils",
        "CFIDE component explorer exposed", "CWE-200", "high",
        "Enumerates installed CFCs and their methods, seeding deserialization attacks.",
        "Remove CFIDE script mappings from production."),
    # ---- Node / Express ----
    Row("node", "/.env", r"(?m)^[A-Z_]+=", "Node .env file exposed", "CWE-200", "high",
        "Application secrets and database URLs are readable.",
        "Serve static files from a dedicated directory; never the project root."),
    Row("node", "/package.json", r'"dependencies"', "package.json exposed", "CWE-200", "medium",
        "Dependency and version inventory maps directly to known CVEs.",
        "Do not serve package.json; whitelist static assets."),
    Row("node", "/debug", r"(?i)environ|secret|config", "Node debug endpoint exposes config",
        "CWE-200", "medium",
        "Debug handlers expose environment variables and internal state.",
        "Disable debug routes in production builds."),
    Row("node", "/__libella_missing__", r"(?i)node_modules[\\/]|at Layer\.handle",
        "Express stack trace disclosure", "CWE-209", "medium",
        "Stack traces reveal file paths, framework versions and code structure.",
        "Set NODE_ENV=production and a custom error handler that returns generic pages.",
        status=404),
    # ---- IIS / ASP.NET ----
    Row("iis", "/web.config", r"(?i)<configuration", "IIS web.config exposed", "CWE-200", "critical",
        "Connection strings and machine keys are readable, enabling auth forgery.",
        "Deny access to *.config via request filtering."),
    Row("iis", "/trace.axd", r"(?i)application trace", "ASP.NET trace.axd exposed", "CWE-200", "medium",
        "Request traces leak cookies, headers and server paths.",
        "Set <trace enabled=\"false\"/> in web.config."),
    Row("iis", "/libella~1.aspx", None, "IIS 8.3 short-name enumeration possible",
        "CWE-200", "low",
        "Short names leak file and directory naming, aiding targeted requests.",
        "Set NtfsDisable8dot3NameCreation=1 and apply the IIS tilde hardening.",
        status=404, ctrl="/libella_no_such_file.aspx"),
    # ---- Apache / Nginx ----
    Row("apache", "/server-status", r"(?i)apache server status", "Apache server-status exposed",
        "CWE-200", "medium",
        "Live request list leaks internal URLs, clients and load patterns.",
        "Restrict /server-status to localhost."),
    Row("apache", "/.htaccess", r"(?i)rewriteengine|directoryindex|authtype", ".htaccess readable",
        "CWE-200", "high",
        "Auth rules and rewrite targets are disclosed; bypasses become obvious.",
        "Deny .ht* files at the server and never rely on obscurity for auth rules."),
    Row("apache", "/nginx.conf", r"server\s*\{", "nginx.conf exposed", "CWE-200", "high",
        "Upstream hosts, TLS material paths and internal routes are disclosed.",
        "Serve only from the docroot; deny configuration files."),
    Row("apache", "/static../WEB-INF/web.xml", r"(?i)<web-app",
        "Alias traversal reads WEB-INF/web.xml", "CWE-22", "high",
        "Path traversal past the alias reaches protected application files.",
        "Use alias with a trailing slash or root/location, not prefix concatenation."),
]

# nginx shares the Apache module rows: same resources, same misconfigurations.
TECH_ROWS: dict[str, list[Row]] = {}
for _row in ROWS:
    TECH_ROWS.setdefault(_row.tech, []).append(_row)
TECH_ROWS["nginx"] = TECH_ROWS["apache"]


def detect_technologies(resp: dict) -> list[str]:
    """Stack from one response: header lines + body head, most specific first."""
    if not resp.get("ok"):
        return []
    head = "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items())
    hay = (head + "\n" + (resp.get("body") or ""))[:32768].lower()
    return [tech for tech, sigs in TECH_SIGNATURES.items() if any(s in hay for s in sigs)]


class TechAssess:
    def __init__(self, probe, engagement_id: str, scope):
        self.probe = probe
        self.eng = engagement_id
        self.scope = scope

    def _req(self, url, **kw):
        return self.probe.request(self.eng, self.scope, url, tool="tech_probe", **kw)

    def detect(self, base: str) -> tuple[list[str], dict]:
        r = self._req(base)
        return detect_technologies(r), r

    def assess(self, base: str, techs: list[str] | None = None) -> dict:
        base = base.rstrip("/")
        found, home = self.detect(base)
        out = {"base": base, "technologies": found, "candidates": [], "observations": []}
        for tech in techs or found:
            for row in TECH_ROWS.get(tech, []):
                cand = self._row(tech, base, row)
                if cand:
                    out["candidates"].append(cand)
            out["candidates"] += getattr(self, f"_extra_{tech}", lambda *a: [])(base, home)
            out["observations"] += getattr(self, f"_obs_{tech}", lambda *a: [])(home)
        return out

    def _row(self, tech: str, base: str, row: Row) -> dict | None:
        url = base + row.path
        opts = {"body_cap": row.cap} if row.cap else {}
        r = self._req(url, **opts)
        if not r.get("ok") or r["status"] != row.status:
            return None
        m = re.search(row.sig, r["body"]) if row.sig else None
        if row.sig and not m:
            return None
        if not row.sig:
            # no signature: the response only counts if a plain miss answers differently
            ctrl = self._req(base + row.ctrl, **(opts)) if row.ctrl else None
            if not ctrl or not ctrl.get("ok"):
                return None
            same = (ctrl["status"], len(ctrl["body"])) == (r["status"], len(r["body"]))
            if same:
                return None
        quote = m.group(0)[:200] if m else (r["body"][:80] or f"HTTP {r['status']}")
        # same path as a generic sensitive-path check -> same dedup key, one finding
        dedup = f"path:{url}" if row.path in SENSITIVE_PATHS else f"tech:{tech}:{url}"
        return _candidate(
            row.title, row.cwe, row.owasp, row.sev, "high" if row.sig else "low", url,
            f"GET {row.path} returned {r['status']}"
            + (f" with content matching {row.sig!r}." if row.sig else " (tilde form accepted)."),
            row.impact, row.fix, r["evidence_id"], quote,
            {"method": "GET", "url": url}, dedup,
        )

    # ---- WordPress specials (need a request shape a table row cannot express) ----

    def _extra_wordpress(self, base: str, home: dict) -> list[dict]:
        out = []
        url = base + "/xmlrpc.php"
        body = ('<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName>'
                "<params/></methodCall>")
        r = self._req(url, method="POST", body=body, headers={"Content-Type": "text/xml"})
        if r.get("ok") and r["status"] == 200 and "system.listMethods" in r["body"]:
            out.append(_candidate(
                "WordPress XML-RPC accepts method calls (system.multicall reachable)",
                "CWE-307", "A07:2021 Identification and Authentication Failures", "medium", "high",
                url, "system.listMethods answered over XML-RPC, so multicall brute force works.",
                "One request can test hundreds of password pairs, defeating per-request lockouts.",
                "Disable xmlrpc.php or block system.multicall at the edge.",
                r["evidence_id"], "system.listMethods",
                {"method": "POST", "url": url, "body": body,
                 "headers": {"Content-Type": "text/xml"}},
                f"tech:wordpress:xmlrpc:{url}",
            ))
        enum_url = base + "/?author=1"
        r = self._req(enum_url, follow_redirects=False)
        loc = (r.get("headers") or {}).get("location", "") if r.get("ok") else ""
        if loc and "/author/" in loc:
            out.append(_candidate(
                "WordPress user enumeration via ?author=1", "CWE-200",
                "A01:2021 Broken Access Control", "low", "high", enum_url,
                f"?author=1 redirects to {loc}, disclosing the login name.",
                "Usernames enable targeted password spraying and phishing.",
                "Block author archives for unauthenticated users or serve a 404.",
                r["evidence_id"], f"location: {loc}",
                {"method": "GET", "url": enum_url}, f"tech:wordpress:author:{base}",
                quote_in="header_fact",
            ))
        slugs = sorted(set(re.findall(r"/wp-content/plugins/([a-z0-9._-]+)/",
                                      (home.get("body") or "").lower())))[:5]
        for slug in slugs:
            readme = f"{base}/wp-content/plugins/{slug}/readme.txt"
            r = self._req(readme)
            if not r.get("ok") or r["status"] != 200:
                continue
            m = re.search(r"(?im)^stable tag:\s*([\w.\-]+)", r["body"])
            if not m:
                continue
            out.append(_candidate(
                f"WordPress plugin '{slug}' version disclosed via readme.txt", "CWE-200",
                "A05:2021 Security Misconfiguration", "low", "high", readme,
                f"readme.txt reports stable tag {m.group(1)}, identifying an exploitable version.",
                "Exact plugin versions map to public CVEs without any scanning.",
                "Delete readme.txt from deployed plugins or block it at the server.",
                r["evidence_id"], m.group(0)[:120], {"method": "GET", "url": readme},
                f"tech:wordpress:readme:{slug}",
            ))
        return out

    # ---- PHP observation (version banner is a signal, never a finding) ----

    def _obs_php(self, home: dict) -> list[dict]:
        v = (home.get("headers") or {}).get("x-powered-by")
        if not v:
            return []
        return [{"kind": "version_signal", "header": "x-powered-by", "value": v,
                 "evidence_id": home.get("evidence_id"),
                 "note": "expose_php is on; version signal only, needs an exposure proof"}]
