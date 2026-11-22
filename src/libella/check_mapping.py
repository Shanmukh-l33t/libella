"""Source-backed map: Libella units -> the WSTG 4.2 tests they genuinely exercise.

One row per unit the engine records evidence for (`intents.role`,
`tool_calls.tool` or `exchanges.tool`). `wstg` lists only tests the check
actually performs, `cwe` lists the CWEs its findings carry so a test can be
reported "with findings". Nothing is claimed for a unit that only plans,
replays or renders — those live in UNMAPPED with the reason.
"""

ROWS = (
    {"unit": "recon", "tools": ("httpx",), "exchanges": ("recon_probe",),
     "wstg": ("WSTG-INFO-02", "WSTG-INFO-08", "WSTG-INFO-09"), "cwe": (),
     "why": "httpx + root probe record status, title and technology (parse_httpx_jsonl)"},
    {"unit": "httpx", "wstg": ("WSTG-INFO-02", "WSTG-INFO-08", "WSTG-INFO-09"), "cwe": (),
     "why": "ProjectDiscovery httpx fingerprint: server header, title, tech tags"},
    {"unit": "crawl", "exchanges": ("crawl", "js_mining"),
     "wstg": ("WSTG-INFO-06", "WSTG-INFO-07"), "cwe": (),
     "why": "Crawler records reachable pages, forms, parameters and JS-mined endpoints"},
    {"unit": "security_headers", "exchanges": ("headers_check",),
     "wstg": ("WSTG-CONF-07", "WSTG-CLNT-09"), "cwe": ("CWE-693",),
     # one header finding names several headers; only the relevant ones count
     "controls": {"WSTG-CONF-07": ("header.hsts",),
                  "WSTG-CLNT-09": ("header.x_frame_options", "header.csp")},
     "why": "reports missing HSTS and X-Frame-Options/CSP on a real response"},
    {"unit": "cookie_flags", "exchanges": ("cookie_check",),
     "wstg": ("WSTG-SESS-02",), "cwe": ("CWE-614",),
     "why": "reads Set-Cookie for HttpOnly/Secure/SameSite on session cookies"},
    {"unit": "cors", "exchanges": ("cors_check",),
     "wstg": ("WSTG-CLNT-07",), "cwe": ("CWE-942",),
     "why": "sends a foreign Origin and reads ACAO/ACAC back"},
    {"unit": "sensitive_paths", "exchanges": ("path_probe",),
     "wstg": ("WSTG-CONF-04", "WSTG-CONF-05", "WSTG-INFO-05"), "cwe": ("CWE-200", "CWE-548"),
     "why": "probes .env/.git/backup files, /actuator, /server-status, /debug for exposure"},
    {"unit": "version_signals", "exchanges": ("fingerprint",),
     "wstg": ("WSTG-INFO-02", "WSTG-INFO-08"), "cwe": (),
     "why": "reads version-bearing response headers (recorded as observation, not a finding)"},
    {"unit": "open_redirect", "exchanges": ("redirect_check",),
     "wstg": ("WSTG-CLNT-04",), "cwe": ("CWE-601",),
     "why": "supplies an off-site URL in a parameter and follows the Location"},
    {"unit": "reflected_xss", "exchanges": ("xss_check",),
     "wstg": ("WSTG-INPV-01",), "cwe": ("CWE-79",),
     "why": "injects a script canary into a parameter and checks the reflection"},
    {"unit": "sqli", "exchanges": ("sqli_check",),
     "wstg": ("WSTG-INPV-05",), "cwe": ("CWE-89",),
     "why": "error-based SQL injection probe on a parameter"},
    {"unit": "sqli_union", "exchanges": ("sqli_union_check",),
     "wstg": ("WSTG-INPV-05",), "cwe": ("CWE-89",),
     "why": "UNION data-extraction proof on an operator-declared parameter"},
    {"unit": "ssti", "exchanges": ("ssti_check", "ssti_confirm"),
     "wstg": ("WSTG-INPV-18",), "cwe": ("CWE-1336",),
     "why": "two arithmetic template payloads must both evaluate"},
    {"unit": "path_traversal", "exchanges": ("traversal_check",),
     "wstg": ("WSTG-ATHZ-01",), "cwe": ("CWE-22",),
     "why": "traversal payload in a parameter, passwd content must appear"},
    {"unit": "auth_bypass", "exchanges": ("auth_bypass_check",),
     "wstg": ("WSTG-ATHN-04",), "cwe": ("CWE-89",),
     "why": "SQL auth-bypass payload against the configured login form"},
    {"unit": "file_upload", "exchanges": ("upload_check", "upload_reach"),
     "wstg": ("WSTG-BUSL-08", "WSTG-BUSL-09"), "cwe": ("CWE-434",),
     "why": "uploads a script file type and fetches it back to prove execution surface"},
    {"unit": "ssrf", "exchanges": ("ssrf_check",),
     "wstg": ("WSTG-INPV-19",), "cwe": ("CWE-918",),
     "why": "operator-declared internal URL must be fetched and its marker returned"},
    {"unit": "idor", "exchanges": ("idor_check",),
     "wstg": ("WSTG-ATHZ-04",), "cwe": ("CWE-639",),
     "why": "authenticated read of another identity's object by id"},
    {"unit": "web_checks",
     "union": ("security_headers", "cookie_flags", "cors", "sensitive_paths",
               "version_signals", "open_redirect", "reflected_xss", "sqli",
               "sqli_union", "ssti", "path_traversal", "auth_bypass", "file_upload",
               "ssrf", "idor"),
     "why": "the intent role that runs every WebChecks method above"},
    {"unit": "nuclei",
     "wstg": ("WSTG-CONF-02", "WSTG-CONF-04"), "cwe": (),
     "why": "template-dependent: misconfiguration and exposed-file families only"},
    {"unit": "nmap",
     "wstg": ("WSTG-CONF-01",), "cwe": (),
     "why": "port/service enumeration is the evidence base for the network config test"},
    {"unit": "ffuf",
     "wstg": ("WSTG-CONF-04", "WSTG-CONF-05"), "cwe": (),
     "why": "wordlist discovery of unreferenced files and admin paths"},
    {"unit": "zap_baseline",
     "wstg": ("WSTG-CONF-02", "WSTG-CONF-07", "WSTG-SESS-02", "WSTG-CLNT-09"), "cwe": (),
     "why": "passive ZAP rules cover headers, cookies, HSTS and frame options"},
    {"unit": "tls_audit",
     "wstg": ("WSTG-CRYP-01",), "cwe": ("CWE-326", "CWE-297", "CWE-298"),
     "why": "audit_tls checks expiry, hostname match and protocol/cipher strength"},
    {"unit": "infra_scan", "tools": ("nmap",), "alias_evidence": ("tls_audit",),
     "wstg": ("WSTG-CONF-01", "WSTG-CRYP-01"), "cwe": ("CWE-326", "CWE-297", "CWE-298"),
     "why": "infra intent runs tls_audit then nmap"},
    {"unit": "api_audit", "exchanges": ("api_check", "api_login"),
     "wstg": ("WSTG-ATHN-04", "WSTG-ATHZ-02", "WSTG-ATHZ-03", "WSTG-ATHZ-04"),
     "cwe": {"WSTG-ATHN-04": ("CWE-306",), "WSTG-ATHZ-02": ("CWE-200", "CWE-285"),
             "WSTG-ATHZ-03": ("CWE-285",), "WSTG-ATHZ-04": ("CWE-639",)},
     "why": "OpenAPI-driven BOLA/BFLA/mass-assignment/missing-auth object probes"},
    {"unit": "graphql_audit", "exchanges": ("graphql_check", "graphql_login"),
     "wstg": ("WSTG-ATHZ-02", "WSTG-ATHZ-04", "WSTG-INPV-05"),
     "cwe": {"WSTG-ATHZ-02": ("CWE-639",), "WSTG-ATHZ-04": ("CWE-639",),
             "WSTG-INPV-05": ("CWE-89",)},
     "why": "introspection, per-role BOLA/BFLA queries and injection probes"},
    {"unit": "web", "union": ("web_checks",),
     "why": "agent web role drives the same WebChecks methods"},
    {"unit": "api", "union": ("api_audit",),
     "why": "agent api role drives the same api_audit probes"},
    {"unit": "authz",
     "wstg": ("WSTG-ATHN-04", "WSTG-ATHZ-02", "WSTG-ATHZ-03", "WSTG-ATHZ-04"),
     "cwe": {"WSTG-ATHN-04": ("CWE-306",), "WSTG-ATHZ-02": ("CWE-285",),
             "WSTG-ATHZ-03": ("CWE-285",), "WSTG-ATHZ-04": ("CWE-639",)},
     "why": "agent authz role attempts authentication and object/function authorization bypasses"},
    {"unit": "infra", "wstg": ("WSTG-CONF-01", "WSTG-CRYP-01"),
     "cwe": ("CWE-326", "CWE-297", "CWE-298"),
     "why": "agent infra role runs TLS audit and host scans"},
    {"unit": "jwt_audit", "why": "forges tokens against the declared verifier and reports only what the app accepted",
     "wstg": ("WSTG-SESS-01", "WSTG-ATHN-04"), "cwe": ("CWE-347", "CWE-345", "CWE-613")},
    {"unit": "oauth_audit", "why": "redirect_uri bypass matrix, state and PKCE checks against the declared client",
     "wstg": ("WSTG-ATHN-04", "WSTG-CLNT-04"), "cwe": ("CWE-601", "CWE-352", "CWE-863")},
    {"unit": "session_audit", "why": "login, fixation, logout invalidation and cookie scope for one identity",
     "wstg": ("WSTG-SESS-03", "WSTG-SESS-06", "WSTG-SESS-02"), "cwe": ("CWE-384", "CWE-613", "CWE-614")},
    {"unit": "privesc_audit", "why": "endpoint x identity matrix; findings only where a control comparison contradicts",
     "wstg": ("WSTG-ATHZ-02", "WSTG-ATHZ-03"), "cwe": ("CWE-284", "CWE-285", "CWE-306", "CWE-639")},
    {"unit": "injection_audit",
     "why": "XXE (direct and out-of-band), blind time-based command injection, LFI/traversal encodings, CRLF headers",
     "wstg": ("WSTG-INPV-07", "WSTG-INPV-12", "WSTG-ATHZ-01", "WSTG-INPV-15"),
     "cwe": ("CWE-611", "CWE-78", "CWE-22", "CWE-113")},
    {"unit": "web_protocol_audit",
     "why": "host header injection, unkeyed cache poisoning, parameter pollution, method tampering, smuggling detection",
     "wstg": ("WSTG-INPV-17", "WSTG-INPV-04", "WSTG-INPV-03", "WSTG-INPV-15"),
     "cwe": ("CWE-644", "CWE-525", "CWE-235", "CWE-650", "CWE-444")},
    {"unit": "code_audit", "wstg": (), "cwe": (),
     "why": "static source scan: WSTG 4.2 has no source-review test, so no test is claimed"},
)

# Units that record state but test no WSTG ID; kept explicit so the gap is readable.
UNMAPPED = {
    "verify": "replays a candidate's proof; tests nothing new",
    "report": "renders the report",
    "container_scan": "image CVEs, not a web test",
    "correlator": "reads recorded state, no target traffic",
    "risk": "scores recorded findings, no target traffic",
    "delegate": "scheduling action",
    "run_baseline": "runs the web_checks surface, whose methods are already mapped",
    "http_write": "permission marker for agent write requests, not a test",
    "subfinder": "subdomain enumeration feeds recon but tests no WSTG 4.2 test",
}

# Tests with no possible Libella check because the evidence sits outside the
# engagement model (host, cloud account, mail server, server logs).
NOT_SUPPORTED = {
    "WSTG-CONF-09": "file permissions need host filesystem access, outside the url/repo/ip scope kinds",
    "WSTG-CONF-11": "cloud storage inventory needs a cloud account, not a web target",
    "WSTG-INPV-10": "IMAP/SMTP injection needs a mail server target, which the scope model does not have",
    "WSTG-INPV-16": "incoming-request review needs server logs, which the engine never reads",
    "WSTG-CLNT-08": "Flash/Silverlight is retired; no check exists and no manual route is meaningful",
}

# No automated check exists but a tester can perform the test by hand.
MANUAL_REASONS = {
    "WSTG-INFO": "no Libella check: search/metafile/architecture review is a human task",
    "WSTG-CONF": "no Libella check: this deployment setting needs manual review",
    "WSTG-IDNT": "no Libella check: role, registration and provisioning flows need a human walkthrough",
    "WSTG-ATHN": "no Libella check: this authentication behaviour needs manual attempts",
    "WSTG-ATHZ": "no Libella check: this authorization boundary needs manual role work",
    "WSTG-SESS": "no Libella check: this session behaviour needs a manual browser run",
    "WSTG-INPV": "no Libella check for this injection class; needs manual payload work",
    "WSTG-ERRH": "no Libella check: error and stack-trace exposure is inspected by hand",
    "WSTG-CRYP": "no Libella check: needs manual cryptography review of the application",
    "WSTG-BUSL": "no Libella check: business-logic abuse needs the intended behaviour understood by hand",
    "WSTG-CLNT": "no Libella check: this client-side behaviour needs manual browser work",
}
MANUAL_OVERRIDES = {
    "WSTG-ATHN-02": "Libella only tries supplied credentials; default-credential guessing is a spray",
    "WSTG-INPV-06": "no LDAP client in the engine",
}


def _expand(rows):
    """Resolve `union` rows so each row lists real IDs and a per-test CWE map.

    A flat `cwe` tuple applies to every mapped test; a dict scopes a CWE to the
    test whose check actually emits it (a SQLi finding is not BOLA evidence).
    """
    out = []
    for r in rows:
        if "union" in r:
            wstg, cwe = [], {}
            for unit in r["union"]:
                src = next(o for o in out if o["unit"] == unit)  # union members precede
                wstg += src["wstg"]
                for test, cwes in src["cwe_by_test"].items():
                    cwe[test] = tuple(dict.fromkeys(cwe.get(test, ()) + tuple(cwes)))
            r = {**r, "wstg": tuple(dict.fromkeys(wstg)), "cwe_by_test": cwe}
        else:
            flat = tuple(r.get("cwe") or ())
            cwe = r["cwe"] if isinstance(r["cwe"], dict) else {t: flat for t in r["wstg"]}
            r = {**r, "cwe_by_test": {t: tuple(cwes) for t, cwes in cwe.items()}}
        out.append(r)
    return out


CHECKS = {r["unit"]: r for r in _expand(ROWS)}
TESTS = {}
for _row in CHECKS.values():
    for _test in _row["wstg"]:
        TESTS.setdefault(_test, []).append(_row["unit"])
EXCHANGE_UNIT = {name: r["unit"] for r in CHECKS.values() for name in r.get("exchanges", ())}
# Unit -> the role rows that run it, so an exchange's parent intent stays visible.
PARENTS = {u: tuple(r["unit"] for r in CHECKS.values() if u in r.get("union", ()))
           for u in CHECKS}
def tests_for(unit: str) -> tuple:
    return CHECKS[unit]["wstg"]


def units_for(test_id: str) -> tuple:
    return tuple(TESTS.get(test_id, ()))


def findings_for(test_id: str, findings) -> list:
    """Findings whose CWE is emitted by a check mapped to this test."""
    units = [u for u in units_for(test_id) if "union" not in CHECKS[u]] or list(units_for(test_id))
    cwes = {c for u in units for c in CHECKS[u]["cwe_by_test"].get(test_id, ())}
    return [f for f in findings if f["cwe"] in cwes]


def manual_reason(test_id: str) -> str:
    if test_id in MANUAL_OVERRIDES:
        return MANUAL_OVERRIDES[test_id]
    return MANUAL_REASONS.get(test_id.rsplit("-", 1)[0], "no Libella check")
