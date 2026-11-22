"""Deterministic assessment policy: the profile is an enforced ceiling.

passive              read-only observation: page fetches and fingerprints, static
                     source/image audits, GET-only header/cookie/CORS/probe checks.
production_safe      the passive surface only, with no active unit permitted. The
                     ceiling for engagements that must stay read-only in production.
safe_active          adds the active checks the engine has always run (injection
                     probes, uploads, authenticated checks, scanners). Default.
advanced_validation  same check surface as safe_active; the scope flag of the same
                     name adds independent replay proof for candidates.

MIN_PROFILE maps every intent role, agent role, check and tool to the least
profile allowed to run it. An unlisted unit is refused: adding a check without a
policy entry can never widen a passive engagement.
"""

PROFILES = ("passive", "production_safe", "safe_active", "advanced_validation")
DEFAULT_PROFILE = "safe_active"

MIN_PROFILE = {
    # deterministic intent roles
    "recon": "passive", "crawl": "passive", "verify": "passive", "report": "passive",
    "web_checks": "passive", "code_audit": "passive", "container_scan": "passive",
    "nuclei_scan": "safe_active", "infra_scan": "safe_active",
    "api_audit": "safe_active", "graphql_audit": "safe_active",
    # offence: token, OAuth, session and role-boundary audits are active but bounded
    "jwt_audit": "safe_active", "oauth_audit": "safe_active",
    "session_audit": "safe_active", "privesc_audit": "safe_active",
    # agent specialist roles
    "web": "safe_active", "api": "safe_active", "authz": "safe_active",
    "infra": "safe_active", "correlator": "passive", "risk": "passive",
    # WebChecks methods
    "security_headers": "passive", "cors": "passive", "sensitive_paths": "passive",
    "version_signals": "passive", "cookie_flags": "passive", "open_redirect": "passive",
    "reflected_xss": "safe_active", "sqli": "safe_active", "ssti": "safe_active",
    "path_traversal": "safe_active", "auth_bypass": "safe_active", "file_upload": "safe_active",
    "ssrf": "safe_active", "idor": "safe_active", "sqli_union": "safe_active",
    # external tools
    "httpx": "passive", "subfinder": "passive",
    "nuclei": "safe_active", "nmap": "safe_active", "ffuf": "safe_active",
    # agent actions
    "run_baseline": "safe_active", "http_write": "safe_active", "delegate": "passive",
}


def _rank(profile: str) -> int:
    """Unknown or absent profile ranks strictest: never widen permission by accident."""
    return PROFILES.index(profile) if profile in PROFILES else 0


def permits(unit: str, profile: str) -> bool:
    need = MIN_PROFILE.get(unit)
    return need is not None and _rank(profile) >= PROFILES.index(need)
