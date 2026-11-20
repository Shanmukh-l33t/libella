"""OWASP WSTG 4.2 coverage ledger for defensive/manual review.

The catalog is the framework's own test list (IDs and titles verbatim from
v4.2). An operator records what was reviewed: a test is `covered` only with
evidence from the same engagement, `manual`/`unsupported` need a written reason,
and everything unrecorded stays `unknown`. Nothing here plans, queues or runs a
tool.
"""
import time

from .db import DB

FRAMEWORK = {
    "id": "OWASP-WSTG",
    "version": "4.2",
    "title": "OWASP Web Security Testing Guide",
    "source": "https://owasp.org/www-project-web-security-testing-guide/v42/",
}
CATEGORIES = (
    ("WSTG-INFO", "Information Gathering"),
    ("WSTG-CONF", "Configuration and Deployment Management Testing"),
    ("WSTG-IDNT", "Identity Management Testing"),
    ("WSTG-ATHN", "Authentication Testing"),
    ("WSTG-ATHZ", "Authorization Testing"),
    ("WSTG-SESS", "Session Management Testing"),
    ("WSTG-INPV", "Input Validation Testing"),
    ("WSTG-ERRH", "Testing for Error Handling"),
    ("WSTG-CRYP", "Testing for Weak Cryptography"),
    ("WSTG-BUSL", "Business Logic Testing"),
    ("WSTG-CLNT", "Client-side Testing"),
)
CATALOG = (
    ("WSTG-INFO-01", "Conduct Search Engine Discovery Reconnaissance for Information Leakage"),
    ("WSTG-INFO-02", "Fingerprint Web Server"),
    ("WSTG-INFO-03", "Review Webserver Metafiles for Information Leakage"),
    ("WSTG-INFO-04", "Enumerate Applications on Webserver"),
    ("WSTG-INFO-05", "Review Webpage Content for Information Leakage"),
    ("WSTG-INFO-06", "Identify Application Entry Points"),
    ("WSTG-INFO-07", "Map Execution Paths Through Application"),
    ("WSTG-INFO-08", "Fingerprint Web Application Framework"),
    ("WSTG-INFO-09", "Fingerprint Web Application"),
    ("WSTG-INFO-10", "Map Application Architecture"),
    ("WSTG-CONF-01", "Test Network Infrastructure Configuration"),
    ("WSTG-CONF-02", "Test Application Platform Configuration"),
    ("WSTG-CONF-03", "Test File Extensions Handling for Sensitive Information"),
    ("WSTG-CONF-04", "Review Old Backup and Unreferenced Files for Sensitive Information"),
    ("WSTG-CONF-05", "Enumerate Infrastructure and Application Admin Interfaces"),
    ("WSTG-CONF-06", "Test HTTP Methods"),
    ("WSTG-CONF-07", "Test HTTP Strict Transport Security"),
    ("WSTG-CONF-08", "Test RIA Cross Domain Policy"),
    ("WSTG-CONF-09", "Test File Permission"),
    ("WSTG-CONF-10", "Test for Subdomain Takeover"),
    ("WSTG-CONF-11", "Test Cloud Storage"),
    ("WSTG-IDNT-01", "Test Role Definitions"),
    ("WSTG-IDNT-02", "Test User Registration Process"),
    ("WSTG-IDNT-03", "Test Account Provisioning Process"),
    ("WSTG-IDNT-04", "Testing for Account Enumeration and Guessable User Account"),
    ("WSTG-IDNT-05", "Testing for Weak or Unenforced Username Policy"),
    ("WSTG-ATHN-01", "Testing for Credentials Transported over an Encrypted Channel"),
    ("WSTG-ATHN-02", "Testing for Default Credentials"),
    ("WSTG-ATHN-03", "Testing for Weak Lock Out Mechanism"),
    ("WSTG-ATHN-04", "Testing for Bypassing Authentication Schema"),
    ("WSTG-ATHN-05", "Testing for Vulnerable Remember Password"),
    ("WSTG-ATHN-06", "Testing for Browser Cache Weaknesses"),
    ("WSTG-ATHN-07", "Testing for Weak Password Policy"),
    ("WSTG-ATHN-08", "Testing for Weak Security Question Answer"),
    ("WSTG-ATHN-09", "Testing for Weak Password Change or Reset Functionalities"),
    ("WSTG-ATHN-10", "Testing for Weaker Authentication in Alternative Channel"),
    ("WSTG-ATHZ-01", "Testing Directory Traversal File Include"),
    ("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema"),
    ("WSTG-ATHZ-03", "Testing for Privilege Escalation"),
    ("WSTG-ATHZ-04", "Testing for Insecure Direct Object References"),
    ("WSTG-SESS-01", "Testing for Session Management Schema"),
    ("WSTG-SESS-02", "Testing for Cookies Attributes"),
    ("WSTG-SESS-03", "Testing for Session Fixation"),
    ("WSTG-SESS-04", "Testing for Exposed Session Variables"),
    ("WSTG-SESS-05", "Testing for Cross Site Request Forgery"),
    ("WSTG-SESS-06", "Testing for Logout Functionality"),
    ("WSTG-SESS-07", "Testing Session Timeout"),
    ("WSTG-SESS-08", "Testing for Session Puzzling"),
    ("WSTG-SESS-09", "Testing for Session Hijacking"),
    ("WSTG-INPV-01", "Testing for Reflected Cross Site Scripting"),
    ("WSTG-INPV-02", "Testing for Stored Cross Site Scripting"),
    ("WSTG-INPV-03", "Testing for HTTP Verb Tampering"),
    ("WSTG-INPV-04", "Testing for HTTP Parameter Pollution"),
    ("WSTG-INPV-05", "Testing for SQL Injection"),
    ("WSTG-INPV-06", "Testing for LDAP Injection"),
    ("WSTG-INPV-07", "Testing for XML Injection"),
    ("WSTG-INPV-08", "Testing for SSI Injection"),
    ("WSTG-INPV-09", "Testing for XPath Injection"),
    ("WSTG-INPV-10", "Testing for IMAP SMTP Injection"),
    ("WSTG-INPV-11", "Testing for Code Injection"),
    ("WSTG-INPV-12", "Testing for Command Injection"),
    ("WSTG-INPV-13", "Testing for Format String Injection"),
    ("WSTG-INPV-14", "Testing for Incubated Vulnerability"),
    ("WSTG-INPV-15", "Testing for HTTP Splitting Smuggling"),
    ("WSTG-INPV-16", "Testing for HTTP Incoming Requests"),
    ("WSTG-INPV-17", "Testing for Host Header Injection"),
    ("WSTG-INPV-18", "Testing for Server-side Template Injection"),
    ("WSTG-INPV-19", "Testing for Server-Side Request Forgery"),
    ("WSTG-ERRH-01", "Testing for Improper Error Handling"),
    ("WSTG-ERRH-02", "Testing for Stack Traces"),
    ("WSTG-CRYP-01", "Testing for Weak Transport Layer Security"),
    ("WSTG-CRYP-02", "Testing for Padding Oracle"),
    ("WSTG-CRYP-03", "Testing for Sensitive Information Sent via Unencrypted Channels"),
    ("WSTG-CRYP-04", "Testing for Weak Encryption"),
    ("WSTG-BUSL-01", "Test Business Logic Data Validation"),
    ("WSTG-BUSL-02", "Test Ability to Forge Requests"),
    ("WSTG-BUSL-03", "Test Integrity Checks"),
    ("WSTG-BUSL-04", "Test for Process Timing"),
    ("WSTG-BUSL-05", "Test Number of Times a Function Can Be Used Limits"),
    ("WSTG-BUSL-06", "Testing for the Circumvention of Work Flows"),
    ("WSTG-BUSL-07", "Test Defenses Against Application Misuse"),
    ("WSTG-BUSL-08", "Test Upload of Unexpected File Types"),
    ("WSTG-BUSL-09", "Test Upload of Malicious Files"),
    ("WSTG-CLNT-01", "Testing for DOM-Based Cross Site Scripting"),
    ("WSTG-CLNT-02", "Testing for JavaScript Execution"),
    ("WSTG-CLNT-03", "Testing for HTML Injection"),
    ("WSTG-CLNT-04", "Testing for Client-side URL Redirect"),
    ("WSTG-CLNT-05", "Testing for CSS Injection"),
    ("WSTG-CLNT-06", "Testing for Client-side Resource Manipulation"),
    ("WSTG-CLNT-07", "Testing Cross Origin Resource Sharing"),
    ("WSTG-CLNT-08", "Testing for Cross Site Flashing"),
    ("WSTG-CLNT-09", "Testing for Clickjacking"),
    ("WSTG-CLNT-10", "Testing WebSockets"),
    ("WSTG-CLNT-11", "Testing Web Messaging"),
    ("WSTG-CLNT-12", "Testing Browser Storage"),
    ("WSTG-CLNT-13", "Testing for Cross Site Script Inclusion"),
)
TITLES = dict(CATALOG)
STATUSES = ("covered", "manual", "unsupported", "unknown")
NOTE_MAX = 2000


def _engagement(db: DB, engagement_id: str):
    if not db.one("SELECT id FROM engagements WHERE id=?", (engagement_id,)):
        raise LookupError("engagement not found")


def workspace(db: DB, engagement_id: str) -> dict:
    """Catalog + recorded coverage for one engagement; unrecorded tests are unknown."""
    _engagement(db, engagement_id)
    recorded = {r["test_id"]: r for r in db.query(
        "SELECT * FROM coverage_entries WHERE engagement_id=?", (engagement_id,))}
    summary = {s: 0 for s in STATUSES}
    summary["total"] = len(CATALOG)
    categories = []
    for prefix, name in CATEGORIES:
        tests, counts = [], {s: 0 for s in STATUSES}
        for test_id, title in CATALOG:
            if not test_id.startswith(prefix + "-"):
                continue
            row = recorded.get(test_id) or {}
            status = row["status"] if row.get("status") in STATUSES else "unknown"
            counts[status] += 1
            summary[status] += 1
            tests.append({"id": test_id, "title": title, "status": status,
                          "note": row.get("note"), "evidence_id": row.get("evidence_id"),
                          "updated_at": row.get("updated_at")})
        categories.append({"id": prefix, "name": name, "counts": counts, "tests": tests})
    return {"framework": {**FRAMEWORK, "tests": len(CATALOG)},
            "engagement_id": engagement_id, "summary": summary, "categories": categories}


def record(db: DB, engagement_id: str, test_id: str, status, note=None,
           evidence_id=None) -> dict:
    """Record one review outcome. Returns the refreshed workspace.

    covered: needs evidence_id that exists in this engagement.
    manual / unsupported: need a note saying what was done or why it cannot be.
    unknown: clears the entry. Raises LookupError (unknown engagement/test) or
    ValueError (bad status, missing justification, foreign evidence).
    """
    _engagement(db, engagement_id)
    if test_id not in TITLES:
        raise LookupError(f"unknown WSTG test {test_id}")
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    if status == "unknown":
        db.execute("DELETE FROM coverage_entries WHERE engagement_id=? AND test_id=?",
                   (engagement_id, test_id))
        return workspace(db, engagement_id)

    note = (note or "").strip() if isinstance(note, str) else note
    if note is not None and not isinstance(note, str):
        raise ValueError("note must be a string")
    if len(note or "") > NOTE_MAX:
        raise ValueError(f"note exceeds {NOTE_MAX} characters")
    if status in ("manual", "unsupported") and not note:
        raise ValueError(f"{status} needs a note explaining the review")
    if evidence_id and status != "covered":
        raise ValueError("evidence_id only applies to covered tests")
    if status == "covered":
        if not evidence_id:
            raise ValueError("covered needs an evidence_id from this engagement")
        ev = db.one("SELECT engagement_id FROM evidence WHERE id=?", (evidence_id,))
        if ev is None:
            raise ValueError("evidence not found")
        if ev["engagement_id"] != engagement_id:
            raise ValueError("evidence belongs to another engagement")

    db.execute(
        "INSERT INTO coverage_entries(engagement_id, test_id, status, note, evidence_id, "
        "updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(engagement_id, test_id) DO UPDATE SET "
        "status=excluded.status, note=excluded.note, evidence_id=excluded.evidence_id, "
        "updated_at=excluded.updated_at",
        (engagement_id, test_id, status, note, evidence_id if status == "covered" else None,
         time.time()))
    return workspace(db, engagement_id)
