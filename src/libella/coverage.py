"""OWASP WSTG 4.2 coverage ledger: what was reviewed, and what was executed.

Two independent records per test, both always visible:

* automatic — derived from persisted engagement state (intents, tool calls,
  captured exchanges, degradation events, findings). It says what the run
  actually did, never what a report would like to claim.
* manual — an operator's recorded review (`covered` needs this engagement's
  evidence, `manual`/`unsupported` need a reason).

`status` is the manual record when one exists, otherwise the automatic status.
Nothing here plans, queues or runs a tool.
"""
import json
import time

from . import check_mapping as mapping
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
STATUSES = ("covered", "manual", "unsupported")  # manual review ledger
AUTO_STATUSES = ("not_applicable", "not_supported", "requires_manual", "skipped_policy",
                 "skipped_dependency", "attempted", "inconclusive", "failed",
                 "completed_no_issue", "finding_unverified", "finding_verified")
CONFIRMED_STATES = {"validated", "reported", "retested_persists"}  # == gate.CONFIRMED_STATES
COMPLETED = ("completed_no_issue", "finding_unverified", "finding_verified")
ATTEMPTED = ("attempted", "inconclusive", "failed") + COMPLETED
MANUAL_AS = {"covered": "completed_no_issue", "manual": "requires_manual",
             "unsupported": "not_supported"}
DEPENDENCY_CODES = {"missing_tool", "tool_unavailable", "image_not_local"}
NOTE_MAX = 2000

# Unit outcome -> the status the ledger shows. Ordered by what wins a merge.
_PREF = (("completed", "completed_no_issue"), ("inconclusive", "inconclusive"),
         ("failed", "failed"), ("skipped_policy", "skipped_policy"),
         ("skipped_dependency", "skipped_dependency"), ("attempted", "attempted"))
_VERB = {"completed": "executed, no finding recorded",
         "inconclusive": "ran partially (timeout/cancel), never completed",
         "failed": "failed",
         "skipped_policy": "refused by the engagement profile",
         "skipped_dependency": "not run: mapped tool or dependency is missing",
         "attempted": "scheduled or running, without a completion record"}


def _engagement(db: DB, engagement_id: str):
    row = db.one("SELECT id FROM engagements WHERE id=?", (engagement_id,))
    if not row:
        raise LookupError("engagement not found")
    return row


def _slot(slots: dict, name: str) -> dict:
    return slots.setdefault(name, {"calls": [], "exchanges": [], "intents": [],
                                   "denied": [], "missing": []})


def _unit_slots(db: DB, engagement_id: str) -> dict:
    """Index persisted execution state by the unit names the engine did record."""
    slots: dict = {}
    for r in db.query("SELECT id, tool, scope_decision, error FROM tool_calls "
                      "WHERE engagement_id=?", (engagement_id,)):
        _slot(slots, r["tool"])["calls"].append(r)
    for r in db.query("SELECT id, tool FROM exchanges WHERE engagement_id=?",
                      (engagement_id,)):
        unit = mapping.EXCHANGE_UNIT.get(r["tool"])
        if unit:
            _slot(slots, unit)["exchanges"].append(r["id"])
    for r in db.query("SELECT id, role, status FROM intents WHERE engagement_id=?",
                      (engagement_id,)):
        _slot(slots, r["role"])["intents"].append(r)
    for e in db.query("SELECT seq, payload_json FROM events WHERE engagement_id=? "
                      "AND kind='degradation'", (engagement_id,)):
        payload = json.loads(e["payload_json"])
        code = payload.get("code")
        if code == "policy_restriction":
            # the orchestrator may name several refused methods in one unit string
            for unit in str(payload.get("unit") or "").split(","):
                if unit.strip():
                    _slot(slots, unit.strip())["denied"].append(e["seq"])
        elif code in DEPENDENCY_CODES:
            detail = str(payload.get("detail") or "").lower()
            for unit, row in mapping.CHECKS.items():
                if any(tool in detail for tool in row.get("tools", ())):
                    _slot(slots, unit)["missing"].append(e["seq"])
    return slots


def _merge(slots: dict, names) -> dict:
    out = {"calls": [], "exchanges": [], "intents": [], "denied": [], "missing": []}
    for name in names:
        for key, value in slots.get(name, {}).items():
            out[key] += value
    return out


def _unit_state(s: dict):
    """What one unit's recorded evidence supports. `missing`/timeout beat a bare exit 0."""
    if s["denied"]:
        return "skipped_policy"
    if any((c["scope_decision"] or "") == "executed: ok" for c in s["calls"]) or s["exchanges"]:
        return "completed"
    if s["missing"] or any((c["error"] or "").startswith("missing_tool") for c in s["calls"]):
        return "skipped_dependency"
    if any(c["error"] in ("timeout", "cancelled") for c in s["calls"]):
        return "inconclusive"
    if any(c["error"] for c in s["calls"]):
        return "failed"
    if any(i["status"] == "done" for i in s["intents"]):
        return "completed"
    if any(i["status"] in ("blocked", "failed") for i in s["intents"]):
        return "failed"
    if any(i["status"] in ("open", "running") for i in s["intents"]):
        return "attempted"
    if any(i["status"] == "exhausted" for i in s["intents"]):
        return "inconclusive"
    return None


def _pointers(slots: dict, units, hits=()) -> dict:
    merged = _merge(slots, units)
    roles = [p for u in units for p in mapping.PARENTS.get(u, ()) if p not in units]
    merged["intents"] += _merge(slots, roles)["intents"]
    return {"tool_calls": [c["id"] for c in merged["calls"]],
            "exchanges": merged["exchanges"],
            "intents": [i["id"] for i in merged["intents"]],
            "events": merged["denied"] + merged["missing"],
            "findings": [f["id"] for f in hits]}


def _derive(test_id: str, slots: dict, findings, profile: str, web: bool):
    """Automatic status + evidence pointers for one test, from recorded execution."""
    everything = mapping.units_for(test_id)
    # per-method rows are precise; a role row (which runs all of them) only speaks
    # when no specific method is mapped, so a refused method is never masked.
    units = [u for u in everything if "union" not in mapping.CHECKS[u]] or list(everything)
    if not web:
        return {"status": "not_applicable", "units": [],
                "reason": "engagement scope has no web category"}, _pointers(slots, [])
    if not units:
        if test_id in mapping.NOT_SUPPORTED:
            return {"status": "not_supported", "units": [],
                    "reason": mapping.NOT_SUPPORTED[test_id]}, _pointers(slots, [])
        return {"status": "requires_manual", "units": [],
                "reason": mapping.manual_reason(test_id)}, _pointers(slots, [])
    states = {}
    for unit in units:
        row = mapping.CHECKS[unit]
        names = (unit, *row.get("tools", ()), *row.get("alias_evidence", ()))
        states[unit] = _unit_state(_merge(slots, names))
    hits = mapping.findings_for(test_id, findings)
    pointers = _pointers(slots, units, hits)
    if hits:
        verified = [f for f in hits if f["state"] in CONFIRMED_STATES]
        f = (verified or hits)[0]
        return {"status": "finding_verified" if verified else "finding_unverified",
                "units": units, "reason": f"finding {f['id']} ({f['cwe']}, {f['state']})"}, pointers
    for state, status in _PREF:
        named = [u for u, s in states.items() if s == state]
        if named:
            reason = f"{', '.join(named)}: {_VERB[state]}"
            if state == "skipped_policy":
                reason += f" ({profile!r})"
            return {"status": status, "units": named, "reason": reason}, pointers
    return {"status": "inconclusive", "units": units,
            "reason": f"{', '.join(units)}: mapped check never ran in this engagement"}, pointers


def workspace(db: DB, engagement_id: str) -> dict:
    """Catalog + automatic execution status + recorded review for one engagement."""
    _engagement(db, engagement_id)
    eng = db.one("SELECT scope_json, profile FROM engagements WHERE id=?", (engagement_id,))
    profile = eng["profile"]
    web = "web" in (json.loads(eng["scope_json"]).get("categories") or [])
    slots = _unit_slots(db, engagement_id)
    findings = db.query("SELECT id, cwe, state FROM findings WHERE engagement_id=?",
                        (engagement_id,))
    recorded = {r["test_id"]: r for r in db.query(
        "SELECT * FROM coverage_entries WHERE engagement_id=?", (engagement_id,))}
    statuses = {s: 0 for s in AUTO_STATUSES}
    manual = {s: 0 for s in STATUSES}
    effective = {s: 0 for s in AUTO_STATUSES}
    categories = []
    for prefix, name in CATEGORIES:
        tests, counts = [], {s: 0 for s in AUTO_STATUSES}
        for test_id, title in CATALOG:
            if not test_id.startswith(prefix + "-"):
                continue
            auto, pointers = _derive(test_id, slots, findings, profile, web)
            row = recorded.get(test_id) or {}
            review = row["status"] if row.get("status") in STATUSES else None
            entry = {"status": review, "note": row.get("note"),
                     "evidence_id": row.get("evidence_id"),
                     "updated_at": row.get("updated_at")} if review else None
            if review:
                manual[review] += 1
            statuses[auto["status"]] += 1
            counts[auto["status"]] += 1
            effective[MANUAL_AS.get(review, auto["status"])] += 1
            tests.append({"id": test_id, "title": title,
                          "status": review or auto["status"],
                          "automatic": auto, "manual": entry, "evidence": pointers})
        categories.append({"id": prefix, "name": name, "counts": counts, "tests": tests})

    completed = sum(effective[s] for s in COMPLETED)
    applicable = len(CATALOG) - effective["not_applicable"]
    summary = {
        "total": len(CATALOG), "applicable": applicable,
        "supported": applicable - effective["requires_manual"] - effective["not_supported"],
        "attempted": sum(effective[s] for s in ATTEMPTED),
        "completed": completed,
        "with_findings": effective["finding_verified"] + effective["finding_unverified"],
        "skipped": effective["skipped_policy"] + effective["skipped_dependency"],
        "manual_required": effective["requires_manual"],
        "not_tested": applicable - completed,
        "statuses": statuses, "manual": manual,
    }
    return {"framework": {**FRAMEWORK, "tests": len(CATALOG)},
            "engagement_id": engagement_id, "summary": summary,
            "categories": categories,
            "mapping": {u: {"tests": list(r["wstg"]), "why": r["why"]}
                        for u, r in mapping.CHECKS.items()}}


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
    if status not in STATUSES and status != "unknown":
        raise ValueError(f"status must be one of {', '.join(STATUSES)}, unknown")
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
