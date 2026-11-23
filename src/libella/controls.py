"""Security control identifiers: what a check asserted, as data rather than prose.

A check that tests several controls at once (the header check, the cookie check)
records WHICH controls failed as structured ids on the finding. Standards
mappings then join on these ids, never on a finding's human-readable title, so a
missing-CSP finding can never fail the HSTS requirement.

Single-control checks do not need ids: the unit that produced the finding (from
its evidence) already identifies the control.
"""
import json

# header the security_headers check reads -> control id
HEADER_CONTROLS = {
    "content-security-policy": "header.csp",
    "x-content-type-options": "header.x_content_type_options",
    "x-frame-options": "header.x_frame_options",
    "strict-transport-security": "header.hsts",
    "referrer-policy": "header.referrer_policy",
}
# cookie attribute the cookie_flags check reads -> control id
COOKIE_CONTROLS = {"HttpOnly": "cookie.httponly", "Secure": "cookie.secure",
                   "SameSite": "cookie.samesite"}
# display name used in the header check's verification quote -> control id
_HEADER_NAMES = {"CSP": "header.csp", "X-Content-Type-Options": "header.x_content_type_options",
                 "X-Frame-Options": "header.x_frame_options", "HSTS": "header.hsts",
                 "Referrer-Policy": "header.referrer_policy"}
KNOWN = frozenset(HEADER_CONTROLS.values()) | frozenset(COOKIE_CONTROLS.values())


def from_quote(quote: str, quote_in: str) -> list:
    """Controls a legacy finding asserted, read from the check's machine-format quote.

    Only the two quote formats Libella's own checks emit are understood
    (`missing: CSP, HSTS` for header_fact, `name|HttpOnly,Secure` for cookie_fact);
    anything else yields no controls rather than a guess.
    """
    quote = quote or ""
    if quote_in == "header_fact" and quote.startswith("missing: "):
        names = [n.strip() for n in quote[len("missing: "):].split(",")]
        return sorted({_HEADER_NAMES[n] for n in names if n in _HEADER_NAMES})
    if quote_in == "cookie_fact" and "|" in quote:
        flags = quote.split("|", 1)[1].split(",")
        return sorted({COOKIE_CONTROLS[f.strip()] for f in flags if f.strip() in COOKIE_CONTROLS})
    return []


def migrate(db, evidence, engagement_id: str) -> int:
    """Backfill control ids on findings created before checks recorded them.

    Reads each finding's stored proof spec (the check's own quote), never its
    title, and marks the result `migrated` so its origin stays visible. Idempotent.
    """
    done = 0
    rows = db.query("SELECT id, evidence_ids_json FROM findings WHERE engagement_id=? "
                    "AND controls_source IS NULL AND (controls_json IS NULL OR controls_json='[]')",
                    (engagement_id,))
    for f in rows:
        controls: list = []
        for eid in json.loads(f["evidence_ids_json"] or "[]"):
            ev = db.one("SELECT kind FROM evidence WHERE id=?", (eid,))
            if not ev or ev["kind"] != "proof_spec":
                continue
            try:
                spec = json.loads(evidence.read(eid))
            except (KeyError, OSError, ValueError):
                continue
            controls = from_quote(spec.get("quote") or "", spec.get("quote_in") or "body")
            break
        # 'none' records that migration looked and found no multi-control assertion
        db.execute("UPDATE findings SET controls_json=?, controls_source=? WHERE id=?",
                   (json.dumps(controls), "migrated" if controls else "none", f["id"]))
        done += 1
    return done
