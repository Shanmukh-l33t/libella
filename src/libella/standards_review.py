"""Analyst-driven checks of captured evidence; never sends target traffic."""
import json
import re

from .scope import Scope

CACHE_CONTROL = "V14.3.2"
CACHE_TEST = "Inspect the captured Cache-Control field for an explicit no-store directive."
CACHE_PREREQUISITE = "A captured response from this engagement which the analyst confirms contains sensitive data."
# Match comma-separated members without interpreting commas inside quoted strings.
_MEMBER = re.compile(r'(?:[^",]|"(?:[^"\\]|\\.)*")+|,')


def inspect_cache(db, evidence, eid, exchange_id, sensitive):
    from .tools.http_probe import mitigation

    if sensitive is not True or not isinstance(exchange_id, str) or not exchange_id:
        raise ValueError("Select an exchange and confirm that its response contains sensitive data.")
    eng = db.one("SELECT scope_json FROM engagements WHERE id=?", (eid,))
    row = db.one("SELECT e.evidence_id, e.url, e.status, e.method, e.peer_ip FROM exchanges e "
                 "JOIN evidence v ON v.id=e.evidence_id AND v.engagement_id=e.engagement_id "
                 "WHERE e.id=? AND e.engagement_id=? AND v.kind='http_exchange'", (exchange_id, eid))
    if not eng or not row:
        raise LookupError("Captured HTTP evidence not found in this engagement.")
    scope = Scope(json.loads(eng["scope_json"]))
    ips = [row["peer_ip"]] if row["peer_ip"] else []
    if not any(scope.check_url(row["url"], category=kind, ips=ips).allowed for kind in ("web", "api")):
        raise ValueError("The captured URL is not in this engagement's web or API scope.")
    outcome, reason, header_present = "inconclusive", "Capture missing or failed its integrity check.", None
    try:
        blob = evidence.read_json(row["evidence_id"])
        request, response = blob["request"], blob["response"]
        headers = {k.lower(): v for k, v in response["headers"].items()}
        body = response["body"].encode()
        if (request["url"], request["method"], response["status"]) == (row["url"], row["method"], row["status"]):
            reason = "This capture is not a successful application response with a body."
            if row["method"] != "HEAD" and row["status"] == 200 and body and not mitigation(200, headers, body):
                field = headers.get("cache-control", "")
                parts = _MEMBER.findall(field)
                header_present = "cache-control" in headers
                if "".join(parts) == field:
                    has_no_store = any(p.strip().lower() == "no-store" for p in parts)
                    outcome = "conforms" if has_no_store else "deviation"
                    reason = "Explicit no-store is present." if has_no_store else "No explicit no-store directive."
                else:
                    reason = "The Cache-Control field could not be parsed unambiguously."
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        pass
    result = {"requirement_id": CACHE_CONTROL, "exchange_id": exchange_id, "evidence_id": row["evidence_id"],
              "outcome": outcome, "reason": reason, "header_present": header_present}
    db.emit(eid, "asvs_cache_sample", result)
    return result


def cache_samples(db, eid):
    return [{**json.loads(r["payload_json"]), "seq": r["seq"], "created_at": r["created_at"]}
            for r in db.query("SELECT seq, payload_json, created_at FROM events WHERE engagement_id=? "
                              "AND kind='asvs_cache_sample' ORDER BY seq", (eid,))]
