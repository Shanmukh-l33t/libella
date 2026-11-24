"""Engagement-scoped target credentials: sealed at rest, tested honestly.

A credential belongs to an EXISTING engagement and can only be presented to a URL
that engagement's Scope already authorizes. Nothing here widens scope, follows a
redirect, or returns a stored value: a 200 alone is reported as "responded
success", never as authorization.

Storage: the whole secret object is one Fernet ciphertext (app.box), so a custom
header name cannot leak a value through a redaction allowlist.
"""
import base64
import json
import re
import time
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from .assessment_window import stored_window_refusal
from .db import new_id

TYPES = ("bearer", "header", "basic", "cookie", "oauth_client_credentials")
TIMEOUT = 10.0
VALUE_MAX = 4096
EXPECT_MAX = 200
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
# Sending these through a client-level default would break framing or the connection.
FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "upgrade",
                     "te", "trailer", "proxy-connection", "keep-alive", "expect"}

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS target_credentials("
    "id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, type TEXT NOT NULL, name TEXT NOT NULL, "
    "header_name TEXT, meta_json TEXT NOT NULL DEFAULT '{}', secret_enc TEXT NOT NULL, "
    "created_at REAL, last_test_at REAL, last_test_json TEXT)"
)

MESSAGES = {
    "accepted": "The endpoint returned {status} and the expected marker was present. "
                "This confirms the credential reached an authenticated response for this URL.",
    "responded_success": "The endpoint returned {status} but the response did not contain the "
                         "expected identity marker. A 200 alone does not prove the credential is "
                         "authorized: it can be a public page, a login screen, or a header the "
                         "server ignores. Add a marker only your authenticated identity sees.",
    "rejected": "The endpoint rejected the credential with {status}. Check the value, the header "
                "scheme, and the account's permissions.",
    "redirect": "The endpoint answered {status} and pointed to {host}. Redirects are never "
                "followed here, so the credential was not sent to another origin. A redirect "
                "usually means this URL did not accept the credential (often a login page).",
    "server_error": "The endpoint returned {status} (server error). That is not an authentication "
                    "result; retry when the target is healthy.",
    "error": "The credential test did not complete: {detail}. No authorization conclusion.",
}


def ensure_schema(db):
    db.execute(SCHEMA)
    db.execute("CREATE INDEX IF NOT EXISTS idx_target_creds_eng "
               "ON target_credentials(engagement_id)")


def _text(value, field: str, limit: int = VALUE_MAX, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{field} must not contain control characters")
    if len(value) > limit:
        raise ValueError(f"{field} is longer than {limit} characters")
    if required and not value.strip():
        raise ValueError(f"{field} is required")
    return value


def _header_safe(value: str, field: str) -> str:
    if not value.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError(f"{field} must be printable ASCII and contain no spaces")
    return value


def _url(value, field: str = "url") -> str:
    text = _text(value, field, 2048)
    try:
        p = urlparse(text)
        port = p.port
    except ValueError:
        raise ValueError(f"{field} has an invalid port") from None
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError(f"{field} must be an absolute http or https URL")
    if p.username or p.password:
        raise ValueError(f"{field} must not embed credentials")
    if port == 0:
        raise ValueError(f"{field} has an invalid port")
    return text


def parse(body) -> dict:
    """Validated credential fields; the secret half stays separate until sealed."""
    if not isinstance(body, dict):
        raise ValueError("credential must be an object")
    kind = body.get("type")
    if kind not in TYPES:
        raise ValueError("type must be one of " + ", ".join(TYPES))
    name = _text(body.get("name") or kind, "name", 120)
    meta, secret = {}, {}
    header_name = "Authorization"
    if kind == "bearer":
        secret["value"] = _header_safe(_text(body.get("value"), "value"), "value")
    elif kind == "header":
        header_name = _text(body.get("header_name"), "header_name", 64)
        if not HEADER_NAME_RE.match(header_name) or header_name.lower() in FORBIDDEN_HEADERS:
            raise ValueError("header_name must be a plain header name that is not hop-by-hop")
        secret["value"] = _header_safe(_text(body.get("value"), "value"), "value")
    elif kind == "basic":
        secret["username"] = _text(body.get("username"), "username", 256)
        secret["password"] = _text(body.get("password"), "password")
    elif kind == "cookie":
        header_name = "Cookie"
        secret["value"] = _header_safe(_text(body.get("value"), "value"), "value")
    else:
        meta["token_url"] = _url(body.get("token_url"), "token_url")
        meta["client_id"] = _text(body.get("client_id"), "client_id", 256)
        meta["scope"] = _text(body.get("scope") or "", "scope", 256, required=False)
        secret["client_secret"] = _text(body.get("client_secret"), "client_secret")
    return {"type": kind, "name": name, "header_name": header_name,
            "meta": meta, "secret": secret}


def public_row(row: dict) -> dict:
    """Display shape: identity, never a value and never ciphertext."""
    meta = json.loads(row.get("meta_json") or "{}")
    return {"id": row["id"], "type": row["type"], "name": row["name"],
            "header_name": row["header_name"], "token_url": meta.get("token_url"),
            "created_at": row["created_at"],
            "last_test": json.loads(row.get("last_test_json") or "null")}


def _auth_headers(row: dict, secret: dict, meta: dict) -> dict:
    kind = row["type"]
    if kind == "oauth_client_credentials":
        raw = f"{meta.get('client_id', '')}:{secret.get('client_secret', '')}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    if kind == "basic":
        raw = f"{secret.get('username', '')}:{secret.get('password', '')}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    if kind == "bearer":
        return {"Authorization": "Bearer " + secret["value"]}
    if kind == "cookie":
        return {"Cookie": secret["value"]}
    return {row["header_name"]: secret["value"]}


def _host_only(url: str) -> str | None:
    """Host:port of a URL, for reporting a redirect target without its path or query."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        port = p.port
    except ValueError:
        return None
    return f"{p.hostname}:{port or (443 if p.scheme == 'https' else 80)}"


def _display_url(url: str) -> str:
    """The tested URL without query, fragment or userinfo (tokens ride in queries)."""
    p = urlparse(url)
    return f"{p.scheme}://{p.hostname}{':' + str(p.port) if p.port else ''}{p.path}"


def _result(classification: str, *, status=None, url=None, location_host=None,
            evidence_id=None, exchange_id=None, detail: str = "") -> dict:
    host = location_host or "another origin"
    message = MESSAGES[classification].format(status=status, host=host, detail=detail)
    return {"classification": classification, "status": status, "message": message,
            "url": url, "location_host": location_host, "evidence_id": evidence_id,
            "exchange_id": exchange_id, "tested_at": time.time()}


def _refused(reason: str, url: str | None = None) -> dict:
    return {"classification": "refused", "status": None,
            "message": f"Refused before any request: {reason}.",
            "url": url, "location_host": None, "evidence_id": None,
            "exchange_id": None, "tested_at": time.time()}


def run_test(app, scope, engagement_id: str, row: dict, url, expect: str | None) -> dict:
    """One bounded request through the platform probe; scope and window decide first."""

    def finish(out: dict) -> dict:
        app.db.execute(
            "UPDATE target_credentials SET last_test_at=?, last_test_json=? "
            "WHERE id=? AND engagement_id=?",
            (out["tested_at"], json.dumps(out), row["id"], engagement_id))
        app.db.emit(engagement_id, "target_credential_test",
                    {"credential_id": row["id"], "type": row["type"],
                     "classification": out["classification"], "status": out["status"],
                     "url": out["url"]})
        return out

    category = next((c for c in ("api", "web") if c in scope.categories), None)
    if category is None:
        return finish(_refused("this engagement does not permit web or api requests"))
    meta = json.loads(row.get("meta_json") or "{}")
    if row["type"] == "oauth_client_credentials":
        if url != meta.get("token_url"):  # a token request goes nowhere else
            raise ValueError("an oauth credential can only be tested at its token_url")
    url = _url(url)
    refusal = stored_window_refusal(app.db, engagement_id)
    if refusal:
        return finish(_refused(refusal, _display_url(url)))
    decision = scope.check_url(url, category)
    if not decision.allowed:
        return finish(_refused(decision.reason, _display_url(url)))

    secret = json.loads(app.box.decrypt(row["secret_enc"]))
    headers, body, method = _auth_headers(row, secret, meta), None, "GET"
    if row["type"] == "oauth_client_credentials":
        form = {"grant_type": "client_credentials"}
        if meta.get("scope"):
            form["scope"] = meta["scope"]
        body, method = urlencode(form), "POST"
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    # The credential rides client defaults, not the probe's recorded headers: the
    # evidence blob redacts by header NAME, so a custom name would store the value.
    with httpx.Client(timeout=TIMEOUT, verify=True, trust_env=False, headers=headers) as client:
        result = app.probe.request(engagement_id, scope, url, method=method, body=body,
                                   category=category, client=client, follow_redirects=False,
                                   tool="target_credential_test")
    return finish(_classify(result, url, _display_url(url), expect))


def _classify(probe_result: dict, url: str, shown: str, expect: str | None) -> dict:
    if not probe_result.get("ok"):
        error = str(probe_result.get("error") or "")
        low = error.lower()
        if "out_of_scope" in error or "window" in low:
            return _refused(error.split(": ", 1)[-1], shown)
        if "peer_ip_mismatch" in error:
            return _refused("the address that answered is not the address the scope authorized "
                            "(possible DNS rebinding)", shown)
        detail = ("the endpoint did not answer within 10 seconds" if "timeout" in low
                  else "the connection failed; check DNS, TLS and that the service is running")
        return _result("error", url=shown, detail=detail)
    status = probe_result.get("status") or 0

    def done(kind: str, **fields) -> dict:
        return _result(kind, evidence_id=probe_result.get("evidence_id"),
                       exchange_id=probe_result.get("exchange_id"), **fields)

    if 200 <= status < 300:
        body = probe_result.get("body") or ""
        kind = "accepted" if expect and expect in body else "responded_success"
        return done(kind, status=status, url=shown)
    if 300 <= status < 400:
        headers = {k.lower(): v for k, v in (probe_result.get("headers") or {}).items()}
        target = urljoin(url, headers["location"]) if headers.get("location") else None
        return done("redirect", status=status, url=shown,
                    location_host=_host_only(target) if target else None)
    if status in (401, 403):
        return done("rejected", status=status, url=shown)
    if status >= 500:
        return done("server_error", status=status, url=shown)
    return done("error", status=status, url=shown,
                detail=f"the endpoint returned an unexpected status {status}")


def insert(db, box, engagement_id: str, parsed: dict) -> str:
    """Store one sealed credential; the caller has already validated everything."""
    cid = new_id("cred")
    db.execute(
        "INSERT INTO target_credentials(id, engagement_id, type, name, header_name, meta_json, "
        "secret_enc, created_at) VALUES(?,?,?,?,?,?,?,?)",
        (cid, engagement_id, parsed["type"], parsed["name"], parsed["header_name"],
         json.dumps(parsed["meta"]), box.encrypt(json.dumps(parsed["secret"])), time.time()))
    return cid
