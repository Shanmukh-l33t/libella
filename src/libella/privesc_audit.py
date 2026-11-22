"""Authenticated role matrix: who reaches which endpoint.

One login per identity through the scoped probe, then exactly one request per
(endpoint, identity) pair — the matrix is the deliverable. A 2xx alone is never
a finding: every candidate carries a differential control from the same
endpoint (another identity that got 401/403, or the same request with no
cookie). Writes are exercised only when the operator declares them in
test_hints; otherwise they are recorded as unexercised and never sent.
"""
import json
import re
from urllib.parse import urlencode, urlparse

from .agent_runtime import _cookie_header
from .checks import _candidate

MAX_ENDPOINTS = 40
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ttf",
          ".svg", ".ico", ".map")
# template styles Flask/FastAPI/Spring/Express paths use for one object id
PLACEHOLDER = re.compile(r"\{[^}]*\}|<[^>]*>|:[A-Za-z_]\w*")
PAIR = re.compile(r'"[^"{}\[\],:]+"\s*:\s*(?:"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)')
QUOTE_KEYS = ("title", "name", "username", "email", "user", "report", "note", "body", "detail")
# Role ordering for the inversion check; unknown roles are left unranked.
ROLE_RANK = {"anonymous": 0, "guest": 0, "readonly": 0, "user": 0, "member": 0,
             "staff": 1, "editor": 1, "manager": 1, "admin": 2, "owner": 3, "root": 3}


def _path_of(url: str) -> str:
    return urlparse(url).path or "/"


def _fill(path: str, value) -> str:
    return PLACEHOLDER.sub(str(value), path)


def _norm(path: str) -> str:
    return "/" + PLACEHOLDER.sub("*", path.strip("/"))


def _skipped(path: str) -> bool:
    low = path.lower()
    return low.endswith(STATIC) or "logout" in low or "signout" in low


def _json(text: str):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _quote(body: str, needle: str | None = None) -> str | None:
    """Smallest verbatim JSON pair that proves access (the whole record if named)."""
    pairs = [m.group(0) for m in PAIR.finditer(body or "")]
    if not pairs:
        return None
    if needle:
        return next((p for p in pairs if needle in p.split(":", 1)[1]), None)
    preferred = [p for p in pairs if any(k in p.split(":", 1)[0].lower() for k in QUOTE_KEYS)]
    return (preferred or pairs)[0]


def _rank(role: str | None):
    return ROLE_RANK.get((role or "").lower())


def _write_declared(hints: dict, method: str, path: str) -> bool:
    """A write runs only when the operator named this exact method+path."""
    allow = hints.get("allow_writes")
    if not allow:
        return False
    declared = allow if isinstance(allow, (list, tuple, dict)) else (hints.get("write_endpoints") or [])
    if isinstance(declared, dict):
        declared = list(declared)
    want = f"{method} {_norm(path)}"
    for d in declared:
        if isinstance(d, dict):
            m, p = str(d.get("method") or "").upper(), d.get("path") or ""
        elif isinstance(d, str):
            m, _, p = d.partition(" ")
            m = m.upper()
        else:
            continue
        if m and p and f"{m} {_norm(p)}" == want:
            return True
    return False


def _endpoints(db, engagement_id, auth_json, endpoints) -> list[dict]:
    raw: list[dict] = []
    if endpoints:
        raw = [dict(e) for e in endpoints if isinstance(e, dict)]
    elif auth_json.get("openapi"):
        spec = auth_json["openapi"]
        if isinstance(spec, str):
            from .api_audit import load_openapi

            raw = load_openapi(spec)["endpoints"]
        elif isinstance(spec, dict):
            raw = [{"method": m.upper(), "path": p}
                   for p, ops in (spec.get("paths") or {}).items()
                   for m in ops if m.lower() in ("get", "post", "put", "patch", "delete")]
    else:
        for a in db.query("SELECT key, value_json FROM assets WHERE engagement_id=? AND kind='endpoint'",
                          (engagement_id,)):
            meta = json.loads(a["value_json"] or "{}")
            raw.append({"method": (meta.get("method") or "GET").upper(),
                        "path": _path_of(a["key"]),
                        "url": a["key"] if a["key"].startswith("http") else None})
    out, seen = [], set()
    for e in raw:
        path = e.get("path") or _path_of(e.get("url") or "")
        method = str(e.get("method") or "GET").upper()
        if not path.startswith("/") or _skipped(path):
            continue
        key = (method, _norm(path))
        if key in seen:
            continue
        seen.add(key)
        out.append({"method": method, "path": path, "url": e.get("url"), "obj_id": e.get("obj_id")})
        if len(out) >= MAX_ENDPOINTS:
            break
    return out


def _base(auth_json: dict, identities: list[dict]) -> str:
    if auth_json.get("base_url"):
        return auth_json["base_url"].rstrip("/")
    for ident in identities:
        p = urlparse(ident.get("login_url") or "")
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    return ""


def _crossings(rows: list[dict]) -> list[tuple[dict, dict, str]]:
    """(allowed row, refused row, kind) where the matrix contradicts itself.

    same_role: two identities with one role disagree, so the guard is not role-based.
    inverted:  a lower-ranked identity is let in where a higher-ranked one is refused.
    """
    out = []
    for row in rows:
        # object endpoints are per-object (BOLA), not per-role: they answer nothing here
        if row["class"] != "ALLOWED" or not row["role"] or PLACEHOLDER.search(row["path"]):
            continue
        for c in rows:
            if (c["identity"] == row["identity"] or c["class"] != "DENIED"
                    or c["method"] != row["method"] or c["path"] != row["path"]):
                continue
            if (c["role"] or "").lower() == row["role"].lower():
                out.append((row, c, "same_role"))
            elif (_rank(c["role"]) or 0) > (_rank(row["role"]) or 0):
                out.append((row, c, "inverted"))
    return out


def audit_role_matrix(db, evidence, probe, scope, engagement_id, auth_json, pipeline,
                      intent_id=None, endpoints=None) -> dict:
    """Log every identity in once, sweep the endpoint matrix, report contradictions."""
    auth_json = auth_json or {}
    hints = auth_json.get("test_hints") or {}
    out = {"status": "limited", "base_url": _base(auth_json, auth_json.get("identities") or []),
           "endpoints": 0, "identities": {}, "matrix": [], "candidates": [], "limitations": []}

    def limit(reason: str):
        out["limitations"].append(reason)
        pipeline.record_observation(engagement_id, intent_id, "limitation",
                                    f"role matrix: {reason}")

    def submit(cand: dict):
        res = pipeline.submit_candidate(engagement_id, cand, intent_id)
        out["candidates"].append({"finding_id": res["id"], "title": cand["title"],
                                  "cwe": cand["cwe"], "endpoint": cand["endpoint"],
                                  "quote": cand.get("quote"),
                                  "description": cand.get("description"),
                                  "deduped": res["deduped"]})

    identities = [i for i in (auth_json.get("identities") or [])
                  if isinstance(i, dict) and i.get("username") and i.get("password")]
    if len({i["username"] for i in identities}) < 2:
        limit("at least two identities with different usernames are required to compare roles")
        return out
    eps = _endpoints(db, engagement_id, auth_json, endpoints)
    if not eps:
        limit("no endpoints to sweep (no endpoints argument, OpenAPI or crawled assets)")
        return out
    base = out["base_url"]
    if not base:
        limit("no base URL: no identity login_url and no base_url in auth_json")
        return out

    # ---- one login per identity, through the scoped probe; no cookie = not logged in
    sessions: dict[str, dict] = {}
    for ident in identities:
        user = ident["username"]
        login_url = ident.get("login_url") or base + "/api/login"
        r = probe.request(
            engagement_id, scope, login_url, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode({ident.get("username_field", "username"): user,
                            ident.get("password_field", "password"): ident["password"]}),
            tool="role_login", follow_redirects=False)
        cookie = _cookie_header(r) if r.get("ok") else ""
        body = _json(r["body"]) if r.get("ok") else {}
        ok = bool(r.get("ok")) and 200 <= r["status"] < 300 and bool(cookie)
        role = (ident.get("role") or (body or {}).get("role") or "").lower()
        own = (body or {}).get("id", (body or {}).get("user_id", (body or {}).get("uid")))
        out["identities"][user] = {"authenticated": ok, "role": role, "status": r.get("status"),
                                   "own_id": own}
        if ok:
            sessions[user] = {"cookie": cookie, "role": role, "uid": own}
        else:
            limit(f"identity '{user}' could not log in (status {r.get('status')}: "
                  f"{r.get('error') or 'no session cookie'})")
    if not sessions:
        return out

    hint_ids = {u: v for u, v in (hints.get("object_ids") or {}).items() if u in sessions}
    anchor = hints.get("obj_id")
    if anchor is None:
        anchor = next(iter(hint_ids.values()), None)
    if anchor is None:
        anchor = next((s["uid"] for s in sessions.values() if s["uid"] is not None), None)
    out["endpoints"] = len(eps)

    def target(ep: dict, path: str) -> str:
        if ep.get("url") and ep["url"].startswith("http"):
            u = urlparse(ep["url"])
            return f"{u.scheme}://{u.netloc}{path}"
        return base + path

    def fetch(url: str, method: str, cookie: str | None, tool: str = "role_matrix") -> dict:
        return probe.request(engagement_id, scope, url, method=method,
                             headers={"Cookie": cookie} if cookie else None,
                             tool=tool, follow_redirects=False)

    def classify(url: str, method: str, cookie: str | None) -> tuple[str, dict]:
        r = fetch(url, method, cookie)
        if not r.get("ok"):
            return "ERROR", r
        if 300 <= r["status"] < 400:  # REDIRECT: follow once
            followed = probe.request(engagement_id, scope, url, method=method,
                                     headers={"Cookie": cookie} if cookie else None,
                                     tool="role_matrix")
            return "REDIRECT", followed if followed.get("ok") else r
        if 200 <= r["status"] < 300:
            return "ALLOWED", r
        if r["status"] in (401, 403):
            return "DENIED", r
        return "ERROR", r

    # ---- matrix: one request per (endpoint, identity), the same object id for all
    rows: list[dict] = []
    for ep in eps:
        write = ep["method"] in WRITE_METHODS
        if write and not _write_declared(hints, ep["method"], ep["path"]):
            for user, s in sessions.items():
                rows.append({"method": ep["method"], "path": ep["path"], "url": None,
                             "identity": user, "role": s["role"], "class": "UNEXERCISED",
                             "status": None, "evidence_id": None, "quote": None,
                             "note": "write not declared by the operator"})
            continue
        if PLACEHOLDER.search(ep["path"]) and (ep.get("obj_id") or anchor) is None:
            for user, s in sessions.items():
                rows.append({"method": ep["method"], "path": ep["path"], "url": None,
                             "identity": user, "role": s["role"], "class": "UNEXERCISED",
                             "status": None, "evidence_id": None, "quote": None,
                             "note": "no object id known for the path parameter"})
            continue
        url = target(ep, _fill(ep["path"], ep.get("obj_id") or anchor))
        for user, s in sessions.items():
            cls, r = classify(url, ep["method"], s["cookie"])
            rows.append({"method": ep["method"], "path": ep["path"], "url": url,
                         "identity": user, "role": s["role"], "class": cls,
                         "status": r.get("status"), "evidence_id": r.get("evidence_id"),
                         "quote": _quote(r["body"]) if cls in ("ALLOWED", "REDIRECT") else None,
                         "note": r.get("error")})

    for row in rows:
        pipeline.record_observation(
            engagement_id, intent_id, "role_matrix",
            f"{row['method']} {row['path']} as {row['identity']} ({row['role'] or 'unknown'}): "
            f"{row['class']}" + (f" {row['status']}" if row["status"] else "")
            + (f" ({row['note']})" if row["note"] else ""),
            evidence_id=row["evidence_id"])
    out["matrix"] = rows
    out["status"] = "assessed"

    # ---- missing authentication: 2xx anonymous where another identity is refused
    by_ep: dict[tuple, list[dict]] = {}
    for row in rows:
        by_ep.setdefault((row["method"], row["path"]), []).append(row)
    for (method, template), group in by_ep.items():
        if method in WRITE_METHODS:
            continue
        url = next((r["url"] for r in group if r["url"]), None)
        denied = [r for r in group if r["class"] == "DENIED"]
        if not url or not denied:
            continue
        control = denied[0]
        anon = fetch(url, method, None, tool="role_matrix_anon")
        anon_cls, anon_r = ("ALLOWED", anon) if anon.get("ok") and 200 <= anon["status"] < 300 \
            else ("DENIED" if anon.get("ok") and anon["status"] in (401, 403) else "ERROR", anon)
        quote = _quote(anon_r.get("body") or "")
        pipeline.record_observation(
            engagement_id, intent_id, "role_matrix_anonymous",
            f"{method} {template} as anonymous: {anon_cls}"
            + (f" {anon_r.get('status')}" if anon_r.get("ok") else ""),
            evidence_id=anon_r.get("evidence_id"))
        if anon_cls != "ALLOWED" or not quote:
            continue
        submit(_candidate(
            f"Missing authentication on {method} {template}",
            "CWE-306", "API2:2023 Broken Authentication", "high", "high", url,
            f"Anonymous {method} {template} returned {anon_r['status']} while "
            f"{control['identity']} ({control['role'] or 'role unknown'}) got "
            f"{control['status']} on the same endpoint. role_pair: "
            f"anonymous vs {control['role'] or 'authenticated'}({control['identity']}).",
            "Anonymous access to records that the application gates for authenticated "
            "roles: unauthenticated bulk disclosure.",
            "Require authentication on the route and deny anonymous access by default.",
            anon_r["evidence_id"], quote,
            {"method": method, "url": url},
            f"noauth:{method}:{template}"))

    # ---- object-level swap: an identity reads another identity's object
    ids = {u: s["uid"] for u, s in sessions.items() if s["uid"] is not None}
    ids.update(hint_ids)
    for ep in eps:
        if ep["method"] != "GET" or not PLACEHOLDER.search(ep["path"]):
            continue
        done = False
        for reader, s in sessions.items():
            for owner, oid in ids.items():
                if done or owner == reader or oid is None:
                    continue
                path = _fill(ep["path"], oid)
                url = target(ep, path)
                r = fetch(url, "GET", s["cookie"])
                if not (r.get("ok") and 200 <= r["status"] < 300):
                    continue
                quote = _quote(r["body"], needle=owner)
                if quote is None:
                    continue
                anon = fetch(url, "GET", None, tool="role_matrix_anon")
                if not (anon.get("ok") and anon["status"] in (401, 403)):
                    continue  # no control: anonymous is not refused here
                done = True
                submit(_candidate(
                    f"BOLA: '{reader}' reads another user's object at {path}",
                    "CWE-639", "API1:2023 Broken Object Level Authorization", "high", "high", url,
                    f"Identity {reader} ({s['role'] or 'role unknown'}, uid {s['uid']}) read {path}, "
                    f"which belongs to {owner} (uid {oid}); the response carries {owner}'s record. "
                    f"The same request without a cookie returned {anon['status']}. role_pair: "
                    f"{s['role'] or 'authenticated'}({reader}) vs {sessions[owner]['role'] or 'authenticated'}"
                    f"({owner}).",
                    "Horizontal privilege escalation: any authenticated user can enumerate every "
                    "object of this type by changing the id.",
                    "Enforce object-level ownership (or tenancy) checks on every object read.",
                    r["evidence_id"], quote,
                    {"method": "GET", "url": url, "headers": {"Cookie": s["cookie"]}},
                    f"bola:{ep['method']}:{ep['path']}"))
                break

    # ---- cross-role: the matrix contradicts itself for one role
    for row, control, kind in _crossings(rows):
        if not row["quote"] or not row["url"]:
            continue
        inverted = kind == "inverted"
        submit(_candidate(
            f"Cross-role access: '{row['identity']}' reaches {row['method']} {row['path']}",
            "CWE-285" if inverted else "CWE-284",
            "API5:2023 Broken Function Level Authorization", "high", "high", row["url"],
            f"{row['identity']} ({row['role']}) got {row['status']} on {row['method']} "
            f"{row['path']} while {control['identity']} ({control['role'] or 'role unknown'}) "
            f"got {control['status']} on the same endpoint"
            + (" — a lower role is let in where a higher role is refused."
               if inverted else " — the guard is not applied to the role it targets.")
            + f" role_pair: {row['role']}({row['identity']}) vs "
              f"{control['role'] or 'authenticated'}({control['identity']}).",
            "Function-level authorization bypass: an identity reaches data or functions its "
            "role does not grant.",
            "Check the caller's role server-side on every route; deny by default.",
            row["evidence_id"], row["quote"],
            {"method": row["method"], "url": row["url"], "headers": {"Cookie": sessions[row["identity"]]["cookie"]}},
            f"crossrole:{row['method']}:{row['path']}:{row['identity']}"))

    db.emit(engagement_id, "role_matrix_complete",
            {"base_url": base, "endpoints": len(eps), "identities": len(sessions),
             "observations": len(rows), "candidates": len(out["candidates"]),
             "limitations": len(out["limitations"])})
    return out
