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
from pathlib import Path
from urllib.parse import urlencode, urlparse

from .agent_runtime import _cookie_header
from .authorization import PLACEHOLDER, PolicyModel, evaluate, from_openapi, from_operator, infer, served_owner
from .authorization import norm as _norm
from .checks import _candidate, _owner_of

MAX_ENDPOINTS = 40
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ttf",
          ".svg", ".ico", ".map")
PAIR = re.compile(r'"[^"{}\[\],:]+"\s*:\s*(?:"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)')
QUOTE_KEYS = ("title", "name", "username", "email", "user", "report", "note", "body", "detail")
# Role ordering for the inversion check; unknown roles are left unranked.
ROLE_RANK = {"anonymous": 0, "guest": 0, "readonly": 0, "user": 0, "member": 0,
             "staff": 1, "editor": 1, "manager": 1, "admin": 2, "owner": 3, "root": 3}


def _held_by(body: str, owner) -> tuple[str | None, object]:
    """(field, value) of the served record that names `owner`, or (None, None)."""
    data = _json(body)
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = next((v for v in data["data"].values() if isinstance(v, dict)), data)
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if isinstance(data, dict):
        for field, value in data.items():
            if isinstance(value, (str, int)) and str(value).lower() == str(owner).lower():
                return field, value
    return None, None


def _contract(identity: str, value, url: str, body: str = "", privilege: str = "",
              owner=None) -> dict:
    """Typed proof (proof.py) for an access-control claim made as `identity`.

    Ownership model: the owner is read from the served body (the field naming `owner`
    when the caller knows who it expected, else a conventional owner field), never
    assumed. Privilege model: the role whose guard was evaluated. Nothing is defaulted;
    a gap makes the verifier refuse the finding instead of validating an untested claim.
    """
    out = {"identity": {"name": identity, "value": value},
           "benign_request": {"method": "GET", "url": url}}  # same route, no credential
    if privilege:
        return {**out, "privilege": privilege}
    field, held = _held_by(body, owner) if owner is not None else (None, None)
    if field:  # the record names its owner by name: the caller is compared by name too
        return {**out, "identity": {"name": identity, "value": identity},
                "owner_field": field, "owner_value": held}
    field, held = _owner_of(body)
    return {**out, "owner_field": field, "owner_value": held}


def _path_of(url: str) -> str:
    return urlparse(url).path or "/"


def _fill(path: str, value) -> str:
    return PLACEHOLDER.sub(str(value), path)


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


CWE_BY_CLASS = {"owner_only": ("CWE-639", "API1:2023 Broken Object Level Authorization"),
                "tenant": ("CWE-639", "API1:2023 Broken Object Level Authorization"),
                "authenticated": ("CWE-306", "API2:2023 Broken Authentication")}


def _authz_pass(model, eps, rows, identities, sessions, hint_ids, fetch, target, submit,
                pipeline, engagement_id, intent_id, out, limit):
    """Judge each endpoint's content against its expected-authorization rule.

    Requests every identity plus anonymous per object, so a resource that EVERY identity
    can read is judged against who should have read it, not against the other identities.
    """
    meta = {i["username"]: i for i in identities}
    ids = {u: s["uid"] for u, s in sessions.items() if s["uid"] is not None}
    ids.update(hint_ids)
    people = [{"username": u, "uid": ids.get(u), "email": meta[u].get("email")} for u in sessions]
    verdicts, hypotheses = {}, []
    for ep in eps:
        if ep["method"] != "GET":
            continue
        label = f"GET {ep['path']}"
        rule = model.get("GET", ep["path"])
        if rule is None:
            seen = [r for r in rows if (r["method"], r["path"]) == ("GET", ep["path"])]
            verdicts[label] = {"verdict": "unknown_policy", "reasons": ["no expected-authorization rule"]}
            if len([r for r in seen if r["class"] == "ALLOWED"]) >= 2 and not any(r["class"] == "DENIED" for r in seen):
                msg = (f"{label}: every identity got the same access and no expected-authorization rule exists; "
                       f"public vs private cannot be decided. Supply a policy (operator/analyst) to validate.")
                pipeline.record_observation(engagement_id, intent_id, "authz_unknown_policy", msg)
                hypotheses.append(msg)
            continue
        templated = bool(PLACEHOLDER.search(ep["path"]))
        subjects = [(o, ids[o]) for o in sessions if o in ids] if templated else [(None, None)]
        if not subjects:
            verdicts[label] = {"verdict": "inconclusive", "reasons": ["no object ids known"]}
            continue
        obs = []
        for owner, oid in subjects:
            path = _fill(ep["path"], oid) if templated else ep["path"]
            url = target(ep, path)
            for user in [*sessions, None]:
                s = sessions.get(user)
                r = fetch(url, "GET", s["cookie"] if s else None, tool="authz_oracle")
                ok = bool(r.get("ok"))
                o = {"identity": user or "anonymous", "role": s["role"] if s else None,
                     "tenant": meta[user].get("tenant") if s else None,
                     "relation": ("anonymous" if s is None else "owner" if owner in (None, user)
                                  else "other_tenant" if None not in (meta[user].get("tenant"), meta[owner].get("tenant"))
                                  and meta[user]["tenant"] != meta[owner]["tenant"] else "other_user"),
                     "status": r.get("status") if ok else None, "mitigated": r.get("mitigated"),
                     "body": r.get("body") or "", "evidence_id": r.get("evidence_id"), "url": url,
                     "cookie": s["cookie"] if s else None, "object_owner": owner}
                if s and ok:
                    o["served_owner"], o["served_owner_of"] = served_owner(
                        o["body"], people[list(sessions).index(user)], [p for p in people if p["username"] != user])
                obs.append(o)
        res = evaluate(rule, obs)
        bad, good = res.pop("violation_obs"), res.pop("control_obs")
        verdicts[label] = res
        summary = (f"{label}: {res['verdict']} (expected {rule.access}, from {rule.source})"
                   + (f"; {'; '.join(res['reasons'])}" if res["reasons"] else ""))
        pipeline.record_observation(engagement_id, intent_id, "authz_verdict", summary,
                                    evidence_id=(bad or good or [{}])[0].get("evidence_id"))
        if res["verdict"] != "violation":
            continue
        if rule.source == "inferred":
            hypotheses.append(summary)
            pipeline.record_observation(engagement_id, intent_id, "authz_hypothesis",
                                        summary + " [hypothesis: review before reporting]",
                                        evidence_id=bad[0].get("evidence_id"))
            continue
        if not res["confirmable"]:
            limit(f"{label}: violation without a control comparison, not reported")
            continue
        v, c = bad[0], good[0]
        quote = _quote(v["body"], v["object_owner"]) or _quote(v["body"])
        if not quote or not v["evidence_id"]:
            limit(f"{label}: violation but no verbatim quote bound to evidence, not reported")
            continue
        kind = rule.access.split(":")[0]
        cwe, owasp = CWE_BY_CLASS.get(kind, ("CWE-285", "API5:2023 Broken Function Level Authorization"))
        if v["relation"] == "anonymous":
            cwe, owasp = CWE_BY_CLASS["authenticated"]
        same = v["body"] == c["body"]
        cand = _candidate(
            f"Authorization violation on {label}: {v['identity']} reads a {rule.access} resource",
            cwe, owasp, "high", "high", v["url"],
            f"Expected access '{rule.access}' (source: {rule.source}"
            + (f", {rule.note}" if rule.note else "") + f"). {v['identity']} ({v['relation']}, role "
            f"{v['role'] or 'none'}) received status {v['status']} with data"
            + (f" carrying {v['served_owner_of']}'s record" if v.get("served_owner_of") else "")
            + f"; control: {c['identity']} ({c['relation']}) is permitted and read the same URL"
            + (" with an IDENTICAL response - identical responses are not proof of correct authorization."
               if same else ".")
            + (f" Also unexpectedly granted: {', '.join(sorted(set(res['violations']) - {v['identity']}))}."
               if len(set(res["violations"])) > 1 else ""),
            "Data the policy restricts is served to identities it should refuse.",
            "Enforce the stated access rule server-side on every request; deny by default.",
            v["evidence_id"], quote,
            {"method": "GET", "url": v["url"], **({"headers": {"Cookie": v["cookie"]}} if v["cookie"] else {})},
            f"authz:GET:{_norm(ep['path'])}",
            proof=_contract(v["identity"], ids.get(v["identity"]), v["url"], v["body"],
                            owner=v["object_owner"]))
        if c["evidence_id"] and c["evidence_id"] != v["evidence_id"]:
            cand["evidence_ids"].append(c["evidence_id"])
        submit(cand)
    out["authorization"] = {"model": model.to_data(), "verdicts": verdicts, "hypotheses": hypotheses}


def audit_role_matrix(db, evidence, probe, scope, engagement_id, auth_json, pipeline,
                      intent_id=None, endpoints=None) -> dict:
    """Log every identity in once, sweep the endpoint matrix, report contradictions."""
    auth_json = auth_json or {}
    hints = auth_json.get("test_hints") or {}
    out = {"status": "limited", "base_url": _base(auth_json, auth_json.get("identities") or []),
           "endpoints": 0, "identities": {}, "matrix": [], "candidates": [], "limitations": []}

    def limit(reason: str, blocked: bool = False):
        out["limitations"].append(reason)
        pipeline.record_observation(engagement_id, intent_id, "limitation",
                                    f"role matrix: {reason}")
        if blocked:
            out["verdict"] = "inconclusive"  # never "ran, nothing found"
            # a sweep that never authenticated proved nothing: without this the
            # ledger would read the intent's completion as "ran, no finding"
            db.emit(engagement_id, "degradation",
                    {"code": "audit_blocked", "unit": "privesc_audit", "detail": reason})

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
        limit("at least two identities with different usernames are required to compare roles", blocked=True)
        return out
    eps = _endpoints(db, engagement_id, auth_json, endpoints)
    if not eps:
        limit("no endpoints to sweep (no endpoints argument, OpenAPI or crawled assets)", blocked=True)
        return out
    base = out["base_url"]
    if not base:
        limit("no base URL: no identity login_url and no base_url in auth_json", blocked=True)
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
        limit("no identity could log in, so no authorization comparison was possible",
              blocked=True)
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
    out["verdict"] = "assessed"

    # ---- expected-authorization model: operator > analyst > openapi_security > inferred
    model = PolicyModel.load(db, engagement_id)
    try:
        spec = auth_json.get("openapi")
        if isinstance(spec, str):
            spec = json.loads(Path(spec).read_text())
        for r in (from_openapi(spec) if isinstance(spec, dict) else []) \
                + from_operator(hints.get("authz_policy") or auth_json.get("authz_policy")):
            model.add(r)
    except (OSError, ValueError, KeyError, TypeError) as e:
        limit(f"authorization policy could not be read: {type(e).__name__}: {e}")
    for ep in eps:
        if model.get(ep["method"], ep["path"]) is None and (hyp := infer(ep["method"], ep["path"])):
            model.add(hyp)
    model.save(db, engagement_id)
    # an explicit expectation replaces the differential heuristics on that endpoint
    covered = {k for k, r in model.rules.items() if r.source != "inferred"}

    # ---- missing authentication: 2xx anonymous where another identity is refused
    by_ep: dict[tuple, list[dict]] = {}
    for row in rows:
        by_ep.setdefault((row["method"], row["path"]), []).append(row)
    for (method, template), group in by_ep.items():
        if method in WRITE_METHODS or (method, _norm(template)) in covered:
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
        if ep["method"] != "GET" or not PLACEHOLDER.search(ep["path"]) \
                or ("GET", _norm(ep["path"])) in covered:
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
                    f"bola:{ep['method']}:{ep['path']}",
                    proof=_contract(reader, ids.get(reader), url, r["body"], owner=owner)))
                break

    # ---- cross-role: the matrix contradicts itself for one role
    for row, control, kind in _crossings(rows):
        if not row["quote"] or not row["url"] or (row["method"], _norm(row["path"])) in covered:
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
            f"crossrole:{row['method']}:{row['path']}:{row['identity']}",
            proof=_contract(row["identity"], ids.get(row["identity"], row["identity"]), row["url"],
                            privilege=control["role"] or "authenticated")))

    _authz_pass(model, eps, rows, identities, sessions, hint_ids, fetch, target, submit,
                pipeline, engagement_id, intent_id, out, limit)

    db.emit(engagement_id, "role_matrix_complete",
            {"base_url": base, "endpoints": len(eps), "identities": len(sessions),
             "observations": len(rows), "candidates": len(out["candidates"]),
             "limitations": len(out["limitations"])})
    return out
