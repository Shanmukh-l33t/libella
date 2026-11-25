"""GraphQL security checks: introspection, injection, field authz, resource abuse.

Every request goes through HttpProbe, so scope is enforced and each exchange is
captured as evidence. Each candidate carries a replayable POST proof_request
(exact compact JSON body plus the identity's Cookie header) and a verbatim
response quote, which is what the verifier re-checks on replay.

Only observed behaviour is claimed: a hardened endpoint that rejects the probe
produces no candidate for that class. Introspection is recorded as an
observation always, and promoted to a low-severity finding only when the dumped
schema names the administrative surface (it is otherwise common and accepted).
"""
import json
from urllib.parse import urlsplit

import httpx

from .checks import SQLI_ERRORS, _candidate

# Fake lab-fixture accounts; the caller passes real identities instead.
LAB_IDENTITIES = (
    {"username": "alice", "password": "SI_SECRET_PASSWORD_GRAPHLAB_A1", "role": "user"},
    {"username": "bob", "password": "SI_SECRET_PASSWORD_GRAPHLAB_B2", "role": "user"},
    {"username": "admin", "password": "SI_SECRET_PASSWORD_GRAPHLAB_C3", "role": "admin"},
)
SENSITIVE_TYPE_NAMES = ("AdminStats", "Mutation")
DEPTH_LEVELS = 6  # manager hops; the document is then 8 levels deep
ALIAS_COUNT = 50
BATCH_SIZE = 3
INTROSPECTION_QUERY = "{__schema{types{name}}}"
INJECTION_MARKER = "libella'"


def _compact(obj) -> str:
    """Compact JSON: no spaces, stable keys. Quotes stay byte-stable on replay."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


def _q(query: str) -> str:
    return _compact({"query": query})


def _json_obj(text: str):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _error_quote(body: str, sig: str) -> str | None:
    """Verbatim slice of the response that carries the database error signature."""
    i = body.lower().find(sig)
    if i < 0:
        return None
    start = body.rfind('"message":"', 0, i)
    quote = body[start:i + len(sig)] if start >= 0 else body[i:i + len(sig)]
    return quote if quote and quote in body else None


def assess_graphql(endpoint_url: str, db, evidence, pipeline, probe, scope, engagement_id,
                   identities=None, category: str = "api") -> dict:
    """Run the deterministic GraphQL checks against one endpoint.

    Returns {endpoint, status, logins, candidates, observations, errors}. status
    is "blocked" when the login request was refused (e.g. out of scope): no check
    runs and nothing is claimed. `evidence` is unused here because HttpProbe
    captures every exchange itself; it is accepted for interface symmetry.
    """
    base = endpoint_url.rstrip("/")
    parts = urlsplit(base)
    login_url = f"{parts.scheme}://{parts.netloc}/login"
    out = {"endpoint": base, "status": "assessed", "logins": {}, "candidates": [],
           "observations": [], "errors": []}
    sessions: dict[str, dict] = {}
    submitted: list[dict] = []
    try:
        for ident in identities or LAB_IDENTITIES:
            name = ident["username"]
            client = httpx.Client(timeout=15, verify=False, trust_env=False)
            r = probe.request(
                engagement_id, scope, login_url, method="POST",
                headers={"Content-Type": "application/json"},
                body=_compact({"username": name, "password": ident["password"]}),
                category=category, client=client, tool="graphql_login",
                follow_redirects=False)
            if not r.get("ok"):
                client.close()
                out["status"] = "blocked"
                out["errors"].append(f"login {name}: {r.get('error')}")
                return out  # scope refusal / transport failure: never guess past it
            body = _json_obj(r["body"]) or {}
            cookie = "; ".join(f"{c.name}={c.value}" for c in client.cookies.jar)
            sessions[name] = {
                "client": client, "cookie": cookie,
                "authenticated": body.get("authenticated") is True,
                "uid": body.get("id"), "username": body.get("username") or name,
                "role": body.get("role") or ident.get("role"),
            }
            out["logins"][name] = {"authenticated": sessions[name]["authenticated"],
                                   "role": sessions[name]["role"], "uid": sessions[name]["uid"],
                                   "cookie": bool(cookie)}

        authed = [n for n, s in sessions.items() if s["authenticated"]]
        if not authed:
            out["status"] = "no_authenticated_identity"
            return out
        me = next((n for n in authed if (sessions[n]["role"] or "").lower() != "admin"), authed[0])
        other = next((n for n in authed if n != me and sessions[n]["uid"] != sessions[me]["uid"]),
                     None)
        my_uid, my_name = sessions[me]["uid"], sessions[me]["username"]

        def gql(payload, as_user: str = me):
            s = sessions[as_user]
            headers = {"Content-Type": "application/json"}
            if s["cookie"]:
                headers["Cookie"] = s["cookie"]
            return probe.request(engagement_id, scope, base, method="POST", headers=headers,
                                 body=_compact(payload), category=category, client=s["client"],
                                 tool="graphql_check", follow_redirects=False)

        def proof(body: str, as_user: str = me) -> dict:
            headers = {"Content-Type": "application/json"}
            if sessions[as_user]["cookie"]:
                headers["Cookie"] = sessions[as_user]["cookie"]
            return {"method": "POST", "url": base, "headers": headers, "body": body}

        def submit(cand):
            res = pipeline.submit_candidate(engagement_id, cand)
            submitted.append({"finding_id": res["id"], "title": cand["title"],
                              "cwe": cand["cwe"], "endpoint": cand["endpoint"],
                              "deduped": res["deduped"]})

        # ---- introspection: observation always, finding only for sensitive schema names
        r = gql({"query": INTROSPECTION_QUERY})
        obj = _json_obj(r["body"]) if r.get("ok") else None
        schema = ((obj.get("data") or {}).get("__schema") or {}) if isinstance(obj, dict) else {}
        types = schema.get("types") if isinstance(schema.get("types"), list) else []
        names = sorted(t["name"] for t in types if isinstance(t, dict) and "name" in t)
        if r.get("ok") and names and not (obj or {}).get("errors"):
            summary = (f"GraphQL introspection enabled at {base}: {len(names)} types "
                       f"({', '.join(names)})")
            pipeline.record_observation(engagement_id, None, "graphql_introspection", summary,
                                        evidence_id=r["evidence_id"], quote='"__schema"')
            out["observations"].append({"endpoint": base, "types": names,
                                        "evidence_id": r["evidence_id"], "summary": summary})
            exposed = [n for n in names if n in SENSITIVE_TYPE_NAMES]
            quote = f'"name":"{exposed[0]}"' if exposed else ""
            if quote and quote in r["body"]:
                submit(_candidate(
                    "GraphQL introspection exposes admin schema surface",
                    "CWE-200", "API8:2023 Security Misconfiguration", "low", "high", base,
                    f"POST {base} with the __schema query returned {len(names)} type names "
                    f"including '{exposed[0]}', so the public schema advertises the "
                    "administrative surface to any authenticated caller.",
                    "Introspection alone is common and often accepted; here it also maps the "
                    "admin-only type, which shortens reconnaissance for privilege escalation.",
                    "Disable introspection in production, or serve an allowlisted public schema.",
                    r["evidence_id"], quote, proof(_q(INTROSPECTION_QUERY)), "gql:introspection"))

        # ---- injection in a string argument (error-based signature)
        inj_q = '{users(filter:"' + INJECTION_MARKER + '"){id username}}'
        r = gql({"query": inj_q})
        low = r["body"].lower() if r.get("ok") else ""
        sig = next((s for s in SQLI_ERRORS if s in low), None)
        quote = _error_quote(r["body"], sig) if sig else None
        if r.get("ok") and quote:
            submit(_candidate(
                "SQL injection in the GraphQL 'users' filter argument",
                "CWE-89", "A03:2021 Injection", "high", "high", base,
                f"POST {base} with {inj_q} returned the database error signature '{sig}' "
                "instead of an empty user list: the filter value reaches the SQL text "
                "unsanitized.",
                "Arbitrary query manipulation against the backing store: bulk data theft, "
                "authentication bypass, and file or command access on many deployments.",
                "Bind every resolver argument as a SQL parameter; never concatenate GraphQL "
                "input into a statement.",
                r["evidence_id"], quote, proof(_q(inj_q)), "gql:sqli:users",
                proof={"signal": "error_signature",
                       # the same resolver with a benign filter value: a server that
                       # errors on any filter raises the same signature without injection
                       "benign_request": {"method": "POST", "url": base,
                                          "headers": {"Content-Type": "application/json"},
                                          "body": _q('{users(filter:""){id username}}')}}))

        # ---- field-level authorization: another user's record
        if other:
            other_uid, other_name = sessions[other]["uid"], sessions[other]["username"]
            q = f"{{user(id:{other_uid}){{id username email role}}}}"
            r = gql({"query": q})
            obj = _json_obj(r["body"]) or {}
            row = (obj.get("data") or {}).get("user") if isinstance(obj, dict) else None
            if (r.get("ok") and isinstance(row, dict) and row.get("id") == other_uid
                    and row.get("username") == other_name):
                quote = (f'"email":"{row["email"]}"' if row.get("email")
                         else f'"username":"{other_name}"')
                if quote not in r["body"]:
                    quote = f'"username":"{other_name}"'
                if quote in r["body"]:
                    submit(_candidate(
                        "GraphQL field-level authorization missing: "
                        f"{my_name} reads another user's record",
                        "CWE-639", "API1:2023 Broken Object Level Authorization",
                        "high", "high", base,
                        f"Identity {my_name} (uid {my_uid}) POSTed {q} and received uid "
                        f"{other_uid}'s ({other_name}) record including email and role; the "
                        "resolver applies no owner or role check.",
                        "Any authenticated caller can enumerate every user record by id: "
                        "personal data disclosure and a map for account takeover.",
                        "Check owner-or-admin on the resolved object inside the resolver, not "
                        "only at the transport layer.",
                        r["evidence_id"], quote, proof(_q(q)), "gql:fieldauthz:user",
                        proof={
                            "identity": {"name": my_name, "value": my_uid},
                            # a GraphQL response nests the record under "data": the
                            # contract names the field, the verifier reads it from there
                            "owner_field": "id",
                            "owner_value": other_uid,
                            # the same query with no credential: a resolver that refuses
                            # anonymous callers is enforcing authorization
                            "benign_request": {"method": "POST", "url": base,
                                               "headers": {"Content-Type": "application/json"},
                                               "body": _q(q)},
                        }))

        # ---- field-level authorization: admin-only field reachable by a regular user
        if (sessions[me]["role"] or "").lower() != "admin":
            q = "{adminStats{totalUsers totalRoles}}"
            r = gql({"query": q})
            obj = _json_obj(r["body"]) or {}
            stats = (obj.get("data") or {}).get("adminStats") if isinstance(obj, dict) else None
            quote = ""
            if r.get("ok") and isinstance(stats, dict) and "totalUsers" in stats:
                quote = (f'"totalRoles":{json.dumps(stats.get("totalRoles"))},'
                         f'"totalUsers":{json.dumps(stats.get("totalUsers"))}')
                if quote not in r["body"]:
                    quote = f'"totalUsers":{json.dumps(stats.get("totalUsers"))}'
                if quote not in r["body"]:
                    quote = ""
            if quote:
                submit(_candidate(
                    "GraphQL field-level authorization missing: "
                    f"non-admin {my_name} reads adminStats",
                    "CWE-639", "API5:2023 Broken Function Level Authorization",
                    "high", "high", base,
                    f"Identity {my_name} (role '{sessions[me]['role']}') POSTed {q} and "
                    "received the administrative statistics object; the field has no role "
                    "check.",
                    "Administrative data and tenant-wide counts leak to every authenticated "
                    "user, aiding targeted abuse and enumeration.",
                    "Guard admin-only fields by role in the resolver; deny by default.",
                    r["evidence_id"], quote, proof(_q(q)), "gql:fieldauthz:adminstats",
                    proof={"identity": {"name": my_name, "value": my_uid},
                           # the privilege the caller lacks, and the same query with no
                           # credential: a resolver that refuses anonymous callers guards it
                           "privilege": "admin",
                           "benign_request": {"method": "POST", "url": base,
                                              "headers": {"Content-Type": "application/json"},
                                              "body": _q(q)}}))

        # ---- resource abuse: query depth
        depth = DEPTH_LEVELS + 2  # outer selection set + the user field's selection set
        nested = "".join(" manager{id" for _ in range(DEPTH_LEVELS)) + "}" * DEPTH_LEVELS
        q = "{user(id:%d){id%s}}" % (my_uid, nested)
        r = gql({"query": q})
        obj = _json_obj(r["body"]) or {}
        node = (obj.get("data") or {}).get("user") if isinstance(obj, dict) else None
        ids = []
        while isinstance(node, dict) and len(ids) < DEPTH_LEVELS + 2:
            ids.append(node.get("id"))
            node = node.get("manager")
        quote = ("".join(f'"id":{ids[i]},"manager":{{' for i in range(3))
                 + f'"id":{ids[3]}') if len(ids) >= 4 else ""
        if r.get("ok") and quote and quote in r["body"] and not obj.get("errors"):
            submit(_candidate(
                f"GraphQL query depth limit absent: depth-{depth} query executed",
                "CWE-770", "API4:2023 Unrestricted Resource Consumption", "medium", "high",
                base,
                f"POST {base} executed a document nested {depth} levels deep ({len(ids)} user "
                "levels returned) with no depth rejection or truncation.",
                "Unbounded nesting multiplies resolver work per request; combined with "
                "aliasing or batching it is a cheap denial of service against the API.",
                "Enforce a maximum query depth (and complexity) before execution.",
                r["evidence_id"], quote, proof(_q(q)), "gql:depth"))

        # ---- resource abuse: alias amplification
        q = "{" + " ".join(f"u{i}:user(id:{my_uid}){{id}}" for i in range(ALIAS_COUNT)) + "}"
        r = gql({"query": q})
        obj = _json_obj(r["body"]) or {}
        data = obj.get("data") if isinstance(obj, dict) else None
        keys = [k for k in data if str(k).startswith("u")] if isinstance(data, dict) else []
        quote = ""
        if r.get("ok") and len(keys) >= ALIAS_COUNT and not obj.get("errors"):
            quote = f'"u0":{{"id":{my_uid}}},"u1":{{"id":{my_uid}}}'
            if quote not in r["body"]:
                quote = f'"u{ALIAS_COUNT - 1}":{{"id":{my_uid}}}'
            quote = quote if quote in r["body"] else ""
        if quote:
            submit(_candidate(
                f"GraphQL alias limit absent: {ALIAS_COUNT} aliases executed in one request",
                "CWE-770", "API4:2023 Unrestricted Resource Consumption", "medium", "high", base,
                f"POST {base} with {ALIAS_COUNT} aliases of the same field returned all "
                f"{len(keys)} results: one request buys {ALIAS_COUNT} resolver executions.",
                "A small request amplifies into many database/resolver calls, enabling cheap "
                "resource exhaustion and brute-force style enumeration.",
                "Cap aliases (or count total field complexity) and reject oversized documents.",
                r["evidence_id"], quote, proof(_q(q)), "gql:alias"))

        # ---- resource abuse: request batching
        batch = [{"query": f"{{user(id:{my_uid}){{id username}}}}"}]
        batch.append({"query": f"{{user(id:{sessions[other]['uid']}){{id username}}}}"} if other
                     else {"query": "{users{id}}"})
        batch.append({"query": "{users{id username}}"})
        r = gql(batch)
        arr = _json_obj(r["body"])
        executed = (r.get("ok") and isinstance(arr, list) and len(arr) == BATCH_SIZE
                    and all(isinstance(e, dict) and "data" in e for e in arr))
        quote = f'[{{"data":{{"user":{{"id":{my_uid},"username":"{my_name}"' if executed else ""
        if quote and quote not in r["body"]:
            quote = '[{"data":{"user":'
        quote = quote if quote in r["body"] else ""
        if quote:
            submit(_candidate(
                f"GraphQL query batching accepted: {BATCH_SIZE} operations in one request",
                "CWE-770", "API4:2023 Unrestricted Resource Consumption", "medium", "high", base,
                f"POST {base} with a JSON array of {BATCH_SIZE} operations executed all of them "
                "and returned an array of results.",
                "Batching multiplies the work and rate-limit footprint of a single HTTP "
                "request, defeating per-request throttling and easing brute force.",
                "Disable request batching, or count each batched operation against the "
                "rate/resource budget.",
                r["evidence_id"], quote, proof(_compact(batch)), "gql:batch"))

        db.emit(engagement_id, "graphql_audit_complete",
                {"endpoint": base, "candidates": len(submitted),
                 "observations": len(out["observations"])})
        out["candidates"] = submitted
        return out
    finally:
        for s in sessions.values():
            s["client"].close()
