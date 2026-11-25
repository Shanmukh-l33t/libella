"""API security checks driven by an OpenAPI description.

Deterministic checks: BOLA, BFLA, mass assignment, excessive data exposure and
missing authentication. Every request goes through HttpProbe, so scope is
enforced and each exchange is captured as evidence. Each candidate carries a
replayable proof_request (including the identity's cookie header) and a verbatim
response quote, which is what the verifier re-checks on replay.
"""
import json
import re
from pathlib import Path

import httpx

from .checks import _candidate

SENSITIVE_FIELDS = ("password", "hash", "secret", "token", "ssn", "api_key", "card_number")
PII_FIELDS = ("email", "phone", "address", "ssn", "role")
ADMIN_PATH = re.compile(r"/admin(/|$)")
HTTP_METHODS = ("get", "post", "put", "patch", "delete")
MA_PROBE_NAME = "massassign-probe"
MA_PROBE_FIELDS = {"is_admin": True, "role": "admin"}  # is_admin first: the sharper proof


def _ref_name(schema: dict) -> str | None:
    if schema.get("$ref"):
        return schema["$ref"].split("/")[-1]
    items = schema.get("items") or {}
    return items["$ref"].split("/")[-1] if items.get("$ref") else None


def _json_body(content: dict) -> dict:
    return ((content or {}).get("application/json") or {}).get("schema") or {}


def load_openapi(path: str | Path) -> dict:
    """Endpoint inventory: method, path, params, request/response schema, auth requirement."""
    spec = json.loads(Path(path).read_text())
    schemas = {name: sorted((s.get("properties") or {}).keys())
               for name, s in ((spec.get("components") or {}).get("schemas") or {}).items()}
    endpoints = []
    for route, ops in (spec.get("paths") or {}).items():
        for method, op in ops.items():
            if method not in HTTP_METHODS:
                continue
            ok = next((r for code, r in (op.get("responses") or {}).items() if str(code).startswith("2")), {})
            endpoints.append({
                "method": method.upper(),
                "path": route,
                "params": sorted(p["name"] for p in op.get("parameters", []) if p.get("name")),
                "request_schema": _ref_name(_json_body((op.get("requestBody") or {}).get("content") or {})),
                "response_schema": _ref_name(_json_body(ok.get("content") or {})),
                "auth": bool(op.get("security")),
            })
    return {"title": (spec.get("info") or {}).get("title", ""), "endpoints": endpoints, "schemas": schemas}


def _json_obj(text: str):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _rows(obj) -> list[dict]:
    if isinstance(obj, list):
        return [r for r in obj if isinstance(r, dict)]
    return [obj] if isinstance(obj, dict) else []


def _leaked_fields(obj, fields=SENSITIVE_FIELDS) -> list[str]:
    return sorted({k for row in _rows(obj) for k in row if any(f in k.lower() for f in fields)})


def _extra_fields(obj, props) -> set[str]:
    return {k for row in _rows(obj) for k in row} - set(props)


def _fill(template: str, value) -> str:
    return re.sub(r"\{[^}]+\}", str(value), template)


def _match(endpoints: list[dict], method: str, path: str) -> dict | None:
    segs = path.strip("/").split("/")
    for ep in endpoints:
        tsegs = ep["path"].strip("/").split("/")
        if ep["method"] == method and len(tsegs) == len(segs) and all(
                t.startswith("{") or t == s for t, s in zip(tsegs, segs)):
            return ep
    return None


def _privileged(value) -> bool:
    return value is True or value == 1 or (isinstance(value, str) and value.lower() == "admin")


def assess_api(base_url: str, openapi_path, identities, db, evidence, pipeline, probe, scope,
               engagement_id: str, category: str = "api") -> dict:
    """Log in each identity, then run the deterministic API checks.

    Returns {status, logins, candidates, observations, errors}. status is
    "blocked" when even the login request was refused (e.g. out of scope): no
    check runs and nothing is claimed.
    """
    base = base_url.rstrip("/")
    spec = load_openapi(openapi_path)
    schemas = spec["schemas"]
    out = {"base_url": base, "status": "assessed", "endpoints": len(spec["endpoints"]),
           "logins": {}, "candidates": [], "observations": [], "errors": []}
    sessions: dict[str, dict] = {}
    submitted: list[dict] = []
    seen: list[tuple[str, str, dict]] = []
    try:
        for ident in identities:
            client = httpx.Client(timeout=15, verify=False, trust_env=False)
            r = probe.request(
                engagement_id, scope, ident.get("login_url", base + "/api/login"),
                method="POST", headers={"Content-Type": "application/json"},
                body=json.dumps({"username": ident["username"], "password": ident["password"]}),
                category=category, client=client, tool="api_login", follow_redirects=False)
            if not r.get("ok"):
                client.close()
                out["status"] = "blocked"
                out["errors"].append(f"login {ident['username']}: {r.get('error')}")
                return out  # scope refusal / transport failure: never guess past it
            body = _json_obj(r["body"]) or {}
            cookie = "; ".join(f"{c.name}={c.value}" for c in client.cookies.jar)
            out["logins"][ident["username"]] = {
                "authenticated": body.get("authenticated") is True,
                "role": body.get("role") or ident.get("role"),
                "uid": body.get("id"), "cookie": bool(cookie)}
            sessions[ident["username"]] = {"client": client, "cookie": cookie, "uid": body.get("id")}
        authenticated = [i["username"] for i in identities
                         if out["logins"][i["username"]]["authenticated"]]
        if not authenticated:
            out["status"] = "no_authenticated_identity"
            return out
        me = authenticated[0]
        my_uid = sessions[me]["uid"]

        def req(path, method="GET", as_user=me, body=None, extra_headers=None):
            s = sessions.get(as_user) if as_user else None
            headers = dict(extra_headers or {})
            if s and s["cookie"]:
                headers["Cookie"] = s["cookie"]
            return probe.request(engagement_id, scope, base + path, method=method,
                                 headers=headers or None, body=body, category=category,
                                 client=(s["client"] if s else None), tool="api_check",
                                 follow_redirects=False)

        def submit(cand):
            res = pipeline.submit_candidate(engagement_id, cand)
            submitted.append({"finding_id": res["id"], "title": cand["title"], "cwe": cand["cwe"],
                              "endpoint": cand["endpoint"], "deduped": res["deduped"]})

        # ---- collection + object reads: excessive data exposure and BOLA
        list_ep = next((e for e in spec["endpoints"]
                        if e["method"] == "GET" and not e["params"]
                        and "owner_id" in schemas.get(e["response_schema"] or "", [])), None)
        rows, detail_ep = [], None
        if list_ep:
            r = req(list_ep["path"])
            seen.append((list_ep["method"], list_ep["path"], r))
            rows = _rows(_json_obj(r["body"])) if r.get("ok") and r["status"] == 200 else []
            leaked = _leaked_fields(rows)
            if leaked:
                submit(_candidate(
                    f"Excessive data exposure: '{leaked[0]}' returned by {list_ep['path']}",
                    "CWE-200", "A01:2021 Broken Access Control", "high", "high",
                    base + list_ep["path"],
                    f"Collection response for {list_ep['path']} contains credential field "
                    f"'{leaked[0]}' for every record.",
                    "Password material in a listing enables offline cracking and account takeover.",
                    "Serialize an explicit response model; never return credential columns.",
                    r["evidence_id"], f'"{leaked[0]}":',
                    {"method": "GET", "url": base + list_ep["path"],
                     "headers": {"Cookie": sessions[me]["cookie"]}},
                    f"exposure:{list_ep['path']}"))

            detail_ep = next((e for e in spec["endpoints"] if e["method"] == "GET" and e["params"]
                              and e["path"].startswith(list_ep["path"] + "/")), None)
            foreign = next((row for row in rows if "id" in row
                            and row.get("owner_id") not in (None, my_uid)), None)
            if detail_ep and foreign:
                path = _fill(detail_ep["path"], foreign["id"])
                r2 = req(path)
                seen.append(("GET", path, r2))
                if r2.get("ok") and r2["status"] == 200:
                    owner, fname = foreign["owner_id"], foreign.get("name")
                    marker = f'"owner_id":{owner}'
                    named = f'"name":"{fname}","owner_id":{owner}'
                    quote = named if named in r2["body"] else marker
                    if quote in r2["body"]:
                        submit(_candidate(
                            f"BOLA: '{me}' reads another user's object at {path}",
                            "CWE-639", "API1:2023 Broken Object Level Authorization", "high", "high",
                            base + path,
                            f"Identity {me} (uid {my_uid}) read {path}, owned by uid "
                            f"{foreign['owner_id']}, with no ownership check.",
                            "Horizontal privilege escalation: any authenticated user can enumerate "
                            "every object of this type by changing the id.",
                            "Enforce object-level ownership (or tenancy) checks on every object read.",
                            r2["evidence_id"], quote,
                            {"method": "GET", "url": base + path,
                             "headers": {"Cookie": sessions[me]["cookie"]}},
                            f"bola:{detail_ep['path']}",
                            proof={
                                # the claim is access AS me to a record owned by someone
                                # else: name both, and keep the object id so the verifier
                                # can ask the same route without the credential
                                "identity": {"name": me, "value": my_uid},
                                "owner_field": "owner_id",
                                "owner_value": foreign["owner_id"],
                                "benign_request": {"method": "GET", "url": base + path},
                            }))

        # ---- administrative functions reachable by a non-admin identity (BFLA)
        my_role = (out["logins"][me]["role"] or "").lower()
        if my_role != "admin":
            for ep in spec["endpoints"]:
                if not ADMIN_PATH.search(ep["path"]) or ep["params"]:
                    continue
                r = req(ep["path"], method=ep["method"])
                seen.append((ep["method"], ep["path"], r))
                if r.get("ok") and r["status"] == 200:
                    submit(_candidate(
                        f"BFLA: non-admin '{me}' can call {ep['method']} {ep['path']}",
                        "CWE-285", "API5:2023 Broken Function Level Authorization", "high", "high",
                        base + ep["path"],
                        f"{ep['method']} {ep['path']} returned 200 for role '{my_role}' "
                        "although the specification declares it admin-only.",
                        "Function-level authorization bypass: a regular user executes "
                        "administrative functions.",
                        "Check the caller's role server-side on every administrative route; deny by default.",
                        r["evidence_id"], r["body"].strip()[:200],
                        {"method": ep["method"], "url": base + ep["path"],
                         "headers": {"Cookie": sessions[me]["cookie"]}},
                        f"bfla:{ep['path']}"))
                    break

        # ---- mass assignment: privileged fields on create, confirmed by re-read
        create_ep = next((e for e in spec["endpoints"]
                          if e["method"] == "POST" and "login" not in e["path"]), None)
        if create_ep:
            payload = json.dumps({"name": MA_PROBE_NAME, **MA_PROBE_FIELDS})
            r = req(create_ep["path"], method="POST", body=payload,
                    extra_headers={"Content-Type": "application/json"})
            seen.append(("POST", create_ep["path"], r))
            created = _json_obj(r["body"]) or {}
            accepted = [k for k in MA_PROBE_FIELDS if _privileged(created.get(k))]
            back_path = (_fill(detail_ep["path"], created["id"])
                         if detail_ep and "id" in created else f"{create_ep['path']}/{created.get('id')}")
            r2 = req(back_path) if accepted else None
            if r2 is not None:
                seen.append(("GET", back_path, r2))
            persisted = [k for k in accepted
                         if r2 is not None and r2.get("status") == 200
                         and _privileged((_json_obj(r2["body"]) or {}).get(k))]
            if persisted:
                key = persisted[0]
                quote = f'"{key}":{json.dumps(created[key])}'
                named = f"{quote},"
                quote = named + f'"name":"{MA_PROBE_NAME}"' if named in r["body"] else quote
                cand = _candidate(
                    f"Mass assignment: '{key}' accepted on {create_ep['path']}",
                    "CWE-915", "API3:2023 Broken Object Property Level Authorization", "high", "high",
                    base + create_ep["path"],
                    f"POST {create_ep['path']} bound caller-supplied '{key}' and the value persisted "
                    f"(re-read {back_path} as the same identity).",
                    "Privilege escalation: a user can set authorization fields on objects they create.",
                    "Bind only an explicit allowlist of writable fields; ignore authorization properties.",
                    r["evidence_id"],
                    quote,
                    {"method": "POST", "url": base + create_ep["path"], "body": payload,
                     "headers": {"Content-Type": "application/json",
                                 "Cookie": sessions[me]["cookie"]}},
                    f"massassign:{create_ep['path']}")
                cand["evidence_ids"] = [r["evidence_id"], r2["evidence_id"]]
                submit(cand)

        # ---- authentication required by the spec, absent in practice (CWE-306)
        for ep in spec["endpoints"]:
            # admin routes are already covered above; don't report one gap twice
            if ep["method"] != "GET" or not ep["auth"] or ADMIN_PATH.search(ep["path"]):
                continue
            path = _fill(ep["path"], 2) if ep["params"] else ep["path"]
            r = req(path, as_user=None)
            seen.append(("GET", path, r))
            if not r.get("ok") or r["status"] != 200:
                continue
            obj = _json_obj(r["body"]) or {}
            exposed = _leaked_fields(obj, PII_FIELDS)
            if not exposed:
                continue
            field = exposed[0]
            quote = (f'"{field}":{json.dumps(obj[field])}'
                     if isinstance(obj, dict) and field in obj else f'"{field}":')
            if quote not in r["body"]:
                quote = f'"{field}":'
            if quote not in r["body"]:
                continue
            submit(_candidate(
                f"Missing authentication on {ep['method']} {path}",
                "CWE-306", "API2:2023 Broken Authentication", "high", "high", base + path,
                f"Unauthenticated GET {path} returned 200 with '{field}' "
                "(the specification requires a session).",
                "Anonymous access to user records: mass enumeration of personal data.",
                "Require authentication on the route and deny anonymous access by default.",
                r["evidence_id"], quote, {"method": "GET", "url": base + path},
                f"noauth:{ep['path']}"))

        # ---- schema conformance: response fields the OpenAPI schema does not describe
        for method, path, r in seen:
            ep = _match(spec["endpoints"], method, path)
            props = schemas.get((ep or {}).get("response_schema") or "", [])
            if not ep or not props or not r.get("ok") or r["status"] >= 300:
                continue
            for field in sorted(_extra_fields(_json_obj(r["body"]), props)):
                summary = (f"{method} {path} returns '{field}' not described by schema "
                           f"{ep['response_schema']}")
                out["observations"].append({"endpoint": base + path, "method": method,
                                            "field": field, "schema": ep["response_schema"],
                                            "evidence_id": r["evidence_id"], "summary": summary})
                pipeline.record_observation(engagement_id, None, "schema_conformance", summary,
                                            evidence_id=r["evidence_id"])

        db.emit(engagement_id, "api_audit_complete",
                {"base_url": base, "candidates": len(submitted),
                 "observations": len(out["observations"])})
        out["candidates"] = submitted
        return out
    finally:
        for s in sessions.values():
            s["client"].close()
