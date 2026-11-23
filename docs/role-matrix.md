# Role matrix (authenticated privilege sweep)

`libella.privesc_audit.audit_role_matrix` answers one question with evidence: **which
identity reaches which endpoint, and where does that contradict the application's own
role model.** The matrix is the deliverable; findings are a by-product of comparing
its rows.

```python
audit_role_matrix(db, evidence, probe, scope, engagement_id, auth_json, pipeline,
                  intent_id=None, endpoints=None) -> dict
```

## Inputs

| Input | Meaning |
| --- | --- |
| `auth_json["identities"]` | `{username, password, role?, login_url, username_field, password_field}`. At least **two different usernames** are required; otherwise the sweep records a limitation and sends nothing. |
| `endpoints` | `[{method, path, url?, obj_id?}]`, used as given. |
| `auth_json["openapi"]` | Fallback: a path to an OpenAPI file or an inline spec. |
| `assets` table | Last fallback: `kind='endpoint'` rows recorded by the crawler. |
| `auth_json["base_url"]` | Target origin; defaults to the first identity's `login_url` origin. |
| `auth_json["test_hints"]` | `object_ids` (username → id), `obj_id` (anchor), `allow_writes`. |

Endpoints are capped at 40 after dropping static assets (`.js`, `.css`, `.png`,
`.woff`, `.svg`, `.ico`, fonts/maps) and logout routes.

## How it runs

1. **One login per identity**, posted through the scoped `HttpProbe` as a form
   (`tool='role_login'`). A session cookie is the success signal; an identity that
   cannot log in is a limitation, never a finding.
2. **One request per (endpoint, identity) pair** with that identity's cookie. Path
   templates are filled with one anchor id (the hint, or the first identity's own id)
   so every identity is compared against the *same* object.
3. **Classification**: `ALLOWED` (2xx), `DENIED` (401/403), `REDIRECT` (3xx, followed
   once), `ERROR` (anything else, or transport failure), `UNEXERCISED` (a write the
   operator did not declare, or a path with no known object id).
4. Every pair is persisted as a `role_matrix` observation bound to its exchange, and
   each unauthenticated probe as `role_matrix_anonymous`. The returned `matrix` list
   carries the same rows.

## What becomes a finding

Every candidate needs a **differential control** from the same endpoint.

| Rule | Condition | Control | CWE |
| --- | --- | --- | --- |
| Missing authentication | anonymous request is 2xx | another identity got 401/403 on the same endpoint | CWE-306 |
| Cross-role (same role) | an identity is 2xx where another identity with the *same* role is 401/403 | that refused identity | CWE-284 |
| Cross-role (inversion) | a lower-ranked role is 2xx where a higher-ranked role is 401/403 | that refused identity | CWE-285 |
| Object swap (BOLA) | identity A reads the object id belonging to identity B, and the body carries B's record | the same request without a cookie is 401/403 | CWE-639 |

Cross-role rules only look at endpoints without a path parameter: per-object routes
are the BOLA rule's business, and an owner-only 403 is not a role contradiction.

Each finding carries a verbatim JSON pair from the response (a named record for BOLA,
a protected field otherwise), a `proof_request` with that identity's `Cookie` header,
and a `role_pair:` clause in the description naming both sides.

## Writes

`POST/PUT/PATCH/DELETE` are sent **only** when `test_hints["allow_writes"]` names the
exact method and path, e.g.

```json
{"allow_writes": ["POST /api/reports/create"]}
```

`allow_writes: true` with the routes in `test_hints["write_endpoints"]` is equivalent.
Everything else is recorded as `UNEXERCISED` in the matrix and never reaches the wire.
Bodies are never guessed: a declared write is sent as the method alone.

## Limitation paths

`status` is `limited` with a reason in `limitations` (also recorded as a `limitation`
observation) when: fewer than two distinct identities are configured, no endpoint
inventory exists, no base URL can be derived, or no identity could log in.
`status` is `assessed` once the matrix has rows.

## Lab

`labs/rolelab/app.py` seeds four roles (user/manager/admin) with two planted bugs —
`/reports-all` serving anonymous callers and `/api/users/<id>` readable by any
authenticated user. `/hard/*` mirrors every route with correct checks and must yield
zero findings; `tests/audit/test_privesc_audit.py` asserts both directions.