# JWT / self-contained token audit

`libella.jwt_audit.audit_jwt(db, evidence, probe, scope, engagement_id, auth_json, pipeline, intent_id=None)`

Forges tokens and sends each one through the engagement's scoped `HttpProbe` to a
single operator-declared, token-accepting URL, then judges every response against
an **anonymous control** request to the same URL. Tokens are decoded with
base64url only — nothing is verified inside Libella.

Returns `{candidates, findings, observations, limitations}`.

## Inputs (`auth_json`)

```json
{
  "identities": [{"login_url": "https://api.example/login", "username": "u", "password": "p"}],
  "test_hints": {"jwt": {
      "url": "https://api.example/me",        // required: the verification endpoint
      "token": "eyJ...",                      // optional: skip discovery
      "header_name": "Authorization",         // or "cookie"
      "pem": "/path/to/public.pem",           // optional: RSA key for the confusion test
      "jku": "https://api.example/jwks.json"  // optional: key source override
  }}
}
```

Discovery reads the first identity's login response (does not follow redirects)
and harvests three-segment tokens from `Set-Cookie` / `Authorization` headers, the
URL query string, and the JSON body. Missing `url` or a missing token is a
**limitation**, never a finding.

## Attack → proof → CWE

| Attack | Proven when | CWE |
|---|---|---|
| `alg` `none`/`nOnE`/`None`, empty signature | a 200 with content the anonymous control did not get | 347 |
| HS256 re-sign with the RS256 public key PEM as the HMAC secret | same, key fetched via `jku` → `x5u`/`jwks_uri` over the probe | 347 |
| HS256 re-signed with one of 40 built-in default secrets | same; the secret is first matched offline against the token signature, so exactly one request is spent | 347 |
| `kid` = `../../../../dev/null`, `/dev/null` (and `/etc/passwd`, observation only) | a token HMAC'd with the empty string is accepted | 345 |
| `jku`/`x5u` on an unauthorised host | **never** — scope refuses the fetch; recorded as a limitation, no egress | — |
| claim flip (`user_id`, `role`, `is_admin`, `scope`) | only after a signing key was proven, and only if the response body *changes* | 863 |
| `exp` in the past / `exp` absent | the re-signed token is accepted | 613 |

A finding requires: control is not 200, the attack request is 200, body non-empty,
body different from the control, no WAF/CDN challenge, and a verbatim quote taken
from that response. "Not 401" proves nothing and is never reported.

`aud` non-enforcement and "claimed token was accepted for another service" are
observations unless a second service is declared, because a distinguishable
response is required.

## Lab

`labs/jwtlab/app.py` (Flask, `LAB_PORT`, module-level state) — RSA keys are
generated into `labs/jwtlab/keys/` on first start (gitignored):

| Endpoint | Behaviour |
|---|---|
| `POST /login` | HS256 signed with `jwtsecret`, also set as a cookie |
| `GET /api/profile` | weak secret accepted, `exp` ignored, `user_id`/`role` claims trusted |
| `GET /api/none` | accepts `alg: none` with an empty signature |
| `POST /login-rs` | RS256 token, header carries `jku` → `/jwks.json` → `/public.pem` |
| `GET /api/rs256` | verifies HS256 with the public PEM as the HMAC secret (confusion bug) |
| `POST /login-hard` | HS256 with a strong secret, the token `/api/hard` accepts |
| `GET /api/hard` | **negative control**: pinned HS256, strong secret, `exp`/`iat`/`sub` required, `aud` enforced, identity and role from the server table |

`tests/audit/test_jwt_audit.py` starts it in-process on port 0 and asserts on
captured `exchanges` rows plus evidence blobs: the vulnerable endpoints produce
CWE-347/613/863 candidates whose quotes occur in their evidence, `/api/hard`
produces zero candidates while still accepting its own token, an out-of-scope
`jku` yields a limitation with no exchange to the foreign host, and every URL used
stays inside the scope.