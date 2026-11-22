# OAuth / OIDC and session-lifecycle audits

Two deterministic audits that use real requests through `HttpProbe` (so scope is
enforced and every exchange becomes evidence). Each candidate carries a
replayable `proof_request` and a verbatim quote the verifier re-checks.

- `src/libella/oauth_audit.py` — `audit_oauth(db, evidence, probe, scope, engagement_id, auth_json, pipeline, intent_id=None)`
- `src/libella/session_audit.py` — `audit_session(...)` with the same signature
- `labs/oauthlab/app.py` — the vulnerable lab plus `/hard/*` negative control

## Configuration

`auth_json['oauth']`:

```json
{"authorize_url": "https://idp.example/authorize",
 "token_url": "https://idp.example/token",
 "client_id": "web-client",
 "redirect_uri": "https://app.example/callback",
 "scope": "openid profile",
 "pkce": true,
 "attacker_origin": "http://127.0.0.2:8080"}
```

`pkce` makes the probe play the client's registered flow (S256 challenge on
every request, verifier on every exchange). `attacker_origin` defaults to
`http://127.0.0.2:8080`; it is only ever *named* in a redirect_uri unless the
engagement scope also authorises it, in which case the landing page is fetched
to prove the code arrived.

`auth_json['session']`:

```json
{"login_url": "...", "username_field": "username", "password_field": "password",
 "username": "operator-identity", "password": "...",
 "protected_url": "...", "logout_url": "...", "password_change_url": "..."}
```

`protected_url` is mandatory: fixation and logout are only claimed when that URL
answers 200 with the cookie and non-200 without it. `password_change_url` is
optional and is exercised with `new_password` set to the *current* password, so
a successful probe changes nothing.

## What is a finding, and what is not

Finding requires the response to prove it:

- **CWE-601 redirect_uri bypass** — a 302 whose `Location` host is the attacker
  origin and whose query/fragment carries `code=`/`access_token=`. The quote is
  the Location up to the code, which is what reproduces on replay (codes are
  per-request). Ten variants are sent: registered control, host swap, path
  append, `@` userinfo, host suffix, trailing-dot host, `%2f` and double-encoded
  separators, subdomain prefix, wildcard suffix, origin-only. Variants that are
  accepted but redirect *within* the registered host are recorded in `vectors`
  and never become findings.
- **CWE-352 missing state / PKCE** — only when the flow completes with neither
  and the code is redeemable at the token endpoint.
- **CWE-598 implicit flow** — `response_type=token` honoured and an access token
  returned in the fragment.
- **CWE-863 scope escalation** — a token is granted with an unregistered
  `admin`/`write` scope, quoting the granted scope.
- **CWE-384 session fixation** — a pre-set session id is still authenticated
  after login.
- **CWE-613 logout** — the pre-logout cookie still gets 200 from the protected
  URL.
- **CWE-620 re-authentication** — a credential change is accepted with no
  current password.

Observations only: missing `state`/PKCE without a completed grant, a
`response_type` accepted without a token, session cookie without
`HttpOnly`/`SameSite`, a session id in a redirect URL.

Limitations are recorded (never silently dropped): missing config keys, a
control flow that does not complete, a landing page that cannot be read, and
every scope refusal — a refused request stops the audit with `status: blocked`
and no claims.

## Lab

`labs/oauthlab/app.py` binds `0.0.0.0:0` so the same process is reachable on
`127.0.0.2`, the loopback alias a real redirect can land on. Seeded: prefix and
path-only redirect matching, optional `state`, no PKCE, implicit flow, scopes
granted verbatim, fixation, logout that only clears the client cookie, password
change without the current password. `/hard/*` implements each flow correctly.
`tests/audit/test_{oauth,session}_audit.py` assert every seeded class fires on
the vulnerable routes, that `/hard/*` yields zero candidates *and* zero
observations, that each quote occurs in its evidence, and that every exchange
row stayed inside the scope.

## Known limits

- `dict(resp.headers)` in `HttpProbe` collapses repeated `Set-Cookie` headers, so
  only the last cookie of a login response is visible to the session audit.
- Scope-escalation findings replay the token exchange. An AS that consumes
  authorization codes will make that replay inconclusive (`invalid_grant`);
  the captured exchange remains the evidence.
- `Secure` is not judged here at all — plain-http labs could not return the
  cookie; `checks.cookie_flags` owns that flag where the transport permits it.
- No browser: `response_mode=form_post` consent pages are not parsed, and a
  Referer leak is stated as the consequence of a URL-carried code rather than
  measured with a real navigation.