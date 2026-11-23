# Authorization model

Identical responses for Alice and Bob do not mean access control is correct: the
requirement may be "only Alice". `audit_role_matrix` therefore judges every GET
against an explicit **expected-authorization rule**, in addition to its differential checks.

## Rule = endpoint + access class + provenance
Classes: `public`, `authenticated`, `role:<name>`, `owner_only`, `tenant:<name>`, `admin_only`, `denied`, `unknown`.
Sources (strongest wins on merge): `operator` > `analyst` > `openapi_security` > `inferred`.

- `operator`: `auth_json.test_hints.authz_policy` (list, or a path to a JSON file) — `{method?, path, access, note?, allow_roles?}`. Identities may carry `tenant`.
- `openapi_security`: `security: []` -> `public`, any requirement -> `authenticated`, silence -> no rule. It cannot express ownership.
- `analyst`: rules already stored for the engagement (table `authz_policy`, created lazily by `authorization.py`).
- `inferred`: object-id GET routes are assumed `owner_only`. **Hypothesis only**: never a finding, recorded as an `authz_hypothesis` observation.

The merged model is returned as `out["authorization"]["model"]`, with per-endpoint `verdicts` and `hypotheses`.

## Oracle: `authorization.evaluate(rule, observations)`
Verdicts: `compliant`, `violation`, `inconclusive`, `unknown_policy`. It judges content: a 200 carrying a login page or
error JSON is a refusal; a WAF/edge response (`mitigated`) or failed request is unusable, never a clean denial; the served
record's identity fields (`owner_id`, `user_id`, `uid`, `owner`, `username`, `user`, `email`) are compared with the
requester's. `compliant` needs at least one permitted read and one real refusal (or a public read).
A `violation` is `confirmable` only for a non-inferred rule AND a permitted identity's read of the same URL (the control).

## The eight cases
A owner permitted · B other user denied · C other tenant denied · D anonymous denied · E private resource open to everyone
-> finding · F public -> clean · G nobody can log in -> `inconclusive` + `audit_blocked` · H no policy -> `unknown_policy` observation.

An explicit rule replaces the noauth/BOLA/cross-role heuristics on that endpoint (no duplicate findings); without a rule they run as before.
Limits: only GET is judged (writes stay unexercised unless declared); a bare `id` field is not read as an owner; the policy is only as good as its author.
