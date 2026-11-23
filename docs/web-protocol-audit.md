# Web protocol audit

`libella.web_protocol_audit.audit_web_protocol(db, evidence, probe, scope, engagement_id, auth_json, pipeline, intent_id=None)`

Protocol-level checks against an operator-declared URL: host header injection, web
cache poisoning, HTTP parameter pollution, method / verb tampering, and opt-in
request-smuggling **detection**. Every request goes through `HttpProbe`, so scope is
enforced per hop and each exchange is captured as evidence.

Returns `{status, url, candidates, observations, limitations, errors}`. `status` is
`assessed`, `not_configured` (no `url` hint) or `blocked` (the URL is out of scope);
in both of the latter cases zero requests are sent.

## Inputs (`auth_json`)

```json
{
  "test_hints": {"web_protocol": {
      "url": "https://app.example/portal",       // required: one declared target
      "host_header": "attacker.example",         // a host you own (lab / your own domain)
      "reset_path": "/reset",                    // optional: the password-reset route
      "cache_probe": "X-Forwarded-Host",         // the unkeyed header to canary
      "param": {"name": "amount", "valid": "100", "invalid": "5000"},
      "methods": "/admin/export",                // or {"path": ..., "protected_marker": "..."}
      "smuggling": true                          // opt-in; nothing is sent without it
  }}
}
```

Each key is independent: a key that is absent is a **limitation** and sends no
request of that kind. No `url` at all means no request at all.

`param` may be a bare name instead of an object; the audit then uses opaque canary
values, which cannot prove an application-level difference — supply `valid` and
`invalid` to make the check meaningful. `methods` may be `true` (probe the declared
`url`), a path, or `{"path", "protected_marker"}`.

## Vector → proof → CWE

| Vector | A finding requires | CWE |
|---|---|---|
| Host header injection (`X-Forwarded-Host`, `X-Host`, `Forwarded: host=`, `Host:`) | the injected host lands in a `Location` header or in an absolute URL in the body (the declared reset link included); quote is `Location: <url>` (header fact) or the absolute URL | 601 |
| Web cache poisoning (declared unkeyed header + unique canary) | the canary is served to a **second** request that did not send the header; the poison request is bound as extra evidence | 349 |
| HTTP parameter pollution (declared parameter, duplicated) | the duplicate answers 2xx where the single invalid value was refused 4xx, the response differs from **both** single-value controls, and it carries the executed (last) copy | 235 |
| Method tampering | GET was refused 401/403/405 and another verb returns 2xx with body content the refusal did not have | 650 |
| `X-HTTP-Method-Override` | GET with the override header returns that content where plain GET was refused | 650 |
| Request smuggling | **detection only**, and only with `smuggling: true`: a CL.TE preamble on one raw connection and the canary request answered on a *different* connection | 444 |

Everything weaker is an observation: a bare reflection in a template, cache
headers present but no canary served, HEAD/OPTIONS answering differently (no body
to prove content), an unhonoured override header, an undesynced smuggling probe
with its timings. A cacheless response is a **limitation**, never a pass.

## Egress and smuggling

The smuggling probe is the only raw socket in the audit. It asks
`Egress(db, scope, engagement_id, tool="protocol_smuggle").decide(host, port, scheme)`
first, dials `decision.ip` (never the hostname), and opens nothing when the decision
denies. Only plain `http` is implemented — no TLS wrap — so an `https` URL records a
limitation instead of a payload. The payload and both responses are stored as an
`http_raw` evidence blob.

## Lab

`labs/protolab/app.py` (Flask, `LAB_PORT`, module-level state, `application` is the
WSGI entry point behind the shim):

| Endpoint | Behaviour |
|---|---|
| `/portal` | proxy shim builds `Location` from `X-Forwarded-Host` (seeded) |
| `/reset` | password-reset link built from the `Host` header (seeded) |
| `/echo` | reflects `X-Forwarded-Host` into an HTML comment — observation only |
| `/cache` | cache keyed on the path only, serves the caller's `X-Cache-Canary` (seeded) |
| `/pay` | validates the first `amount`, settles the last (seeded) |
| `/export` | GET 403, protected action only via PUT (seeded) |
| `/hard/*` | the same routes with correct controls: zero candidates |

`tests/audit/test_web_protocol_audit.py` runs the audit in-process against that lab
and asserts one candidate per seeded weakness with its quote inside the bound
evidence, zero candidates on `/hard/*`, zero requests when the hint is absent, and
that every raw connection was authorized by `Egress.decide` (with zero sockets when
it denies).