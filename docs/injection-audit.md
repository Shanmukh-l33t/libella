# Injection depth audit (XXE, command, LFI/traversal, CRLF)

`libella.injection_audit.audit_injection(db, evidence, probe, scope, engagement_id, auth_json, pipeline, intent_id=None)`

Attacks the parameters an operator declares as injectable input. Parameters are
**never guessed**: a target without a declared parameter is a limitation, not a
probe. Every request goes through the engagement's scoped `HttpProbe` (scope
checked per hop, every exchange stored as evidence). Every candidate carries a
benign control at the same endpoint and parameter, a quote that exists in the
captured evidence blob, and a `proof_request` the verifier can replay.

Returns `{status, candidates, observations, limitations, errors}`. `status` is
`completed` when at least one in-scope target was attacked, `limited` otherwise.

## Inputs (`auth_json`)

```json
{"test_hints": {"injection": {"targets": [
  {"url": "https://app.example/xml", "method": "POST", "param": "xml",  "kind": "xxe"},
  {"url": "https://app.example/ping",                    "param": "host", "kind": "command"},
  {"url": "https://app.example/download",                "param": "file", "kind": "lfi"},
  {"url": "https://app.example/set",                     "param": "name", "kind": "crlf"}
]}}}
```

`method` defaults to `GET`. A `GET` target puts the value in the query string; a
write method puts it in a JSON body `{param: value}`; `param: "body"` sends the
value as the raw request body with `content_type` (XML/SOAP endpoints). `kind`
is one of `xxe`, `command`, `lfi`, `traversal`, `crlf`; without it all classes
are attempted.

## Attack → proved when → CWE

| kind | payload (wire) | proved when | CWE |
|---|---|---|---|
| `xxe` | `<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>` | a `/etc/passwd` line is echoed back | 611 |
| `xxe` | `<!ENTITY % remote SYSTEM "http://127.0.0.1:<port>/oob/<token>">%remote;` | the audit's loopback listener records the token path from a request the audit did not make | 611 |
| `command` | `;sleep 5`, `\|sleep 5`, backticks, `$(sleep 5)`, `& ping -n 5 127.0.0.1` (Windows `Server` header only) | blind: two baselines, then the payload twice, each delay ≥ 4s **and** ≥ 4× the baseline median | 78 |
| `lfi`/`traversal` | plain, `..%2f`, `..%252f`, `%2e%2e%2f`, `....//`, overlong UTF-8 `%c0%ae`, trailing dot/space, `php://filter/convert.base64-encode/resource=index.php` (PHP targets only) | the response carries a `/etc/passwd` line or a base64 blob that decodes to `<?php` | 22 |
| `crlf` | `a%0d%0aset-cookie:...%0d%0alibella-canary:1` | a `libella-canary` response header appears; a reflected body alone never counts | 113 |

Command injection never writes to disk and never exfiltrates: the only payloads
are sleeps. The timing observation is stored with a quote
(`delay 5.12s vs baseline 0.18s`); the candidate's quote is the captured
`duration_ms` of the delayed exchange.

The out-of-band listener is loopback-only (`127.0.0.1:0`, `http.server` in a
thread) and is started only for XXE targets. Libella never requests it; a hit
therefore originates at the target. It answers with a DTD declaring a
`file:///etc/passwd` entity, so a parameter-entity-capable parser also echoes the
file contents in the same exchange.

## Limits recorded rather than reported

- no `test_hints.injection.targets` → one limitation, zero requests
- target URL out of scope → limitation; nothing is sent
- control request failing, or a filtered target where no encoding reaches content
- an OOB listener is only reachable when the target can dial loopback: against a
  remote target the callback cannot arrive, and the observation says so
- an OOB quote lives in the listener-log evidence blob, not in a replayable HTTP
  response, so the verifier treats that finding as inconclusive rather than failed

## Lab

`labs/injlab/app.py` (Flask, `LAB_PORT`, default `0`, binds `127.0.0.1`): `/xml`
(hand-rolled entity expander, resolves `file://` and `http://`), `/ping`
(`shell=True`, really sleeps), `/download` (joined path, no normalisation),
`/setcookie` (parameter written into a header verbatim), and the `/hard/*`
mirrors that reject each class — the negative controls the tests require to
yield zero candidates.