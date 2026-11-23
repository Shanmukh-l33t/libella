# Impact proof

A **verified** finding means an independent replay reproduced the recorded
signal. It does **not** mean impact was demonstrated. Impact proof is a
separate, explicit dimension: it runs only when the operator authorizes a lab
and the finding's own proof URL is inside the engagement scope.

## Gate

```json
{
  "test_hints": {
    "impact_proof": {
      "lab": true,
      "markers": [{"table": "secrets", "column": "token", "value": "IMPACT-MARKER-..."}],
      "sensitive_fields": ["email"],
      "object_id": "2",
      "command": "id",
      "param": "host"
    }
  }
}
```

`prove_impact` sends **zero requests** unless `lab` is exactly `true`, a
supported CWE is present, the finding carries a replayable GET `proof_request`,
and that URL passes `scope.check_url`. Out-of-scope targets are refused.
Authorization is never inferred from the finding or its severity.

## Classes

| CWE | Demonstration | Required signal |
|-----|---------------|-----------------|
| 89 | `UNION SELECT <column> FROM <table>` through the finding's parameter | every declared marker `value` returned verbatim |
| 639 / 284 / 285 | read the other identity's object with the finding's headers | declared sensitive field **and** the object id in the response |
| 78 / 94 | `; <command>` with `command` from the read-only allowlist (`id`, `whoami`, `uname -a`) | distinguishable command output (`uid=`, a username line, kernel name) |

A response that merely differs from a control is not impact. Any other CWE
returns `not_attempted`: no impact proof is defined for that class.

## Destructive actions are out of scope

The module never writes, uploads, downloads, opens a shell, or sends any
command outside the read-only allowlist. A write-looking command (`rm -rf`,
`curl`, `bash -i`) is refused before a request is built.

## Result

`{status, impact, observations, limitations}`, where status is one of
`demonstrated`, `not_attempted`, `refused`, `failed`. Each demonstrated impact
binds the exchange that returned it, records an `impact_demonstrated`
observation with the verbatim quote, and returns the finding id. There is no
impact column in the findings table: impact state lives in the observation and
in the returned record.

## Lab

`labs/impactlab/app.py` (Flask, `LAB_PORT` default 0, 127.0.0.1): vulnerable
`/product`, `/orders/<id>`, `/ping`; hardened twins under `/hard/*` that must
yield zero demonstrations. `/ping?cmd=` runs an arbitrary command on purpose;
the impact layer must never call it.

## Limits

- GET proofs only; a POST proof is `not_attempted` rather than guessed.
- Extraction assumes the endpoint projects at least one column (SQLite
  `UNION` column-count matching is not probed).
- Reads only what the declared marker/field/command shows; no exfiltration of
  unrelated data.