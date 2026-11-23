# Joint offence acceptance

`benchmarks/acceptance_offence.py` answers one question the audit modules' own tests
cannot: does an engagement carry each audit end to end — planner, executor, a real
lab, the finding pipeline, the coverage ledger and the evidence chain?

```sh
PYTHONPATH=src python benchmarks/acceptance_offence.py /tmp/joint
```

The labs are served in-process on ephemeral ports (`werkzeug.make_server`, port 0),
one process per lab module. Credentials (`USERS`, `CLIENT_ID`) are read from the lab
modules at runtime; they are never copied into the benchmark. The only file written
into the output directory besides the app's own data is the role lab's OpenAPI
inventory, which is the operator input that workflow needs.

## What runs

Six engagements, one per audit, each with its own lab instance and its own
`max_duration_s: 900` budget. The credential-bearing secrets are read from the lab
modules, not from this document.

| Engagement | Lab | Declared input | Asserted |
|---|---|---|---|
| `eng_jwt` | `labs/jwtlab` | identity + `test_hints.jwt` | `jwt_audit` done, CWE-347 |
| `eng_role` | `labs/rolelab` | two same-rank identities + OpenAPI | `privesc_audit` done, CWE-639/285/306 |
| `eng_oauth` | `labs/oauthlab` | `oauth` block (prefix-matched `redirect_uri`) | `oauth_audit` done, CWE-601 |
| `eng_session` | `labs/oauthlab` | `session` block (fixation, logout, re-auth seeds) | `session_audit` done, CWE-384/613 |
| `eng_inj` | `labs/injlab` | `test_hints.injection` → `/download?file=`, `kind: lfi` | `injection_audit` done, CWE-22 |
| `eng_proto` | `labs/protolab` | `test_hints.web_protocol` → `/portal` + `host_header` | `web_protocol_audit` done, CWE-601 |

Every engagement also asserts the invariants of any real run: each finding in the
engagement carries bound evidence ids, the evidence chain verifies, and the coverage
ledger counted at least one finding against a WSTG test.

The four new engagements pick the cheapest reliable seed on purpose — LFI rather than
the 5s blind command-injection sleep, host-header injection rather than the opt-in
(and slow) smuggling detection. The OAuth `redirect_uri` bypass is proven by the
`Location` header alone: the attacker page is served by the lab on the `127.0.0.2`
loopback alias but is deliberately *not* an authorized target, so the audit cannot
follow the redirect and the header is the whole proof.

## Output

`acceptance_offence.json` keeps its shape: `{"engagements": {<id>: {...}}, "failures": [...]}`
with the original per-engagement keys (`elapsed_s`, `intents`, `findings`, `wstg`,
`asvs`, `ledger`, `evidence_chain`). The engagements are additive. Stdout is a compact
one-line-per-engagement summary plus `PASS`/`FAIL`.

## Runtime

Each engagement runs the deterministic plan, so each pays for a nuclei scan before its
audit: nuclei covers ~6% of its 6.6k templates in ~80s on a single-threaded lab, is
stopped by its own per-host error cap, and the run is reported as `scan_partial` — a
truthful partial scan, not a pass. Expect roughly 80–100s per engagement.

The labs are served single-threaded on purpose: with `threaded=True` werkzeug accepts
the scan's 25 concurrent sockets, nuclei never reaches its error cap, and one
engagement then spends a quarter of an hour on templates instead of ~80s. Running
several engagements at once against in-process labs starves them for the same reason
(one interpreter, several scanners) — run them one at a time.

## Limits

- The OAuth landing verification (`landed`) is not exercised here; the header proof is.
- Request smuggling is never attempted: this benchmark declares no `smuggling` hint.
- A failed assertion is data, not a skip: `failures` lists exactly what did not hold,
  and the exit code is 1.