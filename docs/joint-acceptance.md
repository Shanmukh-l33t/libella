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
engagement carries bound evidence ids, the evidence chain verifies, the coverage
ledger counted at least one finding against a WSTG test, the `verify` intent completed,
and **every** finding reached `validated` through independent replay. A finding that
stays `suspected` fails the run: the point of the benchmark is the whole pipeline, not
the detector.

The four new engagements pick the cheapest reliable seed on purpose — LFI rather than
the 5s blind command-injection sleep, host-header injection rather than the opt-in
(and slow) smuggling detection. The OAuth `redirect_uri` bypass is proven by the
`Location` header alone: the attacker origin names the `127.0.0.2` loopback alias, which
is deliberately *not* an authorized target, so the audit cannot follow the redirect and
the header is the whole proof.

## Output

`acceptance_offence.json` keeps its shape: `{"engagements": {<id>: {...}}, "failures": [...]}`
with the original per-engagement keys (`elapsed_s`, `intents`, `findings`, `wstg`,
`asvs`, `ledger`, `evidence_chain`). The engagements are additive. Stdout is a compact
one-line-per-engagement summary plus `PASS`/`FAIL`.

## Runtime

Each engagement runs the deterministic plan, so each pays for a nuclei scan before its
audit: nuclei covers 5–7% of its 6.6k templates in ~85s on a single-threaded lab, is
stopped by its own per-host error cap, and the run is recorded as `scan_partial` in the
engagement's own numbers (e.g. `nuclei covered 6% of its templates (1027 requests, 0
matches) before it stopped`) — a truthful partial scan, not a pass. Measured on the
six engagements: 89.6s to 138.5s each, ~10 minutes total.

The labs are served single-threaded on purpose: with `threaded=True` werkzeug accepts
the scan's 25 concurrent sockets, nuclei never reaches its error cap, and one
engagement then spends a quarter of an hour on templates instead of ~85s. Running
several engagements at once against in-process labs starves them for the same reason
(one interpreter, several scanners) — run them one at a time.

## Limits

- The OAuth landing verification (`landed`) is not exercised here; the header proof is.
- Request smuggling is never attempted: this benchmark declares no `smuggling` hint.
- A failed assertion is data, not a skip: `failures` lists exactly what did not hold,
  and the exit code is 1.

## Measured result

Six engagements, one lab instance each, deterministic mode, on `d5df28d` + this change
(2026-11-23): 21 findings, all `validated`, every evidence chain intact.

| Engagement | Wall | Intents done | Findings | CWEs |
|---|---|---|---|---|
| `eng_jwt` | 95.3s | 7/7 | 4 | 347, 613, 693, 863 |
| `eng_role` | 138.5s | 8/8 | 4 | 306, 614, 639, 693 |
| `eng_oauth` | 91.2s | 7/7 | 5 | 352, 598, 601, 693, 863 |
| `eng_session` | 94.7s | 7/7 | 4 | 384, 613, 620, 693 |
| `eng_inj` | 127.8s | 7/7 | 2 | 22, 693 |
| `eng_proto` | 89.6s | 7/7 | 2 | 601, 693 |

Six of the six planned audit families now run end to end. `CWE-693` (protection
mechanism failure) comes from the response-header checks each lab also fails; it is not
part of the family under test but it is real output of the same run.

The hardened `/hard/*` twins of each lab are covered by the audit modules' own unit
tests (zero candidates), not by this benchmark: those tests can assert a negative in
seconds, while a full engagement costs a nuclei scan. This benchmark would rather stay
honest about what it exercises than double its runtime to re-prove a negative.
