# Libella — adversarial audit of the platform (not the labs)

Scope: the platform itself. All attacks were executed against an in-process
localhost lab (127.0.0.1, ephemeral port) and unit-level boundaries; nothing
external was touched. Read-only review of `web/`, `benchmarks/` and `labs/`;
no changes made outside `src/libella/` and `tests/audit/`.

Test-first: every defect below has a regression test in `tests/audit/` that
failed against the original code. 93 audit tests (110 with the pre-existing
suite). Baseline and post-fix benchmark both: **13/13 seeds on vuln, 0 false
positives on hardened, evidence chain valid**.

## Defect summary

| Severity | Count |
|---|---|
| High | 5 |
| Medium | 12 |
| Low | 6 |
| **Total** | **23** |

## High

### H1 — URL-prefix targets authorized any host/port that shared the string prefix
`src/libella/scope.py:187` (`_url_matches`, `check_url`)

`_url_matches` was `url.startswith(target)`. With target `http://127.0.0.1:PORT`,
all of these were authorized:

- `http://127.0.0.1:<port>@localhost:9999/` — userinfo trick, real destination is
  `localhost:9999` (urlparse hostname ignores userinfo, string prefix does not).
- `http://127.0.0.1:PORT11/` — a different port.

PoC: `tests/audit/test_scope_bypass.py::test_userinfo_prefix_does_not_authorize_other_origin`,
`::test_port_variant_of_url_target_is_out_of_scope`,
`::test_url_target_prefix_respects_path_boundary`,
`::test_path_traversal_cannot_smuggle_out_of_prefix`.

Fix: the scope module now compares parsed, normalized components
(`parse_origin`: lowercased scheme/host, explicit port, `posixpath.normpath`
over the percent-decoded path) and requires scheme+host+port equality plus a
path-boundary prefix. `..` segments and trailing-dot hosts can no longer shift
the compared prefix.

### H2 — `url_prefix` exclusions bypassed by case, encoding and dot segments
`src/libella/scope.py:200` (`_excluded_by_prefix`), `check_url`

Exclusion `http://host/admin` did not exclude `HTTP://host/admin/x`,
`http://HOST/admin/x`, `http://host/%61dmin/x` or `http://host/./admin/x`
(the scheme was lowercased by `urlparse` but the exclusion test was a raw
string prefix, and matching was case-sensitive).

PoC: `tests/audit/test_scope_bypass.py::test_exclusion_prefix_case_and_encoding_bypass`.

Fix: exclusions are matched on normalized host/port/path (scheme-insensitive),
keeping the deliberately conservative "over-block is safe" prefix semantics.

### H3 — Tool runner scoped a caller-supplied target, not the parameter the adapter dials
`src/libella/tools/runner.py:56`, `src/libella/tools/adapters.py:230`

Every adapter declares its own egress parameter, but the runner checked the
`target` argument. For `ffuf` the dialled URL is the `url` parameter; a call
with `target=<in-scope>` and `url=<out-of-scope>` passed the scope gate and the
binary would have scanned the attacker-chosen origin. Any new adapter whose
parameter name differs from `target` inherited the same hole.

PoC: `tests/audit/test_tool_injection.py::test_ffuf_url_param_cannot_escape_scope`
(also `::test_adapter_target_param_is_declared`).

Fix: `ToolSpec.target_param` (default `"target"`; `"url"` for ffuf, `"domain"`
for subfinder). The runner derives the scope destination from the *validated*
parameters and audits that destination.

### H4 — Finding state machine allowed unverified findings to be "reported"
`src/libella/findings.py:107` (`transition`)

Only `validated` required a reproduced verification. `suspected -> reported`
(or `remediated`, `retested_fixed`, `retested_persists`) was accepted, and the
report counts `reported`/`retested_persists` as confirmed — so a single
authenticated `POST /api/findings/{id}/state {"state":"reported"}` turned an
unverified candidate into a confirmed finding in the deliverable.

PoC: `tests/audit/test_finding_pipeline.py::test_unverified_finding_cannot_be_reported`,
`::test_retested_states_require_a_real_retest`,
`::test_verified_finding_can_be_reported`.

Fix: explicit transition graph (`ALLOWED_TRANSITIONS`); `validated` **and**
`reported` require a reproduced verification row; `retested_fixed` /
`retested_persists` require a matching `retests` row. Retest transitions stay
reachable from any state (the retest row is the proof).

### H5 — Empty proof quote verified any finding
`src/libella/verifier.py:86` (`_compare`)

`_norm("") in _norm(body)` is always true. A candidate submitted with a
`proof_request` and `quote=""` (e.g. a scanner result with no template id)
was replayed, "reproduced" and promoted to `validated`.

PoC: `tests/audit/test_finding_pipeline.py::test_empty_quote_cannot_verify_a_finding`.

Fix: a blank quote is not proof — `_compare` fails closed with
"empty proof quote"; verification stamps `not_reproduced`.

## Medium

### M1 — Malformed URLs crashed the authorization gate
`scope.py:211` (`check_url`) — `p.port` raises `ValueError` for
`http://host:99999/` and `http://host:PORT.a/`, and `urlparse` raises for
`http://[::1/`. The exception escaped the gate (500 from the API, intent
aborted mid-assessment). PoC: `test_scope_bypass.py::test_malformed_urls_refuse_without_raising`.
Fix: parse errors return `Decision(False, ...)`.

### M2 — Malformed scope documents were accepted at creation and crashed checks
`scope.py:94` — `{"targets":[{"value":"1.2.3.4"}]}` (no `kind`) raised
`KeyError: 'kind'` inside `_ip_blocked` during a check. PoC:
`test_scope_bypass.py::test_scope_rejects_malformed_target_at_construction`,
`::test_scope_rejects_malformed_exclusion_at_construction`.
Fix: `Scope._validate()` rejects bad kinds, unparseable ip/cidr/url and bad
`allowed_ports` at construction (fail closed before any work starts).

### M3 — IPv4-mapped IPv6 bypassed the always-blocked ranges
`scope.py:145` — `::ffff:169.254.169.254` is not "in" `169.254.0.0/16`, so a
`::/0` authorization reached cloud metadata, and cross-version cidr matching
was inconsistent. PoC: `test_scope_bypass.py::test_ipv4_mapped_ipv6_cannot_reach_metadata`,
`::test_ipv6_grants_do_not_widen_across_versions`.
Fix: mapped addresses are normalized to IPv4 before blocklist/target checks;
cidr matching refuses version mismatches.

### M4 — Evidence hash chain forked under concurrency
`evidence.py:57` — `put()` read the chain head and inserted in two separate
critical sections. 16 threads x 3 puts produced `verify_chain -> ok=False`
(false tamper alarm, and real forks are then indistinguishable from noise).
PoC: `tests/audit/test_evidence_integrity.py::test_concurrent_puts_keep_the_chain_valid`.
Fix: one lock covers head-read + insert.

### M5 — Tool output was buffered in full before the cap
`tools/runner.py:133` — `subprocess.run(capture_output=True)` materialized the
whole stream, then sliced to `MAX_OUTPUT`. A 20 MB emitter added ~20 MB RSS.
PoC: `tests/audit/test_resource_caps.py::test_tool_output_is_capped_while_capturing`.
Fix: `_run_capped` streams both pipes through bounded buffers, keeps draining
(so the child never blocks), and reports `truncated`.

### M6 — HTTP responses were buffered in full before `BODY_CAP`
`tools/http_probe.py:117` — `client.request()` read the entire body; a 32 MB
response added ~33 MB RSS while returning only 256 KB. PoC:
`tests/audit/test_resource_caps.py::test_huge_response_is_capped_and_not_buffered`.
Fix: `client.stream()` + `_read_capped` (reads one byte past the cap so
truncation is provable without trusting `Content-Length`).

### M7 — Arbitrary filesystem paths in `wordlist` / `templates`
`tools/adapters.py:14` — `ffuf -w /etc/passwd` (line-by-line file oracle) and
`nuclei -t /etc` were accepted; the only limit was `maxLength`. PoC:
`test_tool_injection.py::test_ffuf_wordlist_cannot_read_arbitrary_file`,
`::test_ffuf_wordlist_traversal_rejected`,
`::test_nuclei_templates_outside_template_root_rejected`.
Fix: `_confine_path` resolves the value and requires it under
`LIBELLA_WORDLIST_DIR` (default `/usr/share/wordlists`) or
`LIBELLA_TEMPLATE_DIR` / `/usr/share/nuclei-templates`.

### M8 — Session cookies leaked through the exchange/evidence API and missed redaction
`api.py:309`, `report.py:32` — `GET /api/exchanges/{id}` returned
`req_headers_json` / `resp_headers_json` verbatim (Cookie, Set-Cookie,
Authorization), and `REDACT_PATTERNS` had no cookie rule, so the same values
survived `redact()` in the evidence endpoint. PoC:
`test_api_security.py::test_exchange_api_does_not_leak_session_cookies`,
`test_secrets_report.py::test_cookie_headers_are_redacted`.
Fix: `redact_headers()` masks credential-bearing headers in both the exchange
row and the evidence blob; `redact()` gained header-shaped (text and JSON) and
session-parameter rules, ordered so finding prose ("Session cookie 'x' missing
flags") is untouched.

### M9 — Report redaction only covered Markdown; JSON/SARIF leaked secrets
`report.py:57` (`_safe`) — `report.json` and `report.sarif` were written from
unredacted DB values, so a secret in a description/impact/remediation reached
the deliverable and the stored `report` evidence artifact. PoC:
`test_secrets_report.py::test_report_text_fields_are_redacted_everywhere`.
Fix: every report text field passes through `redact` + `_md` before it enters
the report dict, so all three renderings and the evidence copy share one
sanitized source.

### M10 — Markdown injection via target-derived strings
`report.py:51` (`_md`) — a crawled endpoint or finding title containing
backticks/newlines broke out of its code span and injected report sections
(`\n## ...`), i.e. a target could write arbitrary content into the deliverable.
PoC: `test_secrets_report.py::test_markdown_injection_via_endpoint_and_name`,
`::test_sarif_is_structurally_valid` (URI with spaces/newlines).
Fix: `_md` collapses CR/LF and neutralizes backticks for every rendered value;
SARIF `artifactLocation.uri` is percent-encoded.

### M11 — `/resume` had no state or worker guard
`api.py:161` — resuming a `running` engagement started a second orchestrator
thread for the same engagement (double execution, duplicated tool calls,
concurrent chain writes). PoC:
`test_api_security.py::test_resume_refuses_an_already_running_engagement`.
Fix: 404 for unknown ids, 409 unless status is draft/paused/failed/cancelled/
budget_exhausted, 409 if a worker thread is alive; thread is registered in
`App._threads`.

### M12 — Intent completion ignored the fencing token
`orchestrator.py:202` — the lease was swept and re-claimed, but the old worker
still executed `UPDATE intents SET status='done'` unconditionally, overwriting
the new owner's state (fencing was declared in the architecture, unused in
code). PoC: `tests/audit/test_races.py::test_stale_worker_cannot_complete_a_reclaimed_intent`.
Fix: `_complete()` updates only `WHERE claim_token=?`; a lost lease emits a
`lease_lost` event instead of corrupting state.

## Low

| ID | Defect | Location | PoC test | Fix |
|---|---|---|---|---|
| L1 | A tool could run under a caller-supplied category different from its own (web tool under a recon-only grant) | `tools/runner.py:44` | `test_tool_injection.py::test_runner_refuses_tool_run_under_foreign_category` | refuse `category != spec.category` |
| L2 | Tampered/missing exchange evidence and unknown report ids produced 500s | `api.py:309`, `:335` | `test_api_security.py::test_unknown_ids_are_404_not_tracebacks`, `::test_tampered_exchange_evidence_is_refused_by_api` | 409 for integrity failures, 404 for unknown ids |
| L3 | Tampered proof-spec raised instead of "inconclusive" | `verifier.py:37` | `test_finding_pipeline.py::test_tampered_proof_spec_is_inconclusive_not_a_crash` | catch and return inconclusive; malformed `proof_request` rejected |
| L4 | `evidence.read()` did not confine the path to the store (a forged row read an arbitrary file) | `evidence.py:79` | `test_http_boundary.py::test_evidence_path_cannot_escape_the_store` | resolve + containment check |
| L5 | `evidence.put()` accepted `../` in the engagement id (blob path traversal) | `evidence.py:36` | `test_evidence_integrity.py::test_engagement_id_cannot_traverse_the_store` | `SAFE_ID` whitelist |
| L6 | `check_host_port` expanded a URL target to every subdomain of its host | `scope.py:262` | `test_scope_bypass.py::test_url_target_with_subdomain_host_tool_match_is_not_expanded` | exact hostname match |

## Attacks that were verified to fail closed (regression-tested, no defect)

- Auth: every route except `/api/health` returns 401 without a token (19 routes,
  parameterized); wrong/oversized tokens rejected; `secrets.compare_digest` is
  used for the comparison; SSE requires the token and accepts it as a query
  parameter (EventSource cannot set headers).
- Engagement isolation: findings/report endpoints filter by engagement; the
  report for A never contains B's findings.
- DNS rebinding: a stub client that connects to a different peer IP than the
  scope check resolved is refused and nothing is captured
  (`test_http_boundary.py::test_dns_rebinding_peer_is_refused`).
- Out-of-scope redirect hops: refused before egress; the second server records
  zero hits (`test_resource_caps.py::test_redirect_out_of_scope_is_refused_before_egress`).
- Redirect loops bounded at `MAX_HOPS`; crawl bounded by `max_pages`
  (`test_resource_caps.py`).
- Prompt injection: a fully hijacked planner (out-of-scope target, metadata
  target, privileged role, hostile objective) cannot create intents, cannot
  mutate `scope_json`, and a hostile intent already in the DB is refused at the
  execution gate (`test_llm_injection.py`, 4 tests).
- Fake evidence ids and cross-engagement evidence ids leave a finding
  `suspected`; dedup never overwrites severity/title and is per-engagement
  (`test_finding_pipeline.py`).
- Concurrent intent claims: exactly one winner, `attempts == 1`
  (`test_races.py::test_concurrent_claims_are_exclusive`); parallel
  verifications leave the chain valid and one validated finding.
- No shell: metacharacters are rejected in every string param of every adapter
  and in array items; a hostile target never reaches a shell
  (`test_tool_injection.py`, 19 tests).
- CSV formula escaping covers `= + - @ \t \r` (`test_secrets_report.py::test_csv_formula_escaping`);
  SARIF is structurally valid (2.1.0 schema, level enum, URI parses, no
  whitespace/control characters).

## Test inventory (new)

`tests/audit/` — 93 tests, all localhost only, ~21 s total:

| File | Tests | Covers |
|---|---|---|
| `conftest.py` | — | in-process HTTP lab (ok/huge/redirect-loop/redirect-out/link-bomb), `App`, `TestClient`, scope and engagement factories |
| `test_scope_bypass.py` | 18 | userinfo/port/path prefix, traversal, exclusions (case/encoding/dot), malformed URLs & scopes, IPv4-mapped IPv6, IPv6 grant widening, decimal-host alias, category/port gates, subdomain expansion |
| `test_tool_injection.py` | 29 | per-adapter metacharacter rejection, unknown params, wordlist/templates traversal, target-param scoping, category identity, no-shell, output cap |
| `test_api_security.py` | 12 | auth on every route, token shapes, SSE, resume guard, verify happy path, 404/409 handling, cookie redaction, engagement isolation, settings masking |
| `test_evidence_integrity.py` | 5 | concurrent chain, single-row forgery, per-engagement heads, id traversal, content addressing |
| `test_finding_pipeline.py` | 8 | state machine, verification gate, empty quote, tampered proof, foreign evidence, dedup, unknown state |
| `test_llm_injection.py` | 4 | compile gate (scope/role/objective), state immutability, exec gate, privileged roles |
| `test_resource_caps.py` | 5 | huge body (+RSS bound), tool output (+RSS bound), redirect loop, out-of-scope redirect, crawl bomb |
| `test_secrets_report.py` | 6 | cookie/header redaction, redaction of all report surfaces, markdown injection, SARIF validity, CSV escaping |
| `test_races.py` | 3 | stale-worker fencing, exclusive claims, parallel verifications |
| `test_http_boundary.py` | 3 | DNS rebinding peer, out-of-scope proof replay, evidence path escape |

## Benchmark re-verification

```
baseline  (fresh dir, before fixes): vuln 13/13 seeds, 0 unmatched, chain ok (172 rows, 154.9s)
                                    hardened 0/13, 0 false positives, chain ok (146 rows, 154.7s)
after     (/tmp/audit_bench):       vuln 13/13 seeds, 0 unmatched, chain ok (142 rows, 154.9s)
                                    hardened 0/13, 0 false positives, chain ok (113 rows, 154.2s)
```

Detection, false-positive count, duration and chain validity are unchanged.
The evidence-row count is lower because crawl/orchestrator changes landed
concurrently from another workstream (duplicate-work prevention and JS bundle
mining); it is not attributable to the fixes above and does not affect scoring.

## Residual risks (accepted, not fixed in this pass)

1. **Ledger forgery with database write access.** The hash chain is unkeyed and
   unanchored: an attacker who can rewrite the SQLite rows *and* the blobs can
   recompute the entire chain undetectably. Anchoring (HMAC with an operator
   key, or periodic external head publication) is needed for real tamper
   evidence. Single-row forgery and blob edits are detected (tested).
2. **Single operator token = global access.** `GET /api/findings/{id}`,
   `/api/evidence/{id}`, `/api/exchanges/{id}` are not engagement-scoped. With
   one token this is the intended single-tenant model; it becomes an IDOR the
   moment multi-user auth is added. Engagement-scoped list/report endpoints are
   isolated (tested).
3. **Token transport.** The SSE endpoint accepts `?token=`; uvicorn access logs
   will contain it. Header auth is available for all other routes.
4. **Secrets at rest.** The API token and the LLM `api_key` are stored in plain
   text in `settings` (the architecture claims Fernet for credentials). Anyone
   who can read the SQLite file gets them. `GET /api/settings` masks the key.
5. **Operator console.** `main.py` prints the API token to stdout on startup
   (first-run UX); that output is a log.
6. **`LLM.base_url` is settable via `PUT /api/settings`.** Combined with a
   stored `api_key` this is an exfiltration path for an operator-supplied key
   if the API is ever exposed beyond localhost. No validation/allowlist.
7. **DNS resolution has no timeout** (`socket.getaddrinfo`); a slow resolver
   stalls a worker until the lease expires (recovery is now safe thanks to
   fencing, but the work is repeated).
8. **`cancel` does not kill running subprocesses** (the architecture promises
   propagation); a tool call runs to its own timeout. Bounded by
   `ToolSpec.timeout_s`.
9. **Findings from nuclei are trusted for title/endpoint** (local template data
   and scanned URL) — sanitized at render time, but the dedup key is
   target-influenced. No cross-engagement effect (tested); within one
   engagement a hostile target could merge two scanner results.
10. **No CSV export exists**, so CSV formula injection has no live surface;
    `_csv_escape` is unit-tested and ready for one. SARIF and Markdown are the
    only machine/human renderings.

## Post-audit maintainer fixes

- Residual #4 (secrets at rest) CLOSED: `src/libella/secrets.py` adds Fernet
  encryption for the API token and LLM config in `settings` (key file 0600 or
  `LIBELLA_SECRET_KEY`). Legacy plaintext rows are migrated on read.
  Regression: `tests/test_secrets_at_rest.py` (4 tests). Suite: 114 passed.
- ARCHITECTURE.md / THREAT_MODEL.md corrected to state that cancel bounds
  subprocesses by tool timeout (hard-kill propagation remains roadmap) and
  that the hash chain is unkeyed (residual #1 stands).

## Notes for reviewers

- Safeguards were never disabled or weakened to make tests pass; the two
  `try/except ValueError` additions (verifier) only stop a recorded verdict from
  raising when the state machine disallows the move — the gate itself is
  stricter than before.
- `tests/audit/conftest.py` binds only 127.0.0.1 on an ephemeral port and shuts
  the server down per test; the suite makes no external network calls.