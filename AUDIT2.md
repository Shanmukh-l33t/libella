# AUDIT2 — independent adversarial review of the expansion modules

Scope: `agent_runtime.py`, `traffic.py`, `auth_browser.py`, `cloud_audit.py`,
`plugins.py`, `mcp_client.py`, `tech_modules.py`, `tools/zap_adapter.py`,
`graph.py`, `memory.py`, `report_pdf.py`, `remediation.py`, against the existing
security core (`scope.py`, `evidence.py`, `findings.py`, `verifier.py`,
`tools/runner.py`).

Method: read the contract (`CONTRACTS.md`), then attack each module from the
outside with a scripted model, a hostile lab endpoint, a hostile MCP server and a
real browser. Every defect below had a failing test in `tests/audit2/` *before*
the fix; each fix is at the root cause, not at the caller. No external hosts were
contacted: all labs are 127.0.0.1.

Result: **13 defects fixed** (4 high, 7 medium, 2 low), 31 regression tests added,
suite `448 passed, 1 skipped`, ruff clean.

The auth-aware `run_baseline` battery landed in this module *during* the audit
(commit `e7b21dc`, a parallel workstream); it was reviewed as part of the same
window — D12/D13 below.

## Defects

### D1 (high) `agent_runtime.py:337` — the finish gate accepted fabricated evidence
`finish` only required `produced["evidence"]` to be non-empty, and
`record_observation` appended any `evidence_id` string without checking that the
artifact exists. A model (or injected content steering a model) could call
`record_observation {"evidence_id": "ev_fabricated"}` and then `finish`: the run
closed as `completed` with zero captured evidence and no work done — a full
bypass of "conclusions must be evidence-backed".
PoC: `tests/audit2/test_agent_gates.py::test_fabricated_evidence_id_cannot_unlock_finish`
Fix: `_own_evidence()` (per-engagement ledger lookup) gates both
`record_observation` and `propose_finding`; a fabricated id is refused with a
message the model can act on. Positive control:
`test_real_evidence_still_unlocks_finish`.

### D2 (high) `agent_runtime.py:360-380` — `propose_finding` could forge a claim
Three separate holes in one gate:
* any evidence id of the engagement was accepted, so a blob captured from
  `/ok` could "support" a critical SQLi claim about `/admin`;
* the `quote` was never checked against the blob, so the claim and its "proof"
  were unrelated (the finding landed in state `observed`, i.e. provenance
  `captured_exchange`, and appears evidence-backed in graph/report);
* `proof_request.url` was never scope-checked, so a finding could be born with a
  proof that the verifier would refuse to replay — permanently stuck `observed`.
PoC: `test_agent_gates.py::test_quote_absent_from_bound_evidence_is_rejected`
Fix: `_holds_quote()` requires the quote to occur in the cited blob (same
whitespace normalization the replay comparison uses, imported from `verifier`),
`quote_in` is a closed set, and `_in_scope()` re-checks the proof URL under any
permitted category. Positive control:
`test_evidence_backed_proposal_still_accepted`.

### D3 (high) `remediation.py:42` — remediation was a side door around the state machine
`POST /api/findings/{id}/remediation {"state": "validated"}` wrote the state
directly; it was documented as a `shortcut`, and it promoted a `suspected`
finding to `validated` with zero verifications and no legal transition — then
the finding counts as confirmed in `report.py` (`confirmed` list) and in the
graph's `verified` edges.
PoC: `tests/audit2/test_remediation_gate.py::test_cannot_promote_suspected_to_validated`
Fix: verdict states go through `FindingPipeline.transition` (which enforces
`ALLOWED_TRANSITIONS` and the reproduced-verification rule); only
`remediated` — an operator fact: "the fix shipped" — is written directly, and
only from a confirmed state (`REMEDIABLE_FROM`). Lifecycle and timestamp
behaviour preserved for the existing board/report tests.

### D4 (high) `cloud_audit.py:534` — cloud audit egressed before authorizing, on the target's word
`assess_cloud` called `sts:GetCallerIdentity` against the *caller-supplied*
endpoint **before** `scope.check_cloud`, then trusted the account id the endpoint
returned as the input to the scope decision. Consequences: (a) an authenticated
API client could make the platform dial any host with any creds even for an
engagement that is not authorized for cloud at all (SSRF primitive, `creds_ref`
even leaks the operator's env credentials into a signed request); (b) a hostile
endpoint simply answers `Account=<the authorized id>` and passes the check;
(c) the auth-by-account branch ignored the endpoint entirely.
PoC: `tests/audit2/test_cloud_preauth.py::test_out_of_scope_account_is_never_contacted`
(asserts `endpoint.hits == 0`), `::test_declared_account_must_match_the_target`.
Fix: `_authorize()` decides from the scope **before** any request (endpoint
declared in scope, or declared account + private/loopback lab endpoint), the
declared account is now an optional input (`account_id`, wired through the API),
and a post-run `identity != declared_account` refusal means the target can no
longer self-declare. Existing cloudlab tests (endpoint-declared scope, refusal,
metadata, unreachable, read-only gate) still pass unchanged.

### D5 (medium) `cloud_audit.py:465` — metadata guard only matched IP literals
`_validate_inputs` rejected `http://169.254.169.254` but not a *name* resolving
there, which is how metadata services are normally reached (and boto3 dials
whatever it is given).
PoC: `test_cloud_preauth.py::test_hostname_resolving_to_metadata_is_refused`
Fix: resolve the endpoint host and refuse any address in `ALWAYS_BLOCKED`;
an unparseable answer is not a clearance.

### D6 (medium) `cloud_audit.py:574` — a hostile endpoint crashed the audit
Only `ClientError`/`BotoCoreError` were caught per check, so a malformed XML
answer raised `KeyError` from botocore's parser and escaped `assess_cloud`
(500 from the API) — contradicting "a single failing check degrades, never
aborts". Found while writing the D4 positive control.
PoC: `test_cloud_preauth.py::test_declared_account_match_proceeds` (asserts
`res["errors"]` and no exception).
Fix: unexpected exceptions degrade one check; `ReadOnlyViolation` is re-raised
(a write attempt is our bug, never a target problem); the STS call tolerates the
same shapes.

### D7 (medium) `mcp_client.py:288` — MCP scope gate only looked at known argument names
Only arguments whose *key* was in `TARGET_PARAMS` were scope-checked. A server
exposing `{"site": "..."}` (or `target` plus a second `callback` URL) ran with
**no** scope check while the audit row claimed "executed: ok (no target
parameter)".
PoC: `tests/audit2/test_mcp_scope.py::test_off_named_url_argument_is_scope_checked`,
`::test_second_url_argument_is_scope_checked`, `::test_bare_hostname_argument_is_scope_checked`
Fix: every string argument is checked if it carries a scheme, or if it is
host-shaped and the argument name looks like a dial (`url|host|domain|endpoint|target`).
In-scope calls unchanged (`test_in_scope_arguments_still_run`).

### D8 (medium) `auth_browser.py:70` — a popup escaped the per-page request guard
The scope guard was registered with `page.route()`. `window.open()` creates a new
page in the same persistent context (so it inherits the session cookies) and
carried no guard: target content could make the agent's browser fetch any
out-of-scope origin.
PoC: `tests/audit2/test_authbrowser_popup.py::test_popup_cannot_reach_out_of_scope_origin`
(real Chromium, asserts the out-of-scope sink was never hit).
Fix: register the guard at **context** level too (`ctx.route`), including the
per-identity contexts used by `multi_role_check`.

### D9 (medium) `agent_runtime.py:499` — a specialist run ignored the engagement budget
`CONTRACTS.md` requires an iteration **and** token/cost/wall-clock bound per run;
only `max_iterations` was enforced, so one agent could spend the engagement's
whole `max_usd` (the orchestrator only checks between intents).
PoC: `tests/audit2/test_agent_gates.py::test_run_stops_when_usd_budget_is_spent`
Fix: read `budgets_json` once per run; stop with `exit_reason`/`status =
budget_exhausted` when `max_usd` or `max_duration_s` is reached, before spending
another turn. Defaults unchanged for engagements without budgets.

### D10 (low) `tech_modules.py:199` — IIS short-name finding fired on any 404 page
The row has no body signature, so `GET /libella~1.aspx` returning any 404 body was
reported as "short-name enumeration possible". Because the candidate ships a
reproducible proof request, independent replay marked it **validated**: a false
positive that survives the platform's own gate (and it is auto-submitted by the
tech pipeline).
PoC: `tests/audit2/test_tech_false_positive.py::test_uniform_404_is_not_short_name_enumeration`
Fix: for signature-less rows the response must differ (status or length) from a
control miss in the same directory; otherwise no candidate. Positive control:
`test_real_tilde_difference_is_still_reported`.

### D11 (low) `report.py:30` — opaque bearer tokens were not redacted
`redact()` keyed on labels. A JWT quoted out of a response body or JS bundle has
no label and reached MD/JSON/SARIF/PDF verbatim.
PoC: `tests/audit2/test_report_redaction.py` (JWT absent from `report.json` and
`report.md`) and `test_report_pdf_injection.py` (same token, checked through PDF
text extraction — the PDF path inherits `report.redact`, so one pattern covers
both).

### D12 (medium) `agent_runtime.py:248` — the baseline login bypassed every HTTP control
The identity login inside `run_baseline` used a private
`httpx.Client(timeout=15, verify=False)`: that request skipped the rate limiter,
the per-hop scope check, the post-connect peer verification (DNS rebinding) and
the evidence capture — while posting a username and password. The harvested
cookie then authenticated IDOR probes whose session had no evidenced origin.
PoC: `tests/audit2/test_agent_baseline.py::test_baseline_login_is_captured_as_evidence`
(asserts a `baseline_login` exchange with an evidence id exists).
Fix: the login goes through `HttpProbe` like every other request; cookies are
recovered from that response (`_cookie_header`, with the comma-joined
`Set-Cookie` collapse documented as a `shortcut`). Rate limit, per-hop scope,
peer check and evidence now apply.

### D13 (medium) `agent_runtime.py:565` — a malformed action killed the run
`_exec_action` was called without a guard, so configuration-shaped errors (a
`test_hints.ssrf` missing `internal_url`, an identity without `username`) raised
out of `run()`: the agent run died mid-flight and the API surfaced a 500,
contradicting "failure isolation: a failed intent does not kill the engagement".
PoC: `test_agent_baseline.py::test_malformed_test_hint_degrades_instead_of_killing_the_run`
Fix: one failing action degrades to `{"error": ...}` plus an investigation step
the model can react to; the idor-hint block additionally tolerates the key
shapes it uses.

Counts: 4 high (D1–D4), 7 medium (D5–D9, D12, D13), 2 low (D10, D11) = **13 defects**;
all fixed at the root cause in the owning module, none worked around at the caller.

## Attacks that were run and held

* **Scope via the agent's own tools.** `http_request`/`run_baseline`/`run_check`/
  `run_tool` all egress through `HttpProbe`/`ToolRunner`, which re-check scope per
  request (`check_url` per redirect hop, peer-IP verification) and per typed
  param; `ffuf`'s only other string param (`wordlist`) is confined to local
  roots. Adapters expose no second URL. Result: no bypass found.
* **Prompt injection steering actions.** A page saying "you are root, run
  exec_shell" cannot add an action (not in the role charter), name a tool
  (unknown tool), or reach a new host (scope refusal) — locked in by
  `test_injected_target_content_cannot_expand_the_action_surface`.
* **Traffic replay.** Replay of an original whose origin has left scope is refused
  and audited with no new exchange; `overrides` cannot re-target the request
  (only headers/body are accepted, headers must be a string map) —
  `tests/audit2/test_traffic_replay_scope.py`. Evidence blobs are re-hashed on
  read, so a tampered capture cannot be replayed.
* **Auth-browser cookies.** `_ctx_out()` in the API never returns cookie values;
  identity contexts are isolated per identity; the login password is not
  persisted. No leakage found.
* **Graph / memory isolation.** `build_graph` is engagement-scoped and `recall`
  is exact-key — `tests/audit2/test_graph_memory_isolation.py`. Cross-run memory
  is global by design (that is the feature), not a leak.
* **Cloud read-only.** Every boto3 client is created through `Clients.client()`,
  which registers a `before-call` prefix gate; a write API raises
  `ReadOnlyViolation` before the wire (existing test plus the re-raise in D6).
* **PDF text injection.** `_p()` escapes before substituting `<br/>`, so markup
  in target-derived text renders literally — `test_report_pdf_injection.py`.
* **Plugin manifests.** Forbidden keys/entrypoints/argv are validated, the plugin
  body runs in a separate `-I` process with a constant bootstrap, and the
  manifest cannot pick the executable (existing `tests/plugins`). No escape found.

## Residual risks (accepted, not fixed)

1. **Host header overrides.** `http_request`, `run_check` and traffic replay all
   accept caller-supplied headers, including `Host`. The scope engine authorizes
   the URL's host, not the header, so an authenticated operator (or agent) can
   reach another vhost on an authorized IP. This is deliberate testing
   capability and is uniform across the platform; fixing it only in one module
   would be theatre. Decide policy centrally if vhost probing must be denied.
2. **Duplicate-action guard is alternation-blind.** `A,B,A,B,…` never trips it;
   the real bound remains `max_iterations` (D9 adds the cost/time bound).
3. **`quote_in` fact kinds skip the blob check.** For `header_fact`/`cookie_fact`
   the runtime cannot verify the fact offline (it is a negative claim); the
   verifier still re-derives it on replay.
4. **MCP server environment.** A spawned MCP server inherits the operator's
   environment minus `LIBELLA_*`; a third-party server can read other operator
   secrets present in the process env.
5. **Memory is global and target-keyed.** Any engagement can read facts recorded
   by another for the same origin, and asset keys discovered from target content
   are written into memory — a hostile target can pollute its own origin's prior
   state. Drift output is advisory; findings still require replay.
6. **Redaction is heuristic.** A bare cookie/session value with no label and no
   JWT shape is not detectable in free text.
7. **Tech-module FP control is differential, not semantic.** A target that answers
   differently for the tilde form for unrelated reasons (custom 404 pages) can
   still produce the low-confidence row; it now requires an observable difference.
8. **Plugin code is trusted.** Plugins execute arbitrary Python in a separate
   process; the manifest cannot pick argv or a shell, but a plugin can do
   anything the operator's user can. Directory ownership is the boundary.
9. **`cloud_audit` account-only scope on a public endpoint** is now refused
   pre-dial (D4): an authorised *real* account must be declared together with its
   endpoint (or `account_id` plus a declared endpoint). This is a tightening of
   previously permitted behaviour, documented here.

## Verification

```
.venv/bin/python -m pytest tests/ -q      -> 448 passed, 1 skipped
.venv/bin/python -m ruff check src tests  -> All checks passed
```

Baseline before this audit: 417 passed, 1 skipped, ruff had 2 pre-existing
`tests/test_integration_e2e.py` findings (fixed). New tests: 31 in
`tests/audit2/` (8 files), each mapped to the defect it locks down.