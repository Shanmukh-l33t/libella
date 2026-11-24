# ASVS 5.0.0 Level 2 coverage backlog

Baseline classification, not a target assessment. The local evidence-review candidate adds a sample-level check for V14.3.2 (set C); this is not a new PairLab coverage result.
Basis: `libella-readiness` @ `852398c` (pinned catalog `asvs-5.0.0.json`, upstream SHA
`82fb2f41cdb623e0b11e4d9a6b97c4306c1d119c`; mapping `mapping-asvs-5.0.0.json`).

**Scope of this file.** The sets below are a *project backlog* classification of the
catalog (what Libella can or cannot evidence). They are not a statement that a given
target needs, passes or fails any requirement: target applicability is decided per
engagement by `coverage.py` (scope categories `web`/`api`, selected level) and by the
operator for feature-gated items.

## Counts (L2 = levels 1 and 2, cumulative)

- Catalog 345 requirements; L2 = **253** (70 level 1 + 183 level 2).
- **Mapped/supported: 39.** A requirement is mapped when `mapping-asvs-5.0.0.json` ties a unit to it
  (23 with at least one `direct` unit, 16 `partial`-only). Mapped means "a check can speak to it", not "a run did".
- **Genuinely executed: 26** is the only recorded figure (`CAPABILITY_MATRIX.md`: "26/253 ASVS L2 executed on PairLab,
  227 honestly untested"). It is produced by `benchmarks/acceptance_standards.py`, which counts a requirement executed only
  with this engagement's evidence pointers.
- **The 26 exact IDs are not recoverable from existing artifacts.** The script writes `standards_asvs.json` to a
  caller-supplied output dir; no copy exists in the repo or sibling `libella-*` trees, `benchmark_runs/results.json`
  has no standards data, and every `report.json` found (11) has no ASVS section. Regenerating means running the
  acceptance (scanners), which was out of scope. Only derivable fact: 26 of the 39 mapped; the other 13 mapped IDs
  were not executed on PairLab, which 13 is unknown.
- `mapping.not_supported` is empty: no ID is declared unsupported in the catalog data. Set E below is a backlog judgement.

## Classification of all 253 L2 IDs

Exact IDs, compacted (`V3.4.1-6` = V3.4.1 through V3.4.6). Each ID is in exactly one set.
Precedence: A, E, D, B, C, F, G (first match wins).

| Set | Category | N | IDs | Prerequisites |
|---|---|---|---|---|
| A | Existing mapped (supported by a unit at this SHA) | 39 | V1.1.2, V1.2.1, V1.2.4-5, V1.3.2, V1.3.6-7, V1.5.2, V3.3.1-2, V3.3.4, V3.4.1-6, V3.5.1-2, V3.7.2, V4.3.1-2, V5.2.2, V5.3.1-2, V8.2.1-2, V8.4.1, V12.1.1-2, V12.2.2, V13.3.1, V13.4.1-3, V13.4.5, V15.2.1, V15.3.1, V15.3.3 | HTTP/TLS reach inside authorised scope; see unit table. Presence in this set means mapped, not executed. |
| B | New: defensively automatable from observed evidence | 12 | V3.3.3, V3.7.1, V4.1.1-2, V6.2.6-7, V6.4.2, V12.2.1, V13.4.4, V14.2.1, V14.2.3, V16.5.1 | Passive observation of exchanges the engagement already recorded (crawl, headers, TLS, login/reset form markup, error bodies actually seen). No new mapping row exists; needs a unit + `mapping-asvs-5.0.0.json` rows. V16.5.1 only from errors already observed (none induced). |
| C | Requires authenticated assessment | 16 | V6.2.2-3, V7.2.2-4, V7.3.1-2, V7.4.1, V7.4.3-4, V7.5.1-2, V8.2.3, V14.3.1-3 | Operator-supplied credentials (one account; two roles for V8.2.3) and a stated session/timeout policy. Observation of own-account responses only. |
| D | Conditionally inapplicable (feature-gated) | 71 | V1.2.6-8, V1.3.4-5, V1.3.8-11, V1.4.1-3, V3.5.5, V4.4.1-4, V5.2.3, V6.5.1-5, V6.6.1-3, V6.8.1-4, V7.1.3, V7.6.1-2, V9.1.1-3, V9.2.1-4, V10.1.1-2, V10.2.1-2, V10.3.1-4, V10.4.1-11, V10.5.1-5, V10.6.1-2, V10.7.1-3, V12.1.3, V15.3.6 | Operator confirms the feature exists (OAuth/OIDC, self-contained tokens, MFA/OOB, SAML/IdP, WebSocket, federation, mTLS, legacy-language or niche sinks). If absent, record not applicable for the engagement; if present, evidence method is source/config or manual. |
| E | Currently unsupported | 7 | V17.1.1, V17.2.1-4, V17.3.1-2 | No capability at this SHA (no media-plane/WebRTC signalling). Also feature-gated: inapplicable when the target carries no real-time media. |
| F | Source / config review | 61 | V1.2.2-3, V1.3.1, V1.3.3, V1.5.1, V3.2.1-2, V3.5.4, V4.1.3, V4.2.1, V5.2.1, V5.4.2-3, V7.2.1, V8.3.1, V11.1.1-2, V11.2.1-3, V11.3.1-3, V11.4.1-4, V11.5.1, V11.6.1, V12.3.1-4, V13.2.1-5, V13.3.2, V14.2.2, V14.2.4, V15.2.2-3, V15.3.2, V15.3.4-5, V15.3.7, V16.2.1-5, V16.3.1-4, V16.4.1-3, V16.5.2-3 | Read access to repo, build/dependency manifests, deployment/proxy/logging configuration or key-management documentation supplied by the operator. |
| G | Manual (documentation, process, judgement) | 47 | V1.1.1, V1.2.9, V2.1.1-3, V2.2.1-3, V2.3.1-4, V2.4.1, V3.5.3, V5.1.1, V5.4.1, V6.1.1-3, V6.2.1, V6.2.4-5, V6.2.8-12, V6.3.1-4, V6.4.1, V6.4.3-4, V7.1.1-2, V7.4.2, V7.4.5, V8.1.1-2, V13.1.1, V14.1.1-2, V15.1.1-3, V16.1.1 | Operator-supplied documentation, design/process evidence and reviewer judgement. Existing `manual` reasons in the mapping (per chapter) apply; V6.3.2 is an explicit manual override (V13.4.6 is level 3, outside L2). |
| | **Total** | **253** | | |

New-work sets (B, C) are defensive observation of the target's own responses and are the only sets where
new units would be added; D, F, G need operator input or access, and E needs a capability that does not exist.
The existing audit modules for JWT, OAuth and session lifecycle are not mapped to ASVS rows at this SHA
(they appear in no `mapping` row), so V7/V9/V10 show no mapped evidence; deciding on that mapping is outside this backlog.

## Set A by unit (mapped, existing)

| Units | IDs | Prerequisite |
|---|---|---|
| Response headers, cookies, CORS, redirects, exposed paths (`security_headers`, `cookie_flags`, `cors`, `open_redirect`, `sensitive_paths`, `zap_baseline`, `ffuf`, `nuclei`) | V3.3.1-2, V3.3.4, V3.4.1-6, V3.5.1-2, V3.7.2, V13.4.1-3, V13.4.5 | HTTP reach in scope |
| Input-handling probes (`reflected_xss`, `sqli`, `sqli_union`, `ssti`, `path_traversal`, `auth_bypass`, `file_upload`, `ssrf`) | V1.1.2, V1.2.1, V1.2.4, V1.3.2, V1.3.6-7, V5.2.2, V5.3.1-2 | Crawl inventory; profile that permits active checks; existing only, not extended here |
| Credentialed API/role checks (`idor`, `privesc_audit`, `authz`, `api_audit`; `sensitive_paths` for V15.3.1 on the user-collection paths only) | V8.2.1-2, V8.4.1, V15.3.1, V15.3.3 | Supplied credentials/roles; API category in scope |
| GraphQL (`graphql_audit`) | V4.3.1-2 | GraphQL endpoint present |
| TLS/infra (`tls_audit`, `infra_scan`, `infra`) | V12.1.1-2, V12.2.2 | TLS port reachable |
| Source/image (`code_audit`, `container_scan`) | V1.2.5, V1.3.2, V1.5.2, V13.3.1, V13.4.2, V15.2.1 | Repo or image supplied |

## Attribution changes (standards branch)

No ID joined or left the mapped set of 39; these changes make an already-mapped requirement read
what the engine did. Method, not a compliance statement: a requirement moves only through
finding -> exchange tool -> unit -> requirement (plus a control id where one check asserts
several), and a partial check that ran reports `partial_evidence`, never a pass.

- Sub-exchanges now resolve to their unit: `idor_check_anon`, `object_enum`, `object_enum_anon` (idor),
  `sqli_bool_true/false/true_repeat` (sqli), `ssrf_discovery` (ssrf), `role_login/role_matrix/role_matrix_anon/authz_oracle`
  (privesc_audit). Before, a finding bound to one of these had no recoverable producer and the requirement
  read `completed_no_issue` next to an observed finding.
- `sensitive_paths` findings carry an `exposure.*` control id per path (`controls.EXPOSURE_CONTROLS`). V13.4.1 now needs
  `vcs_metadata`, V13.4.2 `debug_endpoint`, V13.4.3 `directory_listing` (CWE-548), V13.4.5 `monitoring_endpoint`, V15.3.1
  `excess_fields`. A debug page no longer fails V13.4.1; a `.env` hit attributes to none of them. Findings stored before
  this change have no control id and read as unattributed until an analyst links them.
- `privesc_audit` maps V8.2.1 and V8.2.2 as `partial` (GET only, rule-dependent); a blocked sweep stays `inconclusive`.
- Strength is judged over the units that ran, not every mapped unit. V12.1.2 is `indirect` for the TLS units (they record the
  negotiated cipher, not the enabled suites).
- Still unattributed: `.env` exposure; API2 for the CWE-306 findings of `idor` and `privesc_audit` (they test authentication only
  on a hit, so mapping the unit would claim a run that did not test it); and every JWT/OAuth/session/injection/protocol audit
  (backlog sets C and D).

## Status vocabulary reminder

`not_applicable` (scope has no web/api category) and `requires_manual` (no mapped unit) are
engagement-time outcomes from `coverage.py`; `completed_no_issue` is impossible for a `partial` unit
(reported as `partial_evidence`). A set above never upgrades a requirement to covered.
