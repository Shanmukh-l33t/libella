# Reference workflow record

This record covers setup, provider configuration, readiness, redaction, status and reporting in six public projects. Each finding was traced through source code at a pinned commit. Runtime evidence is limited to inert commands: help output, version output, local configuration commands and the projects' own unit tests. No reference tool ran an assessment, scanner or agent against any target. Assessment workflows, agent planning and tool execution were intentionally excluded, so this record makes no parity claim for them.

Result values: **Verified** means implemented in Libella and exercised by an automated test or browser run. **Design input** means the finding informed a decision but Libella has no implementation. **Not studied** means the workflow was excluded.

## Pinned revisions

| Project | Commit | License |
|---|---|---|
| PentAGI (vxcontrol/pentagi) | `cffed9485aa1cca70762cd08a57ac62a80406258` | see repo |
| ARTEX (BaaRai/ARTEX) | `ab40834567475c449bb34f84a9aa50a6587cb471` | see repo |
| Strix (usestrix/strix) | `a1ccf777d80e812edf23fc8b82bdc17def6143ac` (v1.7.1) | Apache-2.0 |
| Shannon (KeygraphHQ/shannon) | `f22a9cb0958d04b9582652aa7848a9d7b12869c6` | AGPL-3.0-only |
| HexStrike AI (0x4m4/hexstrike-ai) | `d689933ff579d839c676c82b231f8e98326c5f04` | see repo |
| Pentest Swarm AI (Armur-Ai/Pentest-Swarm-AI) | `c077a76499589845b9d0b67ab7c20e99e0dd295f` | see repo |

No reference code was copied into Libella. Shannon is AGPL; Libella only records its behavior.

## Provider configuration and connection testing

| Reference | Observed implementation | Weakness observed | Libella design and code | Result |
|---|---|---|---|---|
| PentAGI | Provider readiness comes from configuration, not a request (`schema.resolvers.go:2225-2260`; UI gate `settings-providers.tsx:62-66`). Keys are environment-only, so `ProviderConfig` has no credential field. A separate provider test makes a live call (`testProvider`) with no deadline (`graphql-deadline.ts:8`). | "Enabled" does not mean "reachable". The live test is unbounded. | One bounded Chat Completions request (10 s, 64 KB, no redirects, `trust_env=False`) that never saves the draft. It returns one of 17 plain-language statuses with latency. `src/libella/provider_diagnostic.py`, `POST /api/settings/provider-test`. | Verified (`tests/test_provider_diagnostic.py`, `benchmarks/check_provider_ui.py`) |
| ARTEX | Masked secret hints keep the last 6 characters (`notify/mask.go`). `PrepareConfigUpdate` returns `ErrDestinationChangedWithoutCredentials` when a destination changes but the credential is still masked. Secrets are sealed at rest, and the list query never selects `api_key` (`db/config.go:180-190`). | None in the traced paths. Its unit tests pass. | A saved key is never sent to a different base URL. Saving a new endpoint without a new key drops the old key. `GET /api/settings` returns only `[SET]`. | Verified |
| Strix | Configuration lives in `~/.strix/cli-config.json` with mode 0600, and environment variables take precedence (`strix/config/loader.py:37-91`). | Telemetry is on by default. | No change: Libella stores provider settings encrypted in SQLite (existing `SecretBox`). | Design input |
| Shannon | The setup writer uses mode 0600 (`config/writer.ts:23-30`). The resolver refuses group-readable secret files (`config/resolver.ts:98-105`). Only one provider is allowed (`env.ts:213-235`). | The CLI refuses to run as root before printing help. | Not adopted. | Design input |
| Pentest Swarm AI | `config show` redacts `server.api_key`. `config validate` is a stub: it hardcodes `config.yaml` and reports "Config is valid" for an unknown provider (`cli/config.go:438-450`). | False validation. | Libella's check makes a real request and never reports success without a text completion. | Verified (negative cases in tests) |
| HexStrike AI | `/health` runs 127 `which` probes plus a one-second CPU sample. | Unsuitable as a liveness probe. Its "127.0.0.1" log line is false because the server binds `0.0.0.0` (`hexstrike_server.py:17289`), and there is no authentication. | Libella keeps `/api/health` free of probes and inventory (existing), and provider checks require authentication. | Verified (existing `tests/audit/test_api_security.py`) |

## Readiness and status

| Reference | Observed | Libella | Result |
|---|---|---|---|
| ARTEX | `server/ready.go:66-80`: single-flight database ping cached for 1 s that returns only `{"ready":bool}`. Version is shown only to signed-in sessions. | Pattern noted. Libella's public health route already discloses only status and version. | Design input |
| Pentest Swarm AI | `doctor` exits 0 with 3 of 8 checks failing. `checkDisk` always passes (`:184`). | A readiness check must fail when its prerequisite fails. Libella's tool readiness page still reports binary presence only; a real diagnostic run per tool is outstanding. | Outstanding |
| Shannon | `status --json` returns typed error codes (`CLI_SCAN_IDENTITY_NOT_FOUND` exits 1, `CLI_USAGE` exits 2). | Not adopted yet. | Design input |

## Reporting and CI output

| Reference | Observed | Libella | Result |
|---|---|---|---|
| Strix | Writes report, CSV and per-finding Markdown with a CSV formula guard (`report/writer.py:139-181`). Atomic SARIF output (`report/sarif.py:305-364`). `--fail-on` exits 2 for CI. | Libella already exports SARIF and DefectDojo JSON and has an offline CI gate (`gate.py`). Report rendering is not yet atomic (audit M8). | Partially verified |
| Shannon | Writes SARIF only for exploit runs. Derives the PDF and deletes a stale PDF, then renames it into place atomically (`report-finalization.ts:392-481`, `pdf-renderer.ts:147-198`). | Atomic rendering is outstanding. | Outstanding |
| PentAGI | `lib/report/report.ts:91-186` plus the `flow-report.tsx` view. | Not compared at UI level. | Not studied in depth |

## Coverage methodology

None of the six projects has a methodology coverage matrix with honest gaps, and none was found in the traced code. Libella adds a manual-review workspace for the 96 OWASP WSTG 4.2 test IDs (`src/libella/coverage.py`, `web/src/pages/Coverage.tsx`). Every test starts as `unknown`. `covered` requires evidence from the same engagement, and `manual` or `unsupported` requires a written note. Findings are not mapped to WSTG IDs automatically. Verified in `tests/test_wstg_coverage.py`.

## Excluded

Assessment execution, agent planning and delegation, tool invocation, browser crawling and traffic capture were not traced or reproduced in any reference project. Reference UIs were not rendered, so no layout or click-count comparisons are made.
