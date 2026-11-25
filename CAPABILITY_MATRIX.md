# Capability Matrix and Engineering Backlog (development instrument)

Compares Libella with six reference platforms on evidence and execution guarantees,
then lists Libella's own capability status and backlog.

**This document makes no claim that Libella is better than any reference platform.**
No reference platform was run on PairLab or on any shared benchmark, so there is no
comparative test. Every competitor cell below says only what was found, and how.

Reference checkouts inspected (read from source on disk, nothing executed for this
document; `docs/research/reference-trace-2026-11.md` traces mechanisms at older commits
for some of them, so cite paths, not line numbers, across the two):

| Product | Short | Checkout | Licence |
|-|-|-|-|
| PentAGI | P | `cffed94` | MIT with EULA |
| Strix | S | `a1ccf77` | Apache-2.0 |
| ARTEX (BaaRai fork) | A | `0255f6a` | AGPL-3.0 |
| HexStrike AI | H | `d689933` | MIT |
| Pentest Swarm AI | W | `c077a76` | AGPL-3.0 |
| Shannon | Sh | `2b40630` | AGPL-3.0 |

## Evidence basis tags

Competitor cells carry exactly one of:

* **SRC** source-inspected: the cell names a path in the product's repository at the
  checkout above. A file existing proves the mechanism is present, not that it works
  or is any good. Nothing from a reference repo was executed for this matrix.
* **DOC** documented-only: taken from the product's README or docs and not confirmed
  in source.
* **UNV** unverified: nothing was found, or the point was inferred. A search that finds
  no match is not proof of absence, so an "none found" cell is always UNV.

Libella cells carry exactly one of:

* **EX** exercised-here: a named test or benchmark in this repository exercised it. The
  head it ran on is stated when it is not `973fa33`.
* **SRC-ONLY** the code exists, but no test or benchmark exercised this claim.

Test counts: full suite 1055 passed, 1 skipped (ZAP not installed) at `973fa33`.
For this document the four files `tests/verify`, `tests/test_check_preconditions.py`,
`tests/test_exec_controls.py` and `tests/test_resume_plan.py` were re-run on this
worktree: 84 passed.

## Comparison 1: long-running operator control

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | Per-flow actions stop, finish, input, rename, report; an ask-the-user tool; flows reloaded from the database at startup. No pause action in that action list. | SRC | `backend/pkg/server/models/flows.go`, `backend/pkg/tools/registry.go`, `backend/pkg/controller/flows.go` |
| Strix | Resume a prior run by name; a wait-for-user tool; a `budget_paused` agent status. Pause from the viewer not found. | SRC | `strix/interface/cli_args.py`, `strix/tools/wait_for_user/tool.py`, `strix/interface/tui/runtime.py` |
| ARTEX | Task pause control, rerun of a blocked or stopped intent, chat stop, operator question flow, approval of intercepted actions. | SRC | `server/task_control.go`, `server/server.go`, `server/ask_operator.go`, `server/intercept.go` |
| HexStrike | Pause, resume and terminate on a single OS process id. No run or engagement model found. | SRC | `hexstrike_server.py` (routes under `/api/processes/`) |
| Pentest Swarm AI | Authorize and confirm gates before active phases, a stop endpoint on the dashboard, scheduler resumes from the last committed cursor. | SRC | `cli/authorize.go`, `cli/confirm.go`, `internal/dashboard/dashboard.go`, `internal/swarm/scheduler.go` |
| Shannon | CLI stop, status and logs commands, confirmation prompts, a pending-workflow resume path. | SRC | `apps/cli/src/commands/stop.ts`, `apps/cli/src/commands/status.ts`, `apps/cli/src/pending-workflow.ts`, `apps/cli/src/confirm.ts` |
| Libella | Pause, cancel and resume; cancel propagates to intents and subprocesses; time window checked at start, resume and between intents. In-flight requests are not preempted at the deadline. | EX | `tests/test_exec_controls.py`, `tests/test_resume_plan.py`. Browser journey E (`benchmarks/check_execution_controls_ui.py`) ran on the earlier `defensive-readiness` head, not rerun at `973fa33`. |

## Comparison 2: authenticated browser sessions

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | A browser tool that calls a scraper service for fetch and screenshot. No session or credential handling found in it. | UNV | `backend/pkg/tools/browser.go` |
| Strix | The agent drives a sandbox browser CLI; a skill documents saving cookies and local storage after a login. Prompt-level, not a runtime-managed session object. | SRC | `strix/skills/tooling/agent_browser.md`, `strix/tools/agent_browser/README.md` |
| ARTEX | Per-task credentials, a browser MCP server record, and a playwright skill with a storage-state reference. | SRC | `server/task_credentials.go`, `agent/tools_creds.go`, `db/browser_mcp.go`, `skills/playwright-cli/references/storage-state.md` |
| HexStrike | Selenium is imported; no login-session handling was traced. | UNV | `hexstrike_server.py` |
| Pentest Swarm AI | Headless Chromium that captures the page's API calls and accepts session auth headers so single-page apps render as a logged-in user. | SRC | `internal/browser/browser.go`, `internal/session/session.go` |
| Shannon | A credential-validator prompt drives a live browser to confirm the login before testing; shared login instructions; a Playwright config writer. | SRC | `apps/worker/prompts/validate-authentication.txt`, `apps/worker/prompts/shared/login-instructions.txt`, `apps/worker/src/ai/playwright-config-writer.ts` |
| Libella | Authenticated browser crawl, multi-role checks, target credentials sealed at rest and never followed across redirects. | EX | `tests/authbrowser/test_auth_browser.py`, `tests/authbrowser/test_authlab.py`, `tests/test_target_auth.py`. Journey D (`benchmarks/check_target_credentials_ui.py`) ran on the earlier `defensive-readiness` head. |

## Comparison 3: live agent visualization

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | GraphQL subscriptions feed a web UI that shows flows, tasks and subtasks. What the UI renders in detail was not source-checked. | SRC (subscriptions), DOC (UI) | `backend/pkg/server/router.go`, `backend/pkg/graph/subscriptions` |
| Strix | A terminal live view, a token-gated local web viewer, and an agent-graph tool the model can call. | SRC | `strix/interface/tui/live_view.py`, `strix/interface/viewer/server.py`, `strix/tools/agents_graph/tools.py` |
| ARTEX | An activity stream endpoint and a live traffic stream behind a web UI. | SRC | `server/server.go` (`/api/exploration/activity/stream`), `traffic/stream.go` |
| HexStrike | A process dashboard endpoint and a console-styling class. Process level, not agent level. | SRC | `hexstrike_server.py` (`/api/processes/dashboard`) |
| Pentest Swarm AI | A dashboard with an events stream, and a separate Next.js web app. | SRC | `internal/dashboard/dashboard.go`, `web/` |
| Shannon | Terminal log tailing in the CLI. The README describes a live terminal experience; Temporal's own UI is brought up by the compose file. | SRC (logs), DOC (README) | `apps/cli/src/commands/logs.ts`, `docker-compose.yml` |
| Libella | Live Operations page over server-sent events. Refresh and reconnect acceptance has not been run. | EX (stream), SRC-ONLY (reconnect) | `benchmarks/acceptance_beginner.py` (SSE p50 0.34 s) on the earlier `defensive-readiness` head, `tests/test_ui_serving.py` |

## Comparison 4: shared investigation graphs

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | An optional Graphiti knowledge-graph client and search tool, plus vector memory. | SRC | `backend/pkg/graphiti/client.go`, `backend/pkg/tools/graphiti_search.go`, `docker-compose-graphiti.yml` |
| Strix | An agent hierarchy graph and shared notes. A cross-agent finding graph was not found. | SRC (agent graph), UNV (finding graph) | `strix/tools/agents_graph/tools.py` |
| ARTEX | A per-task exploration graph and a cross-task asset graph. | SRC | `server/server.go` (`/api/exploration/graph`), `agent/coldgraph.go`, `agent/fact_assets.go` |
| HexStrike | An in-memory vulnerability correlator for attack chains. No persisted graph found. | SRC (correlator), UNV (persistence) | `hexstrike_server.py` (class `VulnerabilityCorrelator`) |
| Pentest Swarm AI | A typed attack graph with path analysis toward a declared objective, and a blackboard shared by agents. | SRC | `internal/attackgraph/graph.go`, `internal/attackgraph/pathanalysis.go`, `internal/swarm/blackboard` |
| Shannon | No graph found; per-stage deliverables go through an artifact store. | UNV | `apps/worker/src/ai/reconciliation/artifact-store.ts` |
| Libella | Investigation graph with finding lineage, plus cross-run memory and drift detection. | EX | `tests/test_graph_memory.py` |

## Comparison 5: searchable traces

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | Separate stored logs for tool calls, terminal, messages, searches and vector store, queryable over GraphQL; optional Langfuse compose file. Full-text search across traces was not found. | SRC (logs), UNV (search) | `backend/pkg/controller/tclogs.go`, `backend/pkg/controller/termlogs.go`, `backend/pkg/graph/schema.graphqls`, `docker-compose-langfuse.yml` |
| Strix | A transcript view of a run. Search over it was not found. | SRC (transcript), UNV (search) | `strix/interface/viewer/transcript.py` |
| ARTEX | Traffic search and fetch tools for agents, traffic filters, and recording of LLM calls. | SRC | `traffic/traffic.go`, `llmrec/llmrec.go`, `docs/vulnerability-traffic-evidence.md` |
| HexStrike | No persistent run or trace store found. | UNV | `hexstrike_server.py` |
| Pentest Swarm AI | Tracing and audit packages exist; whether they are searchable was not examined. | UNV | `internal/swarm/tracing.go`, `internal/audit/audit.go` |
| Shannon | An audit trace and log stream per session; Temporal keeps workflow history. Search not examined. | SRC (trace), UNV (search) | `apps/worker/src/audit/trace.ts`, `apps/worker/src/audit/log-stream.ts` |
| Libella | Traffic search, replay and correlation; an `investigation_steps` timeline per agent run. | EX | `tests/traffic/test_traffic.py`, `tests/test_agent_runtime.py` |

## Comparison 6: broad tool integration

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | Agent roles with terminal, file, browser and several search-engine tools; the README describes a broad security toolset inside per-flow containers. | SRC (tool names), DOC (container toolset) | `backend/pkg/tools/registry.go`, `README.md` |
| Strix | An MCP client with meta-tools, a Caido proxy integration, a shell tool, and a sandbox image that bundles tools. | SRC | `strix/tools/mcp/`, `strix/tools/proxy/`, `containers/` |
| ARTEX | An MCP client, uploadable skills, custom tools, and an image build that fetches nuclei, httpx, sqlmap and others. | SRC | `mcphttp/client.go`, `server/customtool.go`, `Dockerfile` |
| HexStrike | 151 MCP tool registrations in the bridge, over a Flask API in one server file. Counted here; whether each tool works was not tested. | SRC | `hexstrike_mcp.py`, `hexstrike_server.py` |
| Pentest Swarm AI | A tool coordinator, a Semgrep wrapper, a Metasploit client, an MCP server and a plugin executor. | SRC | `internal/tools/coordinator.go`, `internal/integrations/metasploit/client.go`, `internal/mcp/server.go`, `internal/plugins/executor.go` |
| Shannon | Browser automation and command line tools plus a SAST pipeline. Catalogue breadth was not counted. | DOC (README), SRC (SAST) | `README.md`, `apps/worker/src/ai/sast/` |
| Libella | Typed argv adapters (nmap, nuclei, httpx, subfinder, ffuf, trivy, ZAP) plus a plugin and MCP client framework. This is a much smaller catalogue than HexStrike's 151 registrations. The ZAP live test is skipped (ZAP not installed), so ZAP is SRC-ONLY. | EX (ffuf, container, readiness), SRC-ONLY (ZAP) | `tests/test_ffuf_parser.py`, `tests/test_container_scan.py`, `tests/test_tool_readiness.py`, `src/libella/tools/zap_adapter.py` |

## Comparison 7: durable recovery

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | Postgres-backed flows reloaded at startup. | SRC | `backend/pkg/controller/flows.go` |
| Strix | Resume a run by name from the host run directory, with a resume picker. | SRC | `strix/interface/cli_args.py`, `strix/interface/resume_picker.py` |
| ARTEX | Postgres state, a work-claim heartbeat, and abort when a claim is lost. | SRC | `server/engine.go`, `server/claim_heartbeat_test.go` |
| HexStrike | In-memory cache and process table. No run store found. | UNV | `hexstrike_server.py` (class `HexStrikeCache`) |
| Pentest Swarm AI | The scheduler resumes from the last committed cursor; memory is persisted. | SRC | `internal/swarm/scheduler.go`, `internal/memory/persist.go` |
| Shannon | Temporal workflows with a retry policy and resume from a workspace. Needs a Temporal server, not run here. | SRC | `apps/worker/src/temporal/workflows.ts`, `apps/cli/src/pending-workflow.ts` |
| Libella | SQLite leased intents with fencing tokens, bounded retries, resume plan, persisted intent results. Real-model recovery was verified on the baseline only, not on later commits. | EX | `tests/test_resume_plan.py`, `tests/test_intent_result_persistence.py`, `tests/audit/`; `benchmarks/acceptance_recovery.py` on the baseline only |

## Comparison 8: source-informed assessment

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | A coder agent role exists. A source-aware assessment pipeline was not found. | UNV | `backend/pkg/tools/registry.go` |
| Strix | White-box mode with local sources, a diff scope against a base ref, and source-aware skills. | SRC | `strix/interface/cli_args.py`, `strix/skills/coordination/source_aware_whitebox.md`, `strix/skills/custom/source_aware_sast.md` |
| ARTEX | Not found. | UNV | none |
| HexStrike | Not found. | UNV | none |
| Pentest Swarm AI | A Semgrep wrapper. How its output feeds the dynamic phases was not examined. | SRC (wrapper), UNV (use) | `internal/tools/semgrep.go` |
| Shannon | Code analysis first, a SAST stage, and reconciliation of SAST with exploit results. | SRC | `apps/worker/prompts/pre-recon-code.txt`, `apps/worker/src/ai/sast/`, `apps/worker/src/ai/reconciliation/` |
| Libella | A code and dependency audit module with OSV lookups. Its findings cannot be replayed, so they stay observations, and they do not steer dynamic testing. | EX | `tests/code/test_codeaudit.py`; `benchmarks/run_codeaudit.py` (6/6 seeded issues, 0 FP on the clean repo) on earlier heads |

## Comparison 9: independent verification

Competitors do verify. The differences are in what kind of check each uses.

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | An LLM advice tool and an LLM reflector prompt. No non-LLM verifier was found. | SRC | `backend/pkg/tools/registry.go`, `backend/pkg/templates/prompts/reflector.tmpl` |
| Strix | Exchange ids cited by a finding are checked to exist in the proxy project. Counter-evidence and fix-verification are prompt-level skills. No re-execution seen. | SRC | `strix/tools/reporting/tool.py`, `strix/skills/analysis/counterevidence.md`, `strix/skills/analysis/fix_verification.md` |
| ARTEX | A dedicated retest agent bound to one finding: it re-runs a minimal PoC against the recorded evidence, records the requests it actually made, and saves one verdict (reproduced, fixed or inconclusive) through a typed tool. The retest is performed by an LLM agent, not a deterministic replayer. A separate receipt check requires every quote to appear verbatim in a bound response body. | SRC | `agent/retester.go`, `server/finding_retests.go`, `server/finding_verification.go` |
| HexStrike | No verification step found. Workflow step names containing "verify" are prompt text. | UNV | `hexstrike_server.py` |
| Pentest Swarm AI | Non-LLM oracles (out-of-band callback, differential against a baseline, timing threshold) behind the verify flag, consulted for high-stakes findings under a per-campaign cap; falls back to a model verifier, then a passive gate. Unit tests exist; not run here. | SRC | `internal/swarm/verify/oracle.go`, `internal/swarm/verify/oracle/oob.go`, `internal/swarm/verify/oracle/differential.go`, `internal/swarm/verify/oracle/timing.go`, `cli/scan.go` |
| Shannon | The README says no report without a working exploit. Source shows a reconciliation of SAST output with exploit results and a confirm stage in the SAST pipeline. | SRC (reconciliation, confirm stage), DOC (exploit rule) | `apps/worker/src/ai/reconciliation/`, `apps/worker/src/ai/sast/capella/stages/verdicts.ts`, `README.md` |
| Libella | Typed proof contracts per finding class plus class differentials against a negative control; a reproduced quote alone no longer validates. A 29-test adversarial gate with positive twins; 13 mutation checks all killed (run by hand, the harness is not committed). | EX | `src/libella/proof.py`, `src/libella/verifier.py`, `tests/verify/test_verifier_accuracy.py`, `tests/test_check_preconditions.py` |

Libella limits that apply here: out-of-band and smuggling proofs replay as
inconclusive by design, and Libella has no timing oracle. The PairLab gate on the new
verifier is pending (see the benchmark section). No test compares Libella's
verifier with any competitor's on the same findings, so no ranking is stated.

## Comparison 10: usable professional workflows

| Product | What was found | Basis | Where |
|-|-|-|-|
| PentAGI | Web UI with templates, API tokens, per-user settings, REST and GraphQL APIs, report view, usage analytics. | SRC | `backend/pkg/server/`, `frontend/src/lib/report/report.ts` |
| Strix | Headless mode, SARIF output, a fail-on severity option for CI, PDF report export. | SRC | `strix/interface/cli_args.py`, `strix/interface/viewer/report_pdf.py` |
| ARTEX | Company and scope records, task templates, notifications, report and findings export, retest rounds. | SRC | `server/task_templates.go`, `server/notifier.go`, `report/report.go` |
| HexStrike | No report or findings store found. | UNV | `hexstrike_server.py` |
| Pentest Swarm AI | Campaign commands, bug-bounty scope importers, compliance mapping, a report command. | SRC | `cli/campaign.go`, `internal/scope/importer/`, `internal/compliance/compliance.go`, `cli/report.go` |
| Shannon | Per-scan reports, SARIF from the SAST stage, sample reports; the README documents a GitHub Action and hosted findings management. | SRC (reports, SARIF), DOC (Action, hosted) | `apps/worker/src/ai/sast/capella/sarif-exporter.ts`, `sample-reports/`, `README.md` |
| Libella | Reports in Markdown, JSON, SARIF, PDF, HTML, DOCX, XLSX, CSV and GitLab DAST JSON; remediation tracking; historical comparison. Not built: CI and issue-tracker hooks, scheduled retest, organizations, RBAC, SSO, distributed workers. | EX | `tests/report/`, `benchmarks/check_report_exports.py` and `benchmarks/acceptance_beginner.py` on the earlier `defensive-readiness` head |

## Libella measured results

All numbers below are Libella against its own PairLab ground truth. No reference
platform was run on PairLab.

### Four-way PairLab benchmark at `b656a67` (16 seeded classes, 6 negative controls)

| Mode | Twin | Detected | Confirmed | FP | Time | Cost |
|-|-|-|-|-|-|-|
| A native, declared hints | vuln | 16/16 | 16 | 0 | ~14.7s | $0 |
| A native, declared hints | hardened | 0 | 0 | 0 | ~14.4s | $0 |
| A native, no hints | vuln | 13/16 | 13 | 0 | ~14.3s | $0 |
| A native, no hints | hardened | 0 | 0 | 0 | ~15.1s | $0 |
| B agents, no hints | vuln | 13/16 genuine | 16 | 3 | ~286s | ~$0.27 |
| C nuclei only | vuln | 0/16 | 0 | 0 | 600s cap | $0 |
| D full | vuln | 16/16 | 16 | 0 | ~615s | $0 |
| D full | hardened | 0 | 0 | 0 | ~615s | $0 |

* Mode A without hints missed three seeds: SQLi in the `category` filter, IDOR on
  orders, and SSRF.
* Mode B found the same 13 seeds as native, so zero unique true positives over native.
  Its three extra confirmed findings were incorrect: an SSRF proven with an empty
  marker, an unauthenticated IDOR on a public profile, and duplicate root-document
  header findings. These were fixed at `b656a67` with precondition guards.
* Mode C: nuclei sent 15,116 of 16,005 planned requests before the 600s cap and
  matched nothing on this target.
* Mode B was run only on the vulnerable twin, with one seed and one model. It has
  **not** been rerun on the hardened twin or on the new verifier, so the agent
  false-positive rate on the hardened twin and with the new verifier is unknown.
* The hardened twin results for A and D are 0 false positives.

### Nuclei focused profile at `b656a67`

Template inventory is 12,064 with no tags and the http protocol filter, against 4,513
with the focused tags. Focused mode C completed in 403.6s without timing out. Request
counters were not captured in that run, so a request-count comparison with the 15,116
figure above is not available.

### Verification architecture at `973fa33`

* Typed proof contracts per finding class (`src/libella/proof.py`) and class
  differentials against a negative control (`src/libella/verifier.py`). A reproduced
  quote alone no longer validates a finding.
* Adversarial gate: 29 tests in `tests/verify/test_verifier_accuracy.py`, each negative
  case paired with a positive twin. 13 mutation checks, all killed. Full suite 1055
  passed, 1 skipped.
* PairLab gate on the new verifier, measured: vulnerable twin 16/16 seeds validated,
  hardened twin 0 confirmed and 0 false positives, evidence chain intact on both.
* Generic parameter and object discovery closes the three native misses on a HOLDOUT app
  (different endpoint names, parameter names, login fields, JSON envelopes), with no
  operator hints: SQLi, SSRF, IDOR and the session-cookie seed all validated, 0 findings
  on the hardened twin. `labs/holdlab`, `benchmarks/run_holdlab.py`. This is what makes
  the fix general rather than PairLab-specific.

## Libella capability status (development view)

Status vocabulary: VERIFIED means its own tests or benchmark ran against a real
local lab. IN-DEV, PLANNED and NOT SHIPPED are as named. "Ref" names which reference
platform has a comparable mechanism (P, S, A, H, W, Sh above); "not compared" means
no reference was looked at for that row, not that none has one.

### Family A: autonomous intelligence

| Capability | Ref | Ours | Status | Acceptance |
|-|-|-|-|-|
| Autonomous planning | A planner intents, P subtasks | LLM decompose plus compile gate | VERIFIED | agent mode 16/16 (v0.4) |
| Specialist ReAct investigation | S, A, W | `agent_runtime.py` ReAct loop, typed actions | VERIFIED | agent mode 16/16, 17 validated, $0.17 (v0.4) |
| Hypothesis tracking | A fact and finding graph | hypotheses table plus runtime actions | VERIFIED unit | `test_agent_runtime` |
| Delegation | P sub-chains, A intents | delegate action to gated child intent | VERIFIED unit | delegation test |
| Parallel workers | W scheduler, A workers | leased intents plus fencing | VERIFIED | audit race tests |
| Shared durable state | P Postgres, A graph, W blackboard | SQLite plus evidence plus graph | VERIFIED | graph and memory tests |
| Lifecycle termination | S finish tool | finish requires evidence | VERIFIED unit | finish-gate test |
| Budgets and cost routing | S budget scheduler, A budget ledger | per-role model, token and cost caps | VERIFIED | `agent_runs` accounting |
| Failure isolation and retry | P non-retryable errors | intent blocked, bounded retry | VERIFIED | audit and recovery tests |
| Persistent cross-run memory | P vector memory | `memory_facts`, recall, drift | VERIFIED unit | `test_graph_memory` |
| Explainable decisions | A trace search | `investigation_steps` timeline | VERIFIED unit | steps recorded |

### Family B: security assessment

| Capability | Ref | Ours | Status |
|-|-|-|-|
| Web, 16 classes | S, A, Sh | `checks.py`, PairLab 16/16 with declared hints, 13/16 without | VERIFIED |
| Authenticated workflows | S, Sh | `auth_browser.py` | VERIFIED (tests/authbrowser) |
| Multi-role authorization | S, Sh | `api_audit` BOLA and BFLA, role matrix | VERIFIED |
| REST and OpenAPI | Sh | `api_audit` 5/5 | VERIFIED |
| GraphQL | not compared | `graphql_audit` 7/7 | VERIFIED |
| Source and dependency | Sh, W | `codeaudit` 6/6 plus OSV | VERIFIED |
| Cloud posture | not compared | `cloud_audit` against moto | IN-DEV |
| Container | H (trivy wrapper) | `container_adapters` | VERIFIED |
| Technology-specific modules | H | `tech_modules` | IN-DEV |
| TLS and infrastructure | A | `tls_audit` plus nmap | VERIFIED |
| ZAP | S | `zap_adapter` | IN-DEV (live test skipped, ZAP not installed) |

### Family C: investigation

| Capability | Ref | Ours | Status |
|-|-|-|-|
| HTTP capture | A proxy, S Caido | exchanges plus evidence | VERIFIED |
| Traffic search, replay, correlation | A | `traffic.py` | VERIFIED (tests/traffic) |
| Browser automation | S, Sh, W | `browser_crawl` plus `auth_browser` | VERIFIED |
| Evidence provenance | A evidence store and receipt check | derived provenance plus hash chain | VERIFIED |
| Verification | A retest agent and receipt check, W oracles, Sh reconciliation | typed proof contracts plus class differentials (`proof.py`, `verifier.py`) | VERIFIED: 29 adversarial tests, 13 mutations killed, PairLab 16/16 vuln and 0 FP hardened |
| Cross-tool dedup | S | `dedup_key` plus correlation | VERIFIED |
| Investigation graph | A exploration graph, W attack graph | `graph.py` lineage | VERIFIED unit |
| Retest and remediation | A retest agent | retest plus remediation | VERIFIED retest |
| Drift and incremental | not compared | `memory.detect_drift` | VERIFIED unit |

### Family D: product operations

| Capability | Ref | Ours | Status |
|-|-|-|-|
| Command center and agent operations UI | A, P | dashboard, agent-runs and investigation UI | IN-DEV (reconnect acceptance not run) |
| Findings explorer | A, Sh | present | VERIFIED |
| Reports MD, JSON, SARIF | Sh | `report.py` | VERIFIED |
| PDF, HTML, DOCX, XLSX, CSV export | Sh | `report_pdf.py`, `report_formats.py` | VERIFIED (download of every format, earlier head) |
| Target API credential test | Sh | withdrawn pending destination controls | NOT SHIPPED |
| Remediation board and historical comparison | not compared | `remediation`, `compare_engagements` | IN-DEV |
| Plugin and MCP | H, S, A | `plugins`, `mcp_client` | IN-DEV |
| CI and issue-tracker hooks | S | not built | PLANNED |
| Scheduled retest | not compared | not built | PLANNED |
| Orgs, RBAC, SSO, distributed workers | not compared | not started | PLANNED |

### Family F: standards and offence (on `defensive-readiness`)

| Capability | Module | Status | Evidence |
|-|-|-|-|
| Versioned ASVS 5.0.0 catalog (345 reqs) | `standards.py`, `standards_data/asvs-5.0.0.json` | VERIFIED | import pinned by SHA, 16 tests |
| OWASP API Security Top 10 2023 | `standards_data/api-top10-2023.json` | VERIFIED | pinned by SHA |
| One coverage ledger, per-requirement strength | `coverage.py` | VERIFIED | 26 of 253 ASVS L2 executed on PairLab, 227 untested; no improvement claimed |
| JWT attacks | `jwt_audit.py` | VERIFIED unit and lab, joint run | 4 validated findings in the joint acceptance |
| OAuth and OIDC misconfiguration | `oauth_audit.py` | VERIFIED unit and lab | 10 tests |
| Session lifecycle | `session_audit.py` | VERIFIED unit and lab | 7 tests |
| Role matrix escalation | `privesc_audit.py` | VERIFIED unit and lab, joint run | CWE-306 and CWE-639 in the joint acceptance |
| Injection depth (XXE+OOB, blind RCE, LFI, CRLF) | `injection_audit.py` | VERIFIED unit and lab | 12 tests; OOB proof replays inconclusive |
| Web protocol (host header, cache, HPP, verb, smuggling detect) | `web_protocol_audit.py` | VERIFIED unit and lab | 12 tests; smuggling opt-in |
| Atomic spend reservations | `budget.py` | VERIFIED | 8-thread boundary and crash expiry tests |
| Impact demonstration | `impact_proof.py` | VERIFIED unit and lab | 9 tests; lab flag, read-only allowlist, scope gate |
| Dial-time egress on every path | `egress.py` | VERIFIED, real target | KeyReed run, 0 denials after alias fix |
| WAF challenge classified, not scored | `http_probe.mitigation` | VERIFIED, real target | KeyReed: 114 challenge responses read as inconclusive |

Joint acceptance (`benchmarks/acceptance_offence.py`): six engagements, 21 findings
validated, ledgers and evidence chains intact. `scripts/check_test_env.py` (run in CI)
fails when a critical test group stops being collected or Chromium will not launch.
A blocked audit reports `inconclusive`, never a pass.

## Historical results (earlier heads, not rerun at `973fa33`)

* v0.4 agent mode (claude-haiku-4.5): 16/16 PairLab seeds, 17 findings replay-validated,
  $0.17, 526s. Whether declared hints were used in that run is not recorded in this
  document, and it differs from the no-hint agent result above (mode B, 13/16 plus
  three incorrect confirmed findings at `b656a67`). Do not combine the two numbers.
* Deterministic mode on `defensive-readiness`: 16/16, 0 FP on the hardened twin;
  suite 779 passed at v0.4, later 913 on that branch, now 1055 at `973fa33`.
* Browser journeys A, C, D, E and F executed on `defensive-readiness`; none rerun at
  `973fa33`.
* Retest: a removed route reads `fixed (route removed)` only with corroborating
  signals; otherwise inconclusive.
* Independent audit2: 13 defects fixed, 31 regression tests.

## Open items

* PairLab gate on the new verifier: measured (16/16 vuln, 0 FP hardened); re-run on the
  integrated tree pending.
* Mode B on the hardened twin, on the new verifier, and with declared hints.
* Comparative tests of any reference platform on PairLab: none run, so no comparison
  of detection, false positives, cost or time with any of them exists.
* CI and issue-tracker integration, scheduled retest, assessment templates, enterprise
  features.
* Version 0.5.0 artifacts not published.
