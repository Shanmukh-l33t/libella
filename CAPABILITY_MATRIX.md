# Capability Matrix + Engineering Backlog (development instrument)

Status: VERIFIED (executed+tested) / IN-DEV (workstream running) / PLANNED / BLOCKED.
References: PentAGI(P), Strix(S), ARTEX(A), HexStrike(H), Swarm(W), Shannon(Sh).
Research: research/analysis-*.md, inventory-*.md, REA_LOG.md (provable REA invocations).

## Family A — Autonomous Intelligence
| Capability | Ref evidence | Ours | Status | Acceptance |
|---|---|---|---|---|
| Autonomous planning | A planner intents; P subtasks | _plan_agent LLM decompose + compile gate | VERIFIED | agent-mode 16/16 |
| Specialist ReAct investigation | S SandboxAgent; A worker; W ReAct | agent_runtime.py ReAct loop, typed actions | VERIFIED | agent-mode 16/16, 17 validated, $0.17 |
| Hypothesis tracking | A fact/finding graph | hypotheses table + runtime actions | VERIFIED unit | test_agent_runtime |
| Delegation | P sub-chains; A intents | delegate action -> gated child intent | VERIFIED unit | delegation test |
| Parallel workers | W scheduler; A N workers | leased intents + fencing | VERIFIED | audit race tests |
| Shared durable state | P pg; A graph; W blackboard | SQLite + evidence + graph | VERIFIED | graph/memory tests |
| Lifecycle termination | S finish_scan | finish requires evidence; text nudged | VERIFIED unit | finish-gate test |
| Budgets/cost routing | S budget scheduler | per-role model, token/cost, max_iter | VERIFIED | agent_runs accounting |
| Failure isolation/retry | P non-retryable; PentestGPT predicate | intent blocked, bounded retry | VERIFIED | audit + recovery |
| Persistent cross-run memory | P vector memory | memory_facts + recall + drift | VERIFIED unit | test_graph_memory |
| Explainable decisions | A trace search | investigation_steps timeline | VERIFIED unit | steps recorded |

## Family B — Security Assessment
| Capability | Ref | Ours | Status |
|---|---|---|---|
| Web 16 classes | S/A/Sh | checks.py + PairLab 16/16 | VERIFIED |
| Authenticated workflows | S browser; Sh | auth_browser.py (WS) | IN-DEV |
| Multi-role authz | S/Sh | api_audit BOLA/BFLA + auth_browser | VERIFIED api / IN-DEV browser |
| REST/OpenAPI | Sh | api_audit 5/5 | VERIFIED |
| GraphQL | (none strong) | graphql_audit 7/7 | VERIFIED |
| Source/dependency | Sh Capella | codeaudit 6/6 + OSV | VERIFIED |
| Cloud posture | (none) | cloud_audit moto (WS) | IN-DEV |
| Container | H trivy | container_adapters | VERIFIED |
| Tech-specific (WP/PHP/Java/CF/Node/IIS/Apache/Nginx) | H wpscan | tech_modules (WS) | IN-DEV |
| TLS/infra | A | tls_audit + nmap | VERIFIED |
| ZAP | S claims (absent) | zap_adapter (WS) | IN-DEV |

## Family C — Investigation
| Capability | Ref | Ours | Status |
|---|---|---|---|
| HTTP capture | A MITM; S Caido | exchanges + evidence | VERIFIED |
| Traffic search/replay/correlation | A traffic | traffic.py (WS) | IN-DEV |
| Browser automation | S/Sh Playwright | browser_crawl + auth_browser | VERIFIED crawl / IN-DEV auth |
| Evidence provenance | A receipt (gap) | derived provenance + hash chain | VERIFIED |
| Independent verification | (all gap) | verifier replay + TLS re-scan | VERIFIED |
| Cross-tool dedup | S LLM judge | dedup_key + correlation | VERIFIED dedup |
| Investigation graph | A exploration | graph.py full lineage | VERIFIED unit |
| Retest/remediation | A retester | retest + remediation (WS) | VERIFIED retest / IN-DEV board |
| Drift/incremental | (none) | memory.detect_drift | VERIFIED unit |

## Family D — Product Operations
| Capability | Ref | Ours | Status |
|---|---|---|---|
| Command center | A/P UI | dashboard (UI WS) | IN-DEV expand |
| Agent operations | A sessions | agent-runs/investigation UI | IN-DEV |
| Traffic workspace | A traffic tab | UI WS | IN-DEV |
| Tool center | H health | UI WS | IN-DEV |
| Evidence workspace | A traffic | UI WS | IN-DEV |
| Findings explorer | A/Sh | exists | VERIFIED |
| Reports MD/JSON/SARIF | Sh | report.py | VERIFIED |
| PDF export | Sh typst | report_pdf (WS) | IN-DEV |
| Remediation board | (none) | remediation (WS) | IN-DEV |
| Historical comparison | (none) | compare_engagements (WS) | IN-DEV |
| Models/usage | P/A | UI WS | IN-DEV |
| Plugin/MCP | H MCP | plugins/mcp_client (WS) | IN-DEV |
| CI/issue-tracker | S CI | PLANNED | PLANNED |
| Scheduled retest | (none) | PLANNED | PLANNED |

## Verified results (v0.4, executed)

- Agent mode (autonomous specialists, claude-haiku-4.5): 16/16 PairLab seeds,
  17 findings independently replay-validated, 0 missed, $0.17, 526s, clean
  convergence (web/api/authz completed), 2 hypotheses, evidence chain intact.
- Deterministic mode: 16/16, 0 FP hardened (baseline).
- Full suite: 653 passed, 1 skipped (ZAP live), lint clean — counted on branch
  `data-protection`, version 0.5.0 (not yet tagged). The benchmark gate is not part
  of that suite: PairLab last recorded 16/16 vuln, 0 FP hardened, and was not re-run
  on this branch.
- Independent audit2: 13 defects fixed (4 high, 7 medium, 2 low), 31 regression tests.
- End-to-end acceptance test passes through the real API (lifecycle + traffic
  replay + graph + memory + PDF + remediation + chain).
- Provable REA (9+ invocations, evidence IDs) + reference execution (ARTEX,
  PentAGI, strix ran; strix MaxTurnsExceeded failure observed).

## Active workstreams (delegated)
WS-Research-Exec: reference execution + REA deepen + inventories.
WS-Traffic: traffic.py + replay + correlation.
WS-AuthBrowser: auth_browser.py + authlab.
WS-Cloud: cloud_audit.py + moto lab.
WS-Report: report_pdf + remediation + comparison.
WS-ZAP-Tech: zap_adapter + tech_modules + techlab.
WS-Plugin: plugins + mcp_client.
WS-UI: frontend expansion (preserve design).
Parent: agent_runtime + graph + memory + orchestrator integration + verification.

## Remaining after current wave
- CI/CD + issue-tracker integration; scheduled retest; assessment templates.
- Reference benchmarking (same labs, comparable workflows) once references executed.
- Independent adversarial re-audit of new modules; end-to-end acceptance gate.
- Release v0.5.0 (versions bumped in pyproject/__init__; artifacts not yet published).