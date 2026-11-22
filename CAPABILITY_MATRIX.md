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
| PDF/HTML/DOCX/XLSX/CSV export | Sh | report_pdf.py + report_formats.py | VERIFIED (browser download of every format) |
| Target API credential test | Sh | prototype withdrawn pending destination controls | NOT SHIPPED |
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
- Full suite: 779 passed, 1 skipped (ZAP live), lint clean, counted on branch
  `defensive-readiness` at the commit that adds this line (v0.5.0, not tagged).
  PairLab gate re-run on the same code: 16/16 vuln, 0 FP hardened, evidence chains intact.
- Browser journeys executed on that code: A beginner (wizard, real PairLab scan to
  Done, 11/11 findings verified, PDF reopened, SSE p50 0.34 s), C tool readiness
  levels, D target credentials (redirect not followed, out-of-scope sink 0 requests,
  secret absent everywhere), E execution controls (pause/cancel/window close stop
  all egress, 5 req/s cap held), F report recovery (failed render keeps last report,
  all exports reopen, tampered evidence reads broken).
- Retest: a removed route reads `fixed (route removed)` only with corroborating
  signals (control URL up, consistent repeat, no block page); otherwise inconclusive.
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

## Family F — Standards and offence (added on `defensive-readiness`)

Status vocabulary: VERIFIED unit/lab = its own tests prove it against a real local
lab; WIRED = the planner creates its intent and the executor runs it (asserted);
REAL-TARGET = exercised against an authorized external site.

| Capability | Module | Status | Evidence |
|---|---|---|---|
| Versioned ASVS 5.0.0 catalog (345 reqs, exact ids/levels) | `standards.py`, `standards_data/asvs-5.0.0.json` | VERIFIED | import pinned by SHA, 16 tests |
| OWASP API Security Top 10 2023 | `standards_data/api-top10-2023.json` | VERIFIED | pinned by SHA, mapped rows |
| One coverage ledger, per-requirement strength | `coverage.py` | VERIFIED | 26/253 ASVS L2 executed on PairLab, 227 honestly untested |
| Structured control ids (no title/CWE-only attribution) | `controls.py` | VERIFIED | negative controls incl. misleading title |
| Analyst attribution add/remove with history | `coverage.link` | VERIFIED | route + append-only history test |
| JWT attacks (alg none, confusion, weak secret, kid, claims) | `jwt_audit.py` | VERIFIED unit/lab, WIRED, JOINT | 4 validated findings in the joint acceptance |
| OAuth/OIDC misconfiguration | `oauth_audit.py` | VERIFIED unit/lab, WIRED | 10 tests |
| Session lifecycle (fixation, logout, cookie scope) | `session_audit.py` | VERIFIED unit/lab, WIRED | 7 tests |
| Role matrix privilege escalation | `privesc_audit.py` | VERIFIED unit/lab, WIRED, JOINT | CWE-306 + CWE-639 validated in the joint acceptance |
| Injection depth (XXE+OOB, blind RCE, LFI, CRLF) | `injection_audit.py` | VERIFIED unit/lab, WIRED | 12 tests; OOB proof replays inconclusive |
| Web protocol (host header, cache, HPP, verb, smuggling detect) | `web_protocol_audit.py` | VERIFIED unit/lab, WIRED | 12 tests; smuggling opt-in |
| Registered specialists the scheduler runs | `specialists.py`, `orchestrator.py` | VERIFIED | lifecycle + capability admission tests |
| Atomic spend reservations (concurrency-safe ceiling) | `budget.py` | VERIFIED | 8-thread boundary + crash expiry tests |
| Dial-time egress on every path | `egress.py` | VERIFIED, REAL-TARGET | KeyReed: 200/47KB read, 0 denials after alias fix |
| WAF challenge classified, not scored | `http_probe.mitigation` | VERIFIED, REAL-TARGET | KeyReed: 114 challenge responses -> inconclusive |

Joint acceptance (`benchmarks/acceptance_offence.py`): two real engagements drive
planner -> executor -> lab -> pipeline; 8 findings, all independently validated,
ledgers and evidence chains intact. JWT and role-matrix audits are exercised that
way. Injection, web-protocol, OAuth and session audits remain lab-proven and wired
but are not yet exercised in a joint run. A blocked audit (preconditions unmet)
reports `inconclusive`, never a pass. OOB and smuggling proofs replay as
inconclusive by design; nmap remains argv-confined and is reported as
egress-unconfined.
