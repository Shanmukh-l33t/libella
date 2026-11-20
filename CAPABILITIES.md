# Capability Matrix

Honest status: TESTED = exercised with real execution and observed results.
PARTIAL = works with stated limits. PLANNED = not implemented, no claims.

## Assessment lifecycle

| Capability | Status | Evidence |
|---|---|---|
| Engagement creation with enforceable scope | TESTED | tests/test_scope.py, API validation |
| Scope enforcement at exec boundary (DNS-resolved, exclusions, ports, categories) | TESTED | tests/audit/test_scope_bypass.py |
| Redirect-hop scope re-check + peer-IP verification | TESTED | http_probe.py, audit tests |
| Deterministic assessment pipeline (no LLM) | TESTED | PairLab 13/13 validated, 0 FP |
| LLM planning mode (typed deltas, compile gate, budgets) | TESTED | benchmarks/run_llm_mode.py: 8/8 testable seeds validated, out-of-scope proposals rejected |
| Leased intents, fencing, expiry sweep, bounded retries | TESTED | orchestrator.py, audit race tests |
| Duplicate-work prevention | TESTED | duplicate_work_prevented events |
| Pause / resume / cancel | TESTED | API + orchestrator |
| Budget enforcement (time, cost, plan rounds) | TESTED | budget_exhausted paths |
| Degradation visibility (missing tools, blocked intents) | TESTED | degradation events, report section |

## Reconnaissance and discovery

| Capability | Status | Notes |
|---|---|---|
| HTTP probing + fingerprint (platform probe) | TESTED | always available |
| ProjectDiscovery httpx adapter | TESTED | typed, parsed JSONL |
| subfinder passive subdomains | TESTED | adapter + scope-filtered ingest |
| nmap port/service scan | TESTED | adapter, XML parsed, resolved-IP targets only |
| ffuf content discovery | TESTED | adapter, JSON parsed |
| Same-origin crawling (links, forms, params) | TESTED | bounded pages/depth |
| JS bundle API route mining (SPA coverage) | TESTED | bounded scripts; see Juice Shop run |
| Browser-rendered crawling (Playwright) | PLANNED | SPA routes mined statically from bundles, not rendered |
| Certificate transparency / DNS intel | PLANNED | |
| Attack-surface change detection | PLANNED | |

## Web / API testing

| Capability | Status | Notes |
|---|---|---|
| Reflected XSS | TESTED | PairLab PL-01 validated |
| SQL injection (error-based + UNION extraction) | TESTED | PL-02, PL-03 validated |
| Auth bypass via SQLi | TESTED | PL-03 (requires identity config) |
| IDOR / BOLA (authenticated cross-user) | TESTED | PL-04 (requires identities + object hints) |
| Path traversal | TESTED | PL-05, multi-depth payloads |
| CORS misconfiguration | TESTED | PL-06 |
| Excessive data exposure | TESTED | PL-07 |
| SSRF (in-scope marker proof) | TESTED | PL-08 (requires internal target hint) |
| Open redirect | TESTED | PL-09 |
| Debug/config exposure, directory listing | TESTED | PL-10, PL-11 |
| Cookie flag weaknesses | TESTED | PL-12 |
| Missing security headers | TESTED | PL-13 + Juice Shop |
| nuclei template scanning | TESTED | adapter; scanner findings stay unvalidated unless replayed |
| OpenAPI import + schema-driven testing | PLANNED | |
| GraphQL introspection testing | PLANNED | |
| Business-logic / multi-step workflows | PARTIAL | identity login + IDOR; deeper flows planned |
| File upload validation | PLANNED | |
| SSTI / deserialization / XXE | PLANNED | |

## Infrastructure / cloud / code

| Capability | Status | Notes |
|---|---|---|
| TLS / header / exposure checks | PARTIAL | headers tested; deep TLS audit planned |
| AWS / container / K8s posture | PLANNED | |
| Semgrep / Trivy / OSV / secrets scanners | PLANNED | |
| CVE/CWE intelligence with version-vs-confirmation distinction | PARTIAL | version banners are observations only (negative control tested); CVE DB integration planned |

## Evidence and verification

| Capability | Status | Evidence |
|---|---|---|
| Content-addressed evidence + hash chain | TESTED | tamper/chain-break tests |
| Derived provenance (not model-declared) | TESTED | unbound evidence stays suspected |
| Independent replay verification | TESTED | 13/13 PairLab validations |
| Retest after remediation (fixed/persists/inconclusive) | TESTED | verifier.retest + gate tests |
| Dedup by root cause | TESTED | pipeline tests |
| Secret redaction in reports/evidence | TESTED | audit secrets tests |
| SARIF / JSON / Markdown reports | TESTED | deterministic rendering |

## Platform / UX

| Capability | Status | Notes |
|---|---|---|
| Web UI (dashboard, wizard, live ops, graph, findings, evidence, settings) | TESTED | web/ built; see screenshots |
| SSE live updates with cursor replay | TESTED | |
| Token auth, loopback default | TESTED | audit API tests |
| Docker single-container deploy | TESTED | Dockerfile + compose |
| Multi-tenant / horizontal scale | NOT SUPPORTED | deliberate single-instance design |
| Network-namespace egress jail | PLANNED | residual TOCTOU documented |

## Benchmark conditions (reproducible)

- Host: Linux x86_64, 6 cores, 15GB RAM. Python 3.12. nuclei 3.x with
  13,808 templates, httpx 1.12.0, nmap, subfinder, ffuf installed.
- PairLab twins: labs/pairlab/app.py (Flask, localhost). Ground truth:
  labs/pairlab/ground_truth.json (13 seeds, 6 negative controls).
- Deterministic-only run: ~8s/engagement. With nuclei: ~155s/engagement.
- Juice Shop (bkimminich/juice-shop:latest, localhost:3001): see
  benchmark_runs/juice results; SPA coverage via static JS mining.
- LLM mode: OpenAI-compatible endpoint, planner model configured per run;
  cost recorded in llm_usage. No cross-project performance claims are made.