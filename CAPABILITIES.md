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
| TLS audit: expired cert, hostname mismatch, weak protocols (TLSv1/1.1) | TESTED | tlslab twins; findings independently re-verified by TLS re-scan (not HTTP replay); hardened twin 0 findings |
| Header / exposure checks | TESTED | PairLab + Juice Shop |
| Container image vulnerability scan (trivy) | TESTED | local images only; CVE matches are potentially_affected observations, never auto-confirmed |
| Source code audit (semgrep + gitleaks + trivy fs) | TESTED | vulnrepo 6/6 seeded classes (hardcoded creds, eval, shell injection, pickle, debug), cleanrepo 0 FP |
| Dependency advisories via OSV | TESTED | version matches recorded as potentially_affected observations with CVE/package/version/source; never auto-promoted (PyYAML 5.3.1 CVE-2020-14343 verified) |
| AWS / K8s posture | PLANNED | requires operator credentials; not claimed |
| CVE/CWE intelligence beyond OSV (NVD/CPE correlation) | PARTIAL | OSV layer tested; version-vs-confirmed discipline enforced |

## API security (OpenAPI-driven)

| Capability | Status | Notes |
|---|---|---|
| OpenAPI 3 import + endpoint/parameter/schema inventory | TESTED | labs/apilab/openapi.json |
| BOLA (cross-user object access) | TESTED | apilab AP seed validated; hardened 0 |
| BFLA (role boundary) | TESTED | alice hits admin endpoint; hardened 403 |
| Mass assignment (privileged field injection + persistence proof) | TESTED | POST extra field verified via GET |
| Excessive data exposure | TESTED | password hashes in list response |
| Missing auth on sensitive endpoint | TESTED | unauthenticated 200 |
| Schema-conformance observations | TESTED | response fields outside schema recorded |
| GraphQL introspection testing | PLANNED | |

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
- Juice Shop (bkimminich/juice-shop:latest, localhost:3001): 53 assets
  discovered (HTML crawl + JS bundle route mining), 1 validated finding
  (missing security headers) + 1 unvalidated nuclei observation. Deep SPA
  exploitation needs browser rendering (PLANNED); results reported honestly.
- LLM mode: OpenAI-compatible endpoint, planner model configured per run;
  cost recorded in llm_usage. No cross-project performance claims are made.

## Verification evidence log (all real executions)

| Proof | Result | Artifact |
|---|---|---|
| PairLab vulnerable twin | 13/13 seeds detected AND independently replay-validated, 0 FP | benchmark_runs/results.json |
| PairLab hardened twin | 0 confirmed findings, 0 FP | benchmark_runs/results.json |
| CI clean-environment gate | GitHub Actions: ground-truth self-check + 13/13 + 0 FP + chains intact, "benchmark gate PASS" | run 44643365589 |
| Retest after remediation | validated /debug finding: retest=persists on vuln; lab swapped to hardened; retest=fixed; state retested_fixed | benchmarks/run_retest_cycle.py, benchmark_runs/retest/phase{1,2}.json |
| Interrupt and recovery | cancel mid-run (4 intents stopped) -> resume -> done, 8/8 validated, chain intact (234 objects) | benchmarks/run_recovery.py, benchmark_runs/recovery_results.json |
| LLM planning mode | 7 planner calls, 33 intents, compile gate rejected out-of-scope proposal, 8/8 testable seeds validated, budget-bounded | benchmarks/run_llm_mode.py, benchmark_runs/llm_mode_results.json |
| Docker single-container install | image builds; container healthy; full engagement via container API (see DOCKER_VERIFICATION.md) | Dockerfile, docker-compose.yml |
| Evidence tamper resistance | blob rewrite + ledger row forgery detected; chain break detected | tests/audit/test_evidence_integrity.py |
| UI real-data verification | browser-driven: dashboard, live ops, graph, finding detail, rule-out flow, report, settings; 17 screenshots | docs/screenshots/ |
| TLS audit (v0.2) | expired cert + weak protocols validated on vuln twin; hostname mismatch validated on mismatch twin; hardened 0; TLS re-scan verification | benchmarks/run_tlslab.py, benchmark_runs/tlslab_results.json |
| Code/supply-chain audit (v0.2) | vulnrepo 6/6 seeded classes, cleanrepo 0 FP; PyYAML CVE-2020-14343 stays potentially_affected observation | benchmarks/run_codeaudit.py |
| OpenAPI-driven API audit (v0.2) | apilab 5/5 seeds validated (BOLA/BFLA/mass-assignment/exposure/missing-auth), hardened 0 FP | benchmarks/run_apilab.py, benchmark_runs/apilab_results.json |
| Container image scan (v0.2) | real trivy scan of local image; CVEs recorded as observations, 0 auto-confirmed findings; injection rejected | tests/test_container_scan.py |
| Performance (v0.2) | PairLab full run: 153.7s wall, platform CPU 0.5s, scanner children CPU 19.3s, platform peak RSS 60.4MB, 0 LLM tokens | benchmarks/measure_perf.py, benchmark_runs/perf.json |