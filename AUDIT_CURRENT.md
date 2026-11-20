# Current Product Audit (honest classification, pre-expansion)

Legend: VERIFIED = implemented + executed + independently tested.
PARTIAL = works with stated limits. UI-ONLY = interface without deep backend.
MISSING = not implemented.

## VERIFIED (keep)
- Scope engine: fail-closed, DNS-resolved, peer-verified, exclusions, categories,
  repo/image confinement; 18 bypass regression tests.
- Evidence: content-addressed, hash-chained, tamper-tested, derived provenance,
  redaction (MD/JSON/SARIF).
- Deterministic web checks: 16 PairLab classes replay-validated, 0 FP hardened.
- API audit (OpenAPI): 5 classes. GraphQL: 7 classes. TLS: 3 classes + re-scan verify.
- Code/supply-chain: semgrep/gitleaks/trivy/OSV, 6 classes, CVEs stay observations.
- Container image scan (trivy). Recon adapters nmap/nuclei/httpx/subfinder/ffuf.
- Static + Playwright crawl (runtime API discovery).
- Independent replay verification + retest (persists/fixed) + cancel/resume recovery.
- Orchestrator: leased intents, fencing, compile gate, budgets, deterministic plan.
- LLM planner mode (adds intents; cost-accounted; gate rejects out-of-scope).
- Premium UI: dashboard, wizard, live ops, graph, findings, evidence, settings.
- Docker single-container install; CI green; 242 tests; 4 releases.

## PARTIAL (deepen)
- "Agents": roles in a deterministic pipeline, NOT genuine reasoning specialists.
  LLM only adds intents; no per-specialist investigation loop. -> CORE GAP.
- Investigation graph: assets+findings+intents only; no hypotheses, lineage,
  timelines, coverage, decision drill-down. -> deepen.
- Authenticated testing: identity login + IDOR/BOLA only; no multi-step workflows,
  no session-state management, no authenticated browser crawl. -> deepen.
- Persistent memory: per-engagement only; no cross-run intelligence, drift,
  change-based testing, historical finding reuse. -> build.
- Reporting: MD/JSON/SARIF; no PDF, no remediation tracking UI, no historical
  comparison. -> build.

## MISSING (build)
- Genuine autonomous specialist agent runtime (ReAct investigation, hypotheses,
  explainable decisions, delegation, parallel specialists).
- HTTP traffic intelligence workspace: search, inspection, authorized replay,
  historical correlation (ARTEX MITM/traffic depth).
- Cloud posture (AWS IAM/S3/SG/logging/encryption) via controlled moto lab.
- Technology-specific modules: WordPress, PHP, Java, ColdFusion, Node, IIS/Apache/Nginx.
- OWASP ZAP integration.
- MCP client + plugin/extension framework (tools, agents, exporters).
- PDF export; issue-tracker + CI/CD hooks; scheduled retest; assessment templates.
- Reference execution + benchmarking against the six repos.
- Attack-surface drift detection; incremental/change-based assessment.

## UI-ONLY / shallow (fix)
- Graph tab renders real nodes but relationships are shallow (no investigation
  lineage). Agent Operations shows intents, not real agent reasoning traces.
- No traffic workspace, no tool center depth (versions/history), no evidence
  search, no remediation board, no model-usage dashboard depth.

## Architectural corrections required
1. Add a real agent runtime layer above the deterministic tools (tools become the
   agents' callable surface; deterministic pipeline stays as baseline/fallback).
2. Extend data model: hypotheses, investigation_steps, agent_runs, auth_contexts,
   workflows, remediation fields, cross-run memory, traffic replay links.
3. Traffic store + replay API + workspace.
4. Graph builder reads the full lineage (asset->endpoint->observation->hypothesis->
   finding->verification->remediation->retest).
5. Plugin/MCP contract for extensibility.