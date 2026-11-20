# Libella — Architecture

Autonomous penetration-testing workbench. Evidence-first, scope-enforced,
multi-agent. Original implementation; ideas extracted from ARTEX, strix,
PentestGPT, hermes-agent, pentagi, hexstrike-ai, Pentest-Swarm-AI, shannon
(see research/analysis-*.md, never published).

## Decision record (research-driven)

| Decision | Choice | Why (evidence) |
|---|---|---|
| Backend | Python 3.12, FastAPI, single process | Security tooling ecosystem is Python; ARTEX proves single-binary+DB beats microservices; shannon's Temporal adds install weight we avoid |
| State | SQLite (WAL) embedded | Zero external services = simplest self-host (ARTEX needs Postgres, shannon needs Temporal). Durable, resumable, single-file backup |
| Evidence | Content-addressed blobs + append-only hash-chain ledger | ARTEX evidence/store.go pattern + tamper evidence they lack (issue #310) |
| Frontend | React+Vite+TS+Tailwind, static served by backend, one UI | strix lesson: 3 UIs = 22k LOC maintenance; single container deploy |
| Live updates | SSE with monotonic cursor + DB replay on reconnect | ARTEX broadcast pattern, correct degradation |
| Orchestration | Supervisor planner + leased worker intents, typed deltas through compile gate | ARTEX fencing/lease proven; PentestGPT compile_plan rejects invalid state writes; basis != prerequisite (PentestGPT #568) |
| Termination | Lifecycle-tool protocol: only finish tool ends a run; text-only turns nudged, bounded | strix's highest-value idea (fixes "done!" with no output) |
| Tools | Typed adapters, argv built by code, no shell, no free-text args | hexstrike #263/#224 injection class killed by construction; swarm executor gate order |
| Scope | First-class Authorization object enforced at exec boundary + dial hook, DNS-pinned resolved-IP checks | Every reference fails here (ARTEX scope=coverage; strix prompt-only; swarm name-only). Our core differentiator |
| Verification | Independent replay: re-issue bound request, compare observed vs claimed; verbatim quote must exist in captured exchange | ARTEX receipt check + strix/shannon never execute PoCs; swarm oracles. "verified" = reproduced now |
| Provenance | Derived, not declared: observation source computed from evidence binding, never accepted from model | ARTEX #124 open hole closed |
| Budgets | Per-engagement token/cost/time caps, reserve for reporting, pause policy | strix budget-as-scheduler |
| Reports | Deterministic rendering from typed state; MD+JSON+SARIF; redaction pass; CSV formula escaping | shannon collector rendering + its credential-leak gap; strix writer escaping |
| Degradation | Every failure/skip gets a code + visible label; no silent all-clear | swarm #66, shannon #529 |
| License | Apache-2.0 | Patent grant, permissive, no AGPL code copied (ARTEX/swarm/shannon are AGPL; ideas only) |
| Models | OpenAI-compatible abstraction, per-role model, fallback chain, cost accounting | All references; hermes predictability-over-liveness fallback rule |

## Security boundaries (foundational, not bolted on)

1. Engagement authorization object: targets (domains/CIDRs/URL prefixes),
   exclusions, time window, permitted categories, rate/concurrency caps,
   budgets, profile (passive | safe_active | advanced_validation).
   Advanced/disruptive classes require explicit per-engagement flag.
2. Every egress-capable action resolves target -> IP, checks against scope
   (including exclusions, link-local/metadata ranges unless explicitly
   authorized), pins DNS for the connection. Enforced in code, not prompts.
3. Tool execution: typed params -> validated argv -> subprocess with
   timeout, output caps, no shell. Audit row per call: engagement, tool,
   argv, target, decision, duration, exit.
4. LLM output is data. Target content is framed untrusted; it can propose
   observations but cannot mutate canonical state except through the
   compile gate which re-checks scope and evidence bindings.
5. Secrets: credentials redacted from logs, evidence, reports. API token and
   LLM key encrypted at rest (Fernet, key file 0600). Localhost-only bind by
   default; token auth for API.
6. Emergency stop: engagement-level cancel stops intents and leases; running
   subprocesses are bounded by their tool timeout (hard-kill propagation is
   roadmap). Audit logs record every scope decision.

## Data model (SQLite)

engagements(id, name, profile, status, scope_json, auth_json, budgets_json,
  window_start, window_end, created_at, ...)
assets(id, engagement_id, kind, key, value_json, parent_id, discovered_by,
  first_seen, last_seen)  -- dedup by (engagement_id, kind, key)
intents(id, engagement_id, parent_id, role, objective, status,
  claim_token, lease_expires, depends_on_json, informed_by_json,
  created_at, finished_at, result_json)
  status: open|running|done|blocked|exhausted|stopped
observations(id, engagement_id, intent_id, asset_id, kind, summary,
  evidence_id, quote, source_derived, created_at)
findings(id, engagement_id, title, cwe, owasp, severity, cvss, confidence,
  asset_id, endpoint, state, description, impact, remediation,
  dedup_key, created_at, updated_at)
  state: suspected|observed|validated|reported|remediated|retested_fixed|
         retested_persists|ruled_out
evidence(id, engagement_id, sha256, kind, path, bytes, created_at,
  prev_hash, chain_hash)  -- append-only ledger
exchanges(id, engagement_id, evidence_id, method, url, status,
  req_headers_json, resp_headers_json, duration_ms, tool, created_at)
verifications(id, finding_id, attempt, method, replay_exchange_id,
  verdict, detail, created_at)
tool_calls(id, engagement_id, intent_id, tool, argv_json, target,
  scope_decision, exit_code, duration_ms, artifact_id, error, created_at)
events(id, engagement_id, seq, kind, payload_json, created_at)  -- SSE cursor
llm_usage(id, engagement_id, role, model, input_tokens, output_tokens,
  cost_usd, created_at)
retests(id, finding_id, exchange_id, verdict, created_at)
settings(key, value_json)

## Assessment lifecycle

create engagement (scope+auth+budgets) -> start ->
planner decomposes objectives into intents (recon first) ->
workers claim intents (lease+fencing) -> execute typed tools/checks ->
observations bound to evidence -> findings proposed (dedup by root cause) ->
independent verifier replays proof request -> state promotion only on
reproduced evidence -> planner convergence (goals covered or exhausted) ->
deterministic report (MD/JSON/SARIF, redacted) -> retest mode re-runs
proof requests against fixed target, verdict fixed/persists/inconclusive.

Human can pause/resume/steer/cancel at any point; every decision audited.

## Agent roles (functional, one process)

planner (decompose, dispatch, converge), recon (assets/services/fingerprint),
web (WSTG checks, authenticated flows), api (OpenAPI, BOLA/BFLA, schema),
infra (TLS/headers/exposure), code (semgrep/trivy/secrets, optional),
verifier (independent replay, adversarial), reporter (deterministic render),
retester. Roles = prompt + tool subset + model choice, not processes.
Merge/split based on measured performance.

## Deployment

Single container: backend + built frontend + toolchain (nmap, nuclei,
httpx, subfinder, ffuf installed in image; availability probed at startup,
missing tools degrade loudly). docker compose up. Localhost bind default.
Dev: uv sync + pnpm build. SQLite file + evidence dir = backup unit.