# Libella Expansion Contracts (shared schemas for parallel workstreams)

All modules obey: scope enforced in code at exec boundary; evidence bound to real
captured artifacts (ev_ ids); findings promote only via independent verification;
LLM output is data through a compile gate; untrusted target content never mutates
policy/state; secrets redacted; every tool call audited. Preserve premium UI design.

## Data model extensions (SQLite, add via db.py SCHEMA; idempotent CREATE IF NOT EXISTS)

hypotheses(id, engagement_id, asset_id, intent_id, kind, statement, status,
  confidence REAL, created_by, created_at, updated_at)
  status: open|supported|refuted|inconclusive
investigation_steps(id, engagement_id, intent_id, agent_run_id, seq, action_kind,
  summary, tool_call_id, observation_id, evidence_id, hypothesis_id, model,
  tokens INTEGER, created_at)
  action_kind: reason|tool_call|observation|hypothesis|conclusion|delegation
agent_runs(id, engagement_id, intent_id, role, model, status, iterations INTEGER,
  tokens_in INTEGER, tokens_out INTEGER, cost_usd REAL, started_at, finished_at,
  summary, exit_reason)
  status: running|completed|failed|cancelled|budget_exhausted
auth_contexts(id, engagement_id, name, username, login_flow_json, cookies_json,
  status, last_verified_at, created_at)
  status: active|expired|failed
workflows(id, engagement_id, name, auth_context_id, steps_json, status, created_at)
  steps_json: [{action: navigate|click|fill|submit|extract|assert, selector, value, ...}]
remediation: ALTER findings ADD COLUMN remediation_notes TEXT, owner TEXT,
  fix_commit TEXT, remediated_at REAL, due_at TEXT, remediation_state TEXT DEFAULT 'open'
traffic: ALTER exchanges ADD COLUMN replay_of TEXT, tags_json TEXT DEFAULT '[]'
memory_facts(id, target_key, kind, value_json, source_engagement_id, confidence,
  first_seen, last_seen)  -- cross-run intelligence keyed by stable target identity
asset_changes(id, engagement_id, asset_key, change_kind, old_json, new_json, detected_at)

## Agent runtime (src/libella/agent_runtime.py) — CORE, parent-owned

Specialist roles: planner, recon, web, api, authz, infra, code, cloud, verifier,
correlator, risk, reporter, retester, auditor. Each = charter prompt + tool subset
+ model choice. NOT separate processes; one runtime, structured contracts.

ReAct investigation loop per intent:
  system = role charter + scope.prompt_block() + untrusted-data framing + tool schemas
  bounded by max_iterations (role budget) + token/cost budget + wall clock
  each turn model emits ONE typed action (JSON, validated):
    {thought, action, args}
    action in: call_tool | record_hypothesis | update_hypothesis | record_observation
               | propose_finding | delegate | finish
  deterministic gate validates: tool exists + params schema + scope; evidence ids
    real; propose_finding requires bound evidence + quote (reuses FindingPipeline);
    finish requires evidence-backed conclusion (lifecycle termination; plain text
    never ends a run; bounded nudge on text-only turns).
  execute via existing ToolRunner / HttpProbe / checks / adapters.
  append investigation_steps + agent_runs accounting; checkpoint each turn.
  failure isolation: a failed intent does not kill the engagement; retry bounded
    only when nothing executed (PentestGPT predicate).
  model routing per role via LLM.model_for; fallback; cost to llm_usage + agent_runs.

Deterministic checks become callable tools (run_web_check, run_api_check, etc.) so
agents invoke them deliberately; the existing deterministic pipeline remains as a
baseline mode and as the agents' tool surface. Both modes share evidence/findings.

Compile gate (extend orchestrator): LLM-proposed intents/delegations validated for
role, scope, deps; hypotheses/observations/findings written only through gated
writers that re-check evidence binding + scope.

## Traffic intelligence (src/libella/traffic.py + API) — WS-Traffic

- Store: reuse exchanges + evidence blobs. Add search (url/method/status/tool/text
  in body via evidence), filter, pagination.
- Authorized replay: POST /api/exchanges/{id}/replay -> re-issue through HttpProbe
  with scope check + per-hop checks; new exchange links replay_of; diff vs original
  (status/length/body delta); never replay out-of-scope; audit.
- Correlation: group exchanges by endpoint/asset; link to observations/findings.
- API: GET /api/engagements/{id}/traffic (search/filter/page), GET /api/exchanges/{id}
  (exists), POST /api/exchanges/{id}/replay, GET /api/engagements/{id}/traffic/correlate.
- UI: Traffic workspace (table + request/response inspector + replay button + diff).

## Authenticated browser workflows (src/libella/auth_browser.py) — WS-AuthBrowser

- Playwright login flows: form fill, submit, success assertion, capture cookies ->
  auth_contexts. Multi-identity. Session reuse across crawl/tests. Expired detection.
- Authenticated crawl: render pages WITH session, discover routes + runtime API.
- Workflow recorder/runner: steps_json executed via Playwright, scope-checked each
  navigation; extract/assert; evidence screenshots + DOM + network.
- Multi-role access-control: run same workflow/object access as each identity,
  compare expected vs observed (extends api_audit BOLA/BFLA to browser flows).
- API: POST /api/engagements/{id}/auth-contexts (login flow), GET list, POST verify,
  POST /api/engagements/{id}/workflows + run. UI: identities/workflows panel.

## Cloud posture (src/libella/cloud_audit.py) — WS-Cloud

- AWS read-only posture via boto3 against a controlled moto/localstack lab endpoint
  (operator-supplied endpoint_url + creds; NEVER real accounts without explicit scope).
- Checks: IAM wildcard policies/privilege escalation paths, S3 public access/block
  settings, security group 0.0.0.0/0 ingress, CloudTrail/Config logging enabled,
  encryption (S3/EBS/RDS), root MFA, unused credentials. Each -> observation +
  candidate finding with evidence (API response artifact), CWE, severity.
- Scope kind "cloud" (account/region/endpoint); enforced; read-only only.
- moto lab fixture in labs/cloudlab for positive/negative verification.
- Extensible provider interface (Azure/GCP adapters later, same contract).

## Investigation graph + memory (parent-owned, with runtime)

- Graph builder reads full lineage: assets->services->apps->endpoints->auth_contexts;
  observations->evidence; hypotheses->findings; findings->verifications->remediation->
  retests; intents->agent_runs->investigation_steps->tool_calls. Real persisted data.
- API /graph extended: node types (asset, endpoint, hypothesis, finding, verification,
  agent_run, evidence), edge kinds, filters, timeline, coverage.
- Cross-run memory: memory_facts keyed by stable target identity; reuse prior
  discoveries/findings; drift detection (asset_changes) between engagements;
  change-based incremental assessment (retest changed surfaces only).

## Plugin / MCP contract (src/libella/plugins.py) — later wave

- Tool plugin: manifest {name, version, contract: ToolSpec, entrypoint}; registered
  through Registry; scope/audit enforced identically. MCP client: connect external
  MCP servers, expose their tools as typed adapters with scope gate (no raw shell).
- Exporter plugin: report exporters (PDF, issue-tracker) via common contract.

## Reporting (extend report.py) — WS-Report

- PDF export (reportlab/weasyprint) from canonical report.json; redacted.
- Remediation tracking fields + board; historical comparison (diff two engagements'
  findings); retest report section. Executive + technical views.

## Finding triage (remediation workflow)

- Owner, due date and remediation state persist on the finding row and are edited
  via POST /api/findings/{id}/remediation (token auth, same gate as every other
  route). Remediation state is `open | in_progress | resolved`; posting `resolved`
  stamps remediated_at. It is independent of verification: no reproduced check is
  required, and a retest verdict (fixed/regressed) still wins on the board.
- `due_at` is an ISO calendar date (YYYY-MM-DD); empty string clears it. Text
  limits: owner 120, notes 4000, fix_commit 200. Invalid state/date/oversize -> 400.
- Activity: every write emits `finding_remediation` with a field-level `changes`
  diff; GET /api/findings/{id}/activity?limit= (<=200, newest first) returns this
  finding's events, reusing the existing events table.
- UI: finding detail has a Remediation card (owner, status, due date, notes) plus
  the activity list; the remediation board panel uses the same fields.

## Acceptance discipline
Every module: unit + integration tests, negative controls, real execution evidence,
ruff clean, scope/injection regression. Status tracked in BACKLOG.md. No completion
claim without executed verification. Independent review of critical modules.