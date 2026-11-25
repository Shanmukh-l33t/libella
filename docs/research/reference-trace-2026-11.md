# Reference trace: how six autonomous pentest platforms work, and what Libella is missing

Correction 2026-11-24: statements of the form "Libella is ahead" or "stronger" in
this trace were removed because no comparative test exists. One factual error was
corrected: ARTEX has a dedicated retest agent and a receipt check (section on ARTEX,
verification). See `CAPABILITY_MATRIX.md` for the current evidence-basis comparison.

Date: 2026-11-21. Base: `f0b4a8d` (branch `defensive-readiness`), worktree
`libella-ref-trace`, branch `w-reference-trace`.

Purpose: a source-traced comparison of six open-source autonomous pentesting
platforms against Libella's current runtime, restricted to the mechanisms
Libella does **not** have (or has only in a weaker form). Each section answers
the same eight questions, names the Libella counterpart, and proposes the
smallest change.

## Method and evidence tags

* The six repositories were cloned read-only (shallow, default branch) under
  `/home/computebox/project-pentest/research/refs/`, which is outside this
  worktree and therefore outside git. Nothing was executed from any reference
  repository: no agent, scanner, server or test.
* Each statement about a reference is **source-inspected at the pinned commit**
  in the table below. Line numbers are from that checkout.
* No reference platform was run, so no behaviour here is claimed from a live
  run. The one **runtime-observed** fact in this document is Libella's own test
  suite result (recorded at the end).
* Tags: **[S]** source-inspected, **[R]** runtime-observed, **[U]** unverified
  (inference or README-only; used sparingly and labelled).
* Licences matter for reuse: ARTEX, Pentest-Swarm-AI and Shannon are AGPL-3.0;
  PentAGI MIT; Strix Apache-2.0; HexStrike MIT. This document records behaviour
  only. No reference code was copied, and AGPL code must not be.

| Reference | Commit traced | Licence |
|---|---|---|
| PentAGI (`vxcontrol/pentagi`) | `cffed9485aa1cca70762cd08a57ac62a80406258` | MIT |
| Strix (`usestrix/strix`) | `a1ccf777d80e812edf23fc8b82bdc17def6143ac` | Apache-2.0 |
| ARTEX (`BaaRai/ARTEX`) | `2411943de6fece8d606960c516906a428b0f1010` | AGPL-3.0 |
| HexStrike AI (`0x4m4/hexstrike-ai`) | `d689933ff579d839c676c82b231f8e98326c5f04` | MIT |
| Pentest-Swarm-AI (`Armur-Ai/Pentest-Swarm-AI`) | `fd48e2bd26516b82584a84350a0b459d97c007d6` | AGPL-3.0 |
| Shannon (`KeygraphHQ/shannon`) | `d72c082dc873273cb99ea53bdec1c582c2493753` | AGPL-3.0 |

SHA drift: `docs/research/reference-workflows.md` pins older commits for ARTEX
(`ab40834`), Shannon (`f22a9cb`) and Swarm (`c077a76`). The SHAs above are the
ones this trace actually read. Do not mix line numbers across the two documents.

## Libella baseline (what the comparison is against)

All **[S]**, `src/libella/` at `f0b4a8d`:

* **Loop** — one ReAct loop per intent, per chartered role:
  `agent_runtime.py:28` `CHARTERS` (charter prose + allowed action list +
  `max_iterations`), `:491` `AgentRunner.run` (while `iterations < max_iter`),
  `:136` `ACTION_SCHEMA` (one JSON action per turn), `:584` duplicate-action
  guard, `:472` `finish` refuses a run that produced no evidence.
* **Planning** — `orchestrator.py:183` `_plan_deterministic`, `:226`
  `_plan_llm` (max 4 extra intents, compile gate), `:264` `_plan_agent`
  (specialist intents at start only). Re-planning happens only in `llm` mode
  and only when the frontier is empty (`:357`). Intents are leased with a
  fencing token (`:398` `_claim_next`, `:33` `LEASE_S`, `:382` `_complete`).
* **Tools** — `tools/__init__.py:11` `ToolSpec` (typed params, `target_param`,
  `port_param`, `destructive`), `Registry.register`, `tools/runner.py:40`
  `ToolRunner.run` (validates params, resolves the dialled parameter, checks
  scope, builds argv, no shell). Plugins may add `ToolSpec`s from a manifest at
  startup (`plugins.py:1`, `api.py:87-91`).
* **Memory** — SQLite tables `intents`, `agent_runs`, `investigation_steps`,
  `hypotheses`, `observations`, `findings`, `evidence`, `memory_facts`
  (`db.py:20-128`); per-turn working memory is rebuilt from the DB
  (`agent_runtime.py:479` `_context`, `:534` `workmem`); cross-engagement
  `memory_facts` exist but are only exposed by `api.py:780` (`mem.recall`).
* **Standard** — `coverage.py:20` `FRAMEWORK` (WSTG 4.2), `:39` `CATALOG`,
  `check_mapping.py:10` `ROWS` (unit → WSTG ids, with `why`), `:129`
  `NOT_SUPPORTED`, `:138` `MANUAL_REASONS`. This is a **ledger** derived from
  recorded execution (`coverage.py:266` `_derive`), not a planner input.
* **Verification** — `verifier.py:79` `Verifier.verify` replays the bound
  proof request through the scoped probe, compares a verbatim quote against the
  fresh body/headers (`:166` `_compare`), treats WAF/challenge pages as
  inconclusive (`:104`), re-checks TLS facts (`:136`), and only promotes
  `validated` on reproduction; `:225` `retest` adds corroboration before
  claiming a fix.
* **Scope** — `scope.py:15` `ALWAYS_BLOCKED` (metadata/link-local), `:228`
  `check_url` (DNS resolve, exclusions, ports, categories), `:301`
  `check_host_port`, `:279` `authorized_ports`; `policy.py:20` `MIN_PROFILE`,
  `:48` `permits`. Enforcement points: `AgentRunner._refused` (`:173`),
  `HttpProbe.request` per redirect hop (`tools/http_probe.py:144`),
  `ToolRunner.run` pre-flight (`tools/runner.py:78-84`).
* **Drive** — FastAPI + React (`api.py`, `web/`), `api.py:318` resume restarts
  `_run_loop` over open intents.

Two limits of the baseline matter for every comparison below:

1. The agent carries only `history[-1]` plus a rebuilt workmem dict between
   turns (`agent_runtime.py:540`, `:534`); the conversation itself is not
   persisted, so a restart resumes intents, not reasoning.
2. Subprocess tools are scope-checked **before launch only**; the child then
   has ordinary network access (`tools/runner.py:180` `_run_capped` sets
   `start_new_session`, PATH and HOME — no network namespace, no proxy).

---

## 1. PentAGI (`cffed948`)

### (a) Verified mechanism

1. **Next action.** A per-subtask agent chain, not a graph. `providers/provider.go:708`
   `PerformAgentChain` assembles the chain's handlers (adviser, coder, installer,
   memorist, pentester, searcher; the summarizer is resolved separately in
   `performAgentChain`) and runs the chosen chain;
   `providers/performer.go:58` `performAgentChain` is the loop (`:116`
   `for iteration := 0; ; iteration++`), calling the model, executing tool calls
   one at a time (`:282` `execToolCall`). Task decomposition is itself a model
   call before this loop (`templates/prompts/subtasks_generator.tmpl`,
   `generator.tmpl`); subtasks are rows, edited by the `subtask_list` /
   `subtask_patch` tools (`tools/registry.go:11-52`). **[S]**
2. **Tools.** A compile-time set: tool names are Go constants
   (`tools/registry.go:11-52`) bound to handlers in `tools/tools.go:856`
   (`TerminalToolName: term.Handle`). A model cannot gain a new tool at runtime.
   What *can* change at runtime is the container's installed binaries: the
   `installer` agent installs packages and verifies them
   (`templates/prompts/installer.tmpl:79` `<installation_verification>`), and
   the `terminal` tool then runs them (`tools/terminal.go:125` `Handle`). **[S]**
3. **Context/memory.** Three layers: per-task/subtask message chains in
   Postgres (`database/msgchains.sql.go`, updated after every step by
   `performer.go:918` `updateMsgChain`), a pgvector "guide/answer/code" memory
   with tools `search_in_memory` / `search_guide` / `store_guide`
   (`tools/memory.go:29,50`; `database/knowledge.sql.go`), and an optional
   Neo4j/Graphiti temporal graph queried by `graphiti_search`
   (`tools/graphiti_search.go:36`; written by `performer.go:979`
   `storeToGraphiti`). Context-window pressure is handled by compaction
   (`providers/window_compaction.go`, invoked at `performer.go:136-150`). **[S]**
4. **Plans from a standard.** None found. The prompt corpus
   (`templates/prompts/*.tmpl`) contains no WSTG/PTES/OWASP test identifiers
   (`grep -r "WSTG\|PTES\|OWASP" templates/prompts` → no matches). Planning is
   free-text task decomposition. **[S]**
5. **Verification.** No independent verifier. `reflector.tmpl:1` is a "TOOL
   CALL WORKFLOW ENFORCER" that rewrites plain-text answers into tool calls,
   not a fact checker. The only adversarial role is the mentor/"execution
   monitor" progress review (`performer.go:401`), which reviews progress, not
   evidence. Findings are whatever the pentester writes in `hack_result`. **[S]**
6. **Incomplete/budget.** Hard iteration ceiling per chain: `performer.go:38`
   `maxLimitedAgentChainIterations = 20`, overridable by
   `MAX_LIMITED_AGENT_TOOL_CALLS` (`config/config.go:317`). The last three
   iterations are a shutdown window in which the reflector is invoked to
   terminate gracefully (`performer.go:124-137`). Exhaustion returns an error
   (`ErrAgentModelCall`), not a partial result. **[S]**
7. **Authorization/scope.** Not enforced. `grep -rn "scope" backend/pkg`
   returns only tenant/Docker-name and SQL user scoping; there is no target
   allowlist, no egress check, no per-request gate. Authorization is prompt
   text: `templates/prompts/pentester.tmpl:5-11` states the engagement is
   "PRE-AUTHORIZED … Never request permission". Tools run in the worker
   container with ordinary network access. **[S]**
8. **Driving/resume.** React frontend over a GraphQL API with subscriptions
   (`backend/pkg/graph/schema.graphqls`); flows, tasks, subtasks and message
   chains are database rows, so a restart can continue a waiting task
   (`controller/flow.go:1430`, "tasks … being resumed (e.g. after waiting)"). **[S]**

### (b) Gap or match in Libella

* **Match, weaker:** both keep durable step/chain records. PentAGI persists the
  full LLM message chain per subtask; Libella persists one-line step summaries
  plus the DB projections, not the conversation (`agent_runtime.py:206`
  `_step`).
* **Gap:** Libella has no memory tier the agent can query. PentAGI's memorist
  is a *role* with vector + graph search tools; Libella's `memory.recall` is
  never called by the runtime (only `api.py:780`).
* **Gap:** no runtime tool installation. Libella's plugin dir is read at app
  start (`api.py:87-91`); the agent's `run_tool` prompt is hard-coded to five
  binaries (`agent_runtime.py:504`), so even registered plugin tools are
  invisible to it.
* **Difference:** no code-level scope enforcement was found in the traced PentAGI
  paths (scope is prompt text there); Libella has a scope object, policy profiles
  and a per-hop HTTP check. No comparative test was run.

### (c) Smallest change, ranked

* **P0 — none from this reference.** Do not import its authorization model.
* **P1 — make recall real:** in `AgentRunner._context`
  (`agent_runtime.py:479`), add `memory.recall(self.db, target)` for the
  intent's target and include the top 5 facts (with `source_engagement_id` and
  `last_seen`) in `workmem`. ~6 lines, reuses the existing table.
* **P1 — expose registered tools to the agent:** replace the hard-coded tuple
  at `agent_runtime.py:504` with `[s.schema() for s in self.registry.tools.values()
  if s.category in ... and permits(s.name, self.profile)]`. Kills the plugin
  blind spot without a new subsystem.
* **P2 — persist the turn, not just the summary:** extend `_step` writes with
  the action args/result (a `detail_json` column), so a resumed intent can seed
  `history` from the last N steps. This is the cheap half of PentAGI's message
  chain.

---

## 2. Strix (`a1ccf77`)

### (a) Verified mechanism

1. **Next action.** The outer loop is Strix's; the inner turn loop is the
   `openai-agents` SDK. `core/execution.py:235` `run_agent_loop` →
   `:542` `_run_until_lifecycle` drives turns until a lifecycle tool settles the
   agent (`finish_scan`, `agent_finish`, `wait_for_user`, `wait_for_agents`;
   map at `agents/factory.py:568`). Each turn is
   `:799` `Runner.run_streamed(...)`, i.e. the SDK's tool-calling loop with a
   `max_turns` cap. A turn that ends in plain text is nudged back into a tool
   call (`:992` `_append_tool_required_message`); repeated failure is
   `:661` `_exhausted_recovery`. Subagents are spawned concurrently
   (`:391` `spawn_child_agent`) and coordinated by `AgentCoordinator`
   (`core/agents.py`), with messages and a shared agent graph
   (`tools/agents_graph/tools.py`). **[S]**
2. **Tools.** A fixed base tuple `agents/factory.py:639` `_BASE_TOOLS`
   (notes, todos, coverage, reporting, proxy/Caido, agent graph, MCP meta-tools)
   plus `Shell`/`Filesystem` capabilities attached to a `SandboxAgent`
   (`:821-840`). Extra tools can be registered **programmatically before**
   agents are built (`:704` `register_agent_tools`), not during a run. Runtime
   discovery is MCP-shaped: connections are registered in `McpRegistry`
   (`tools/mcp/registry.py:327`, catalog `:206` `ensure_catalog`) and the agent
   gets `search_mcp_tools` / `get_mcp_tool_schema` / `call_mcp`
   (`tools/mcp/agent_tools.py:168,225,261`) instead of the tools being injected
   into its schema. **[S]**
3. **Context/memory.** Each agent gets a SQLite session
   (`core/sessions.py:38` `open_agent_session` → `agents.memory.SQLiteSession`,
   `_PooledConnectionSession`), stored under the run's state dir
   (`core/paths.py`, `strix_runs/<run>/.state`). Compaction is proactive
   (`llm/compaction.py`, called at `core/execution.py:794`), image budget is
   enforced separately (`:790`). Cross-agent context is deliberate: notes
   (`tools/notes/tools.py:1`, mirrored to `{state_dir}/notes.json`) and
   parent history handed to a child (`spawn_child_agent(... parent_history ...)`,
   `core/execution.py:391`). **[S]**
4. **Plans from a standard.** Skills, not a plan compiler. Markdown skills live
   at `strix/skills/<category>/<name>.md` and are loaded on demand by
   `load_skill` (`tools/load_skill/tool.py:9`) or assigned to a child at
   creation (`create_agent(skills=…)`). The package-level `skills/` tree holds
   longer playbooks (e.g. `skills/owasp-top-10-testing`). Nothing maps a
   standard's test ids to executable checks. **[S]**
5. **Verification.** Report-time validation, not replay:
   `tools/reporting/tool.py:231` `_verify_http_exchange_ids` checks that cited
   Caido exchange ids exist; `:303` `_validate_analysis_fields` forces a
   `counterevidence` string and a `confidence_rationale` when confidence is not
   `high`; `:274` validates the CVSS breakdown. The claim itself is never
   re-executed. **[S]**
6. **Incomplete/budget.** Budget is enforced at the model-call boundary
   (`core/hooks.py` `BudgetExceededError` / `BudgetPausedError`), with a
   sub-agent reserve (`core/execution.py:301-307`) and stop/pause policy
   (`core/runner.py:225` `budget_policy`). Coverage is reconciled at finish:
   `tools/finish/tool.py:86` `_coverage_summary` warns when no coverage was
   recorded and lists gaps (`strix/report/coverage.py`). **[S]**
7. **Authorization/scope.** Prompt and container, not transport. The scope
   block is rendered from run inputs (`agents/prompts/scope.jinja`,
   `agents/prompt.py:161` `render_scope_prompt`) and `core/inputs.py:170`
   computes `has_scope` for prompt text. The sandbox container gets
   `NET_ADMIN`/`NET_RAW` (`runtime/docker_client.py:14,251-257`) and an optional
   docker network (`:57-65`); no per-target allowlist exists in the traced
   paths. `scope_rules` (proxy tool) edits Caido's display scope, not egress. **[S]**
8. **Driving/resume.** CLI/TUI + web viewer. `--resume <run>` reopens a run
   directory (`interface/cli_args.py:324,494` `load_resume_state`; run dirs from
   `core/paths.py`), and the SQLite session restores conversation state. **[S]**

### (b) Gap or match in Libella

* **Gap:** Libella has no session store. Strix's per-agent SQLite session plus
  notes is exactly the missing "carry reasoning across turns/restarts" layer
  (`agent_runtime.py:540` keeps only `history[-1]`).
* **Gap:** no hot/in-run tool discovery. Libella's registry is static per boot;
  Strix's MCP catalog is queried at run time and called through meta-tools.
  (Libella does not need MCP to close this; a tool listing is enough — see 1(c).)
* **Gap:** no coverage reconciliation at finish inside the agent. Libella's
  coverage ledger is recomputed post-hoc from DB state (`coverage.py:304`) and
  is honest, but the *agent* is never told what it failed to cover; Strix's
  `finish_scan` returns coverage gaps to the model and the report.
* **Difference, not a ranking:** verification. Strix checks that cited exchange
  ids exist in the proxy project and carries counter-evidence and fix-verification
  as prompt-level skills; Libella replays the proof request (`verifier.py:79-122`).
  No comparative test was run, so neither is claimed to be more accurate.
* **Match:** both use lifecycle tools to end a run and refuse plain text as a
  terminal state (`agent_runtime.py:472` vs `core/execution.py:542`).

### (c) Smallest change, ranked

* **P0: none identified** for verification (no comparative test exists).
* **P1 — persist the ReAct transcript:** a `agent_messages(run_id, seq, role,
  content_json)` table written beside `_step`, and on `AgentRunner.run` seed
  `history` from the last 10 rows when an intent is retried after a crash.
  This is the cheap version of Strix's SQLite session and also fixes PentAGI's
  P2 item.
* **P1 — tell the agent what is uncovered:** when a run is about to finish,
  call `coverage._derive` for the in-scope WSTG ids and put the `requires_manual`
  / `not_supported` counts in the finish result (one query, no new table).
* **P2 — explicit subagent budget:** a per-intent child cap (count intents with
  `parent_id = intent_id` and refuse `delegate` past N). Strix reserves budget
  for children; Libella's `delegate` (`agent_runtime.py:450`) is unbounded.

---

## 3. ARTEX (`2411943`)

This is the closest architectural reference to Libella: planner/worker split,
leased intents, a coverage ledger, a budget ledger with wrap-up, and a real
transport gate.

### (a) Verified mechanism

1. **Next action.** Event-driven planner + workers. `agent/planner.go:24`
   `Planner` is "the sole intent generator", woken on every (debounced) graph
   change (`:477` `Plan`); its prompt is `:417` `plannerDefaultTmpl` ("read the
   situation → judge the goals → add exploration intents only when there is a
   genuinely uncovered new direction"). A per-task todo scratchpad survives
   wake-ups (`planner.go:43-55`, `todos map[int64]*actool.TodoStore`), and
   serial exploit chains are dispatched step by step (`:454` prompt rules).
   Workers execute intents (`agent/worker.go:63` `Worker`), goals are
   decomposed up front (`agent/goals.go:99` `DecomposeGoals`). **[S]**
2. **Tools.** A code-defined catalog made runtime-editable in two dimensions.
   `agent/toolcatalog.go:9` `ToolSeed` expands built-in tools into DB rows;
   `ToolResolve` filters by agent binding and overrides description/schema/
   defaults at runtime, while handlers stay in code (`:10-20` comment). A
   lexical "tool RAG" projects the bound list to the top-k relevant tools
   (`agent/toolrag.go:15`, core tools always kept). MCP servers contribute
   tools as `mcp__server__tool` (`mcphttp/client.go:1-40`,
   `agent/assembly.go:29`), so a new remote tool needs a DB row, not a deploy. **[S]**
3. **Context/memory.** Postgres exploration/asset stores are the shared state;
   every LLM session can be persisted (`transcript.Store`, passed to planner,
   worker and main agent) and resumed (`agent/session.go:14` `resumeSession`).
   Compaction turns cold turns into summary nodes (`agent/compaction.go`,
   `agent/coldgraph.go`). A "lessons" block from prior outcomes is injected
   into the planner (`planner.go:116` `SetLessonsBlock`). Workers inherit task
   context (blackboard inheritance tests, `agent/blackboard_inheritance_test.go`). **[S]**
4. **Plans from a standard.** Skills as documents (`skills/*/SKILL.md`, loaded
   via `server/assembly.go:27`), plus a coverage ledger (`agent/coverage_ledger.go:13`
   `recordCoverage`, outcomes `reported|no_issue_found|ruled_out|not_applicable|
   needs_follow_up`). No WSTG/PTES mapping was found in the traced Go code or
   skills (`grep -rn "WSTG\|PTES" agent skills` → no matches). **[S]**
5. **Verification.** Evidence binding plus adversarial self-check, no replay.
   `agent/finding_workflow.go:82` instructs that "unverified candidates must not
   be passed as evidence" and requires traffic refs in reproduction order;
   `report_finding` demands a reproducible PoC (`agent/promptcatalog.go:60`,
   "strictly forbidden to report as confirmed anything inferred solely from
   version/CVE matching"). The solo agent is told to re-trigger via an
   independent path (`:44`). A dedicated retest agent does exist for filed
   findings (`agent/retester.go`, `server/finding_retests.go`), and a receipt
   check (`server/finding_verification.go`); both were found in a later read of
   the `0255f6a` checkout. This trace's earlier statement that no separate verify
   role exists was wrong for retests. **[S]**
6. **Incomplete/budget.** A budget ledger with a wrap-up phase.
   `agent/budget.go:36` `Budget{Tokens,Turns}`, `:97` `BudgetLedger`,
   `:164` `BeginWrapup`, `:230` `BudgetWrapupBlocks`; the settlement prompt and
   turn count come from `agent/wrapup.go:134` `wrapupSettlement` (defaults
   `:92` `WrapupDefault`). The prompt carries a deadline contract
   (`promptcatalog.go:66`). **[S]**
7. **Authorization/scope.** The strongest traced model, and explicitly *not*
   RoE scope: `guard/guard.go:1-6` says "The RoE authorization-scope mechanism
   was removed; a replacement may be added later." What remains is (i) an
   audit/intercept hook on every tool call (`guard.go:84` `preToolUse`,
   `:150` `applyIntercept`), (ii) a target gate that requires human-approved
   "pins" per host:port (`intercept/target_gate.go:1-33`,
   `intercept/target_request.go`), and (iii) `intercept/target_dial.go:41`
   `PinnedDialer`, which re-resolves the name at connect time, compares the
   answer with the pins and connects only to the compared address — closing the
   DNS-rebinding/redirect gap that a URL check alone leaves open. Platform-owned
   HTTP clients use that dialer (`agent/webfetch_dialer_test.go`), and redirect
   hops are gated (`intercept/target_redirect.go`). Separately, `egress/egress.go:1`
   is a rate/jitter/concurrency governor, not an allowlist. **[S]**
8. **Driving/resume.** Web UI (`web/`) over a server API; tasks/intents/facts
   live in Postgres so a restart continues from the store. An intent can pause
   for operator input and resume with the answer (`server/ask_operator.go:31-82`). **[S]**

### (b) Gap or match in Libella

* **Gap (the important one):** Libella checks scope at the URL/launch boundary;
  ARTEX checks it again at the socket, on the address actually dialled
  (`target_dial.go:41`). Libella's HTTP path is close (per-hop `check_url` in
  `http_probe.py:144`), but `_run_capped` subprocesses are not confined
  (`tools/runner.py:180`), and a scanner that follows a redirect or resolves a
  new name is outside the decision Libella made.
* **Gap:** no wrap-up phase. Libella's agent stops at `max_iterations`
  (`agent_runtime.py:614`) or budget (`:558`), then the orchestrator verifies
  and reports (`orchestrator.py:434-460`) — honest, but the agent never spends
  its last turns consolidating findings. ARTEX's `BeginWrapup` is the pattern.
* **Gap:** no lessons/memory injection into the planner; no tool-RAG or
  runtime-editable tool catalog (Libella's plugins are boot-time only).
* **Difference, not a ranking:** Libella's `Verifier` replays the proof request;
  ARTEX binds recorded traffic, runs a receipt check (`server/finding_verification.go`,
  quotes must appear verbatim in a bound response body) and has a dedicated retest
  agent (`agent/retester.go`, `server/finding_retests.go`) that re-runs a minimal
  PoC and saves a reproduced, fixed or inconclusive verdict. No comparative test was run.
* **Match:** both lease intents and keep a coverage ledger; ARTEX's ledger is
  agent-written per surface (`recordCoverage`), Libella's is derived from
  evidence (harder to fake).

### (c) Smallest change, ranked

* **P0 — confine subprocess egress, or refuse tools that cannot be confined.**
  Smallest honest step: add a `network_unbounded: bool` to `ToolSpec`
  (`tools/__init__.py:11`) for adapters that follow redirects/recurse
  (nuclei, ffuf), and in `ToolRunner.run` refuse them unless the engagement
  profile is `safe_active` **and** the adapter passes an explicit
  `-no-redirect`/`-ac` equivalent. Document the residual in the report
  limitations. (A CONNECT proxy or netns is the real fix, but is not the
  smallest change.)
* **P1 — wrap-up turn:** when `iterations >= max_iter - 2` or cost ≥ 90 % of
  `max_usd`, restrict `actions` to `record_observation|propose_finding|finish`
  and add one system line asking for consolidation. Localized change in
  `AgentRunner.run`; no schema change.
* **P1 — target gate on redirects for non-HTTP tools:** pass
  `follow_redirects=False` semantics into adapters where the binary supports it,
  and record the flag in the tool call row so coverage can say "redirect not
  followed".
* **P2 — tool catalog from the registry** (same as 1(c)); ARTEX's DB-override
  layer is not worth copying at Libella's size.

---

## 4. HexStrike AI (`d689933`)

### (a) Verified mechanism

1. **Next action.** There is no agent loop. The repository is two files: a
   Flask tool server (`hexstrike_server.py`, 734 KB, 156 `@app.route`s) and an
   MCP stdio client (`hexstrike_mcp.py`, 218 KB, 151 `@mcp.tool` wrappers) that
   exposes each route as a tool to an external LLM client. "Planning" is
   `hexstrike_server.py:572` `IntelligentDecisionEngine`, a lookup table:
   `:971` `select_optimal_tools(profile, objective)` scores tools from
   `_initialize_tool_effectiveness` (`:581`) and `:1462` `create_attack_chain`
   emits a fixed `AttackChain`. `TargetProfile` comes from local heuristics
   (`:811` `analyze_target`). **[S]**
2. **Tools.** Adding a tool means writing a Flask route and an MCP wrapper
   function — two edits and a restart; there is no registry, manifest or
   discovery path. **[S]**
3. **Context/memory.** None. The server is stateless per request apart from
   in-process caches and a process table (`/api/cache/*`, `/api/processes/*`,
   `@app.route` list at `:9268-9392`); no conversation, no findings store, no
   cross-run state. **[S]**
4. **Plans from a standard.** Hard-coded workflow step lists, not a standard.
   Example: a CTF chain literal at `:3227` (`{"step": 8, "action":
   "flag_extraction", …}`), and bug-bounty workflow managers that return
   predefined phases (`:3279`). **[S]**
5. **Verification.** None. Output parsing is per-tool; the only validator found
   is a CTF flag format check (`:4003` `_validate_flag_format`). **[S]**
6. **Incomplete/budget.** None. Per-command timeout only
   (`:5236` `execute_command_async`, `subprocess` at `:5272`). **[S]**
7. **Authorization/scope.** None, and this is the "what not to copy" case.
   `:5272-5275` runs `subprocess.Popen(..., shell=True)` with model-supplied
   arguments; `/api/command` (`:9137`) executes arbitrary commands; no
   authentication middleware was found in the server (`grep -n
   "before_request\|require_auth" hexstrike_server.py` → no matches). There is
   no target allowlist anywhere. **[S]**
8. **Driving/resume.** An MCP config file (`hexstrike-ai-mcp.json`) points the
   user's LLM client at the stdio server; no state to resume. **[S]**

### (b) Gap or match in Libella

* **Match, weaker:** Libella's deterministic intent roles are also a fixed
  routing table, but the agent layer on top can choose among typed actions.
* **Difference:** Libella uses scope checks, typed tools (`ToolSpec` + argv, no
  shell), replay verification and a persisted state; none of these was found in
  the traced HexStrike paths. No comparative test was run. HexStrike is a
  cautionary reference for the design, not a model.
* **Gap worth noting:** HexStrike's *tool surface breadth* (156 routes) is
  wider than Libella's adapters. Breadth is not the missing mechanism, but it is
  why the project is popular; Libella's answer should stay typed adapters, not
  a generic command runner.

### (c) Smallest change, ranked

* **P0 — none.** Nothing here should be copied.
* **P2 — breadth via plugins, not code:** keep `ToolSpec` as the only way to add
  a tool (`plugins.py`), and add a `LIBELLA_PLUGIN_DIR` example pack rather than
  a `/api/command` escape hatch. Any request to add a "run arbitrary command"
  tool should be refused on scope grounds.

---

## 5. Pentest-Swarm-AI (`fd48e2b`)

### (a) Verified mechanism

1. **Next action.** Stigmergic blackboard + predicate-triggered agents.
   `internal/swarm/blackboard/types.go:1-9`: "Agents read and write findings
   tagged with a type; their trigger predicates wake them when relevant state
   appears. Pheromone weights decay over time." `internal/swarm/agent.go:19`
   `Agent{Name, Trigger, MaxConcurrency, Handle}`; `internal/swarm/scheduler.go:149`
   `Run` subscribes to the board and launches an agent when its predicate
   matches; `internal/engine/swarm_runner.go:113` `RunSwarm` registers the
   agents (recon, classifier, exploit, report, …). **[S]**
2. **Tools.** A Go interface registry: `internal/tools/base.go:8`
   `Tool{Name, Run, IsAvailable}`; `internal/tools/coordinator.go:126` `RunAll`
   and `:189` `RunSelected` filter by `IsAvailable()`; `internal/toolprobe`
   probes binaries. A new tool is a Go type registered in code; there is no
   runtime addition (MCP exists as a client, `internal/mcp/`). **[S]**
3. **Context/memory.** Two stores: the blackboard (durable via
   `internal/swarm/blackboard/postgres.go`; in-memory fallback in `board.go`)
   and a JSON-backed keyword memory (`internal/memory/store.go:20`
   `MemoryStore`, `:42` `RecallRelevant(keywords)`, `persist.go:26/50`
   `Load`/`Persist`). Campaign context can be imported as a pack
   (`internal/ctxpack/ctxpack.go:51` `Load`). Retrieval is keyword matching,
   not embeddings. **[S]**
4. **Plans from a standard.** No. Taxonomy maps findings *back* to OWASP Top 10
   2021 + CWE for reporting (`internal/taxonomy/taxonomy.go:2-40`) and
   compliance maps categories to controls (`internal/compliance/compliance.go:2`).
   Coverage is a report-honesty computation (`internal/coverage/coverage.go:1-30`:
   recon observations, endpoints, blocked signals → confidence level), not a
   plan. **[S]**
5. **Verification.** The most interesting model of the six: cost-aware active
   corroboration. `internal/swarm/verify/verify.go:1-40` promotes/rejects a
   cheap agent's signal at a handoff; `oracle.go:1-35` defines an `Oracle` that
   returns a hard verdict from a signal outside any model (OOB callback fired,
   differential response, timing threshold), consulted only for high-stakes
   uncorroborated claims under a per-campaign cap. `internal/swarm/quality`
   is the passive gate; `agents/confirmation.go` implements confirmation flows. **[S]**
6. **Incomplete/budget.** Pause-on-budget that still produces a report:
   `scheduler.go:183-215` — when the budget is hit, the enforcer writes a
   `CAMPAIGN_COMPLETE` finding to the blackboard, which fires the report agent,
   so the run ends with a partial report instead of nothing. **[S]**
7. **Authorization/scope.** Real, and layered. `internal/scope/validator.go:24`
   `Validate(target)` (host/IP/domain/port, scheme), `:187` `ValidateCommand`
   (extracts targets from a shell command), plus `internal/scope/watcher.go`
   (program-term changes) and `programterms/`. At the socket,
   `internal/scope/egress.go:22` `ScopedDialContext` refuses an out-of-scope
   `host:port` in `DialContext` — explicitly "a last-line EGRESS guard"; the
   comment also states the honest limit: external subprocesses are bounded only
   by command validation, and a kernel-level jail is the commercial tier. **[S]**
8. **Driving/resume.** Cobra CLI (`cli/`, `cmd/pentestswarm/main.go` →
   `cli.Execute`): `scan`, `run`, `report`, `scope`, `workspace`, `serve`,
   `tui_run`, `mcp`, `doctor`. `workspace` is a named config, not a run
   checkpoint; no `--resume` flag was found, and the state that survives is
   whatever the blackboard/DB persisted. **[S]**

### (b) Gap or match in Libella

* **Gap:** Libella's agents are not event-triggered. The orchestrator runs a
  frontier of intents; nothing wakes a specialist because a *fact* appeared
  (a new endpoint, a leaked object id). Swarm's `OBJECT_REF` finding type
  (`blackboard/types.go:44-48`) is exactly the "react to a discovery" mechanism
  Libella's `record_observation`/`hypothesis` rows could feed.
* **Gap:** no oracle layer. Libella's replay verifier covers HTTP facts but has no OOB-callback or timing oracle; Swarm shows how to keep
  that cost-bounded.
* **Gap:** Libella has no report-on-budget path *inside* the agent run; it does
  verify+report after (`orchestrator.py:434`), which is equivalent in outcome
  but loses the agent's own consolidation.
* **Match:** Libella's scope check is comparable to Swarm's
  `Validate`; Libella has an `ALWAYS_BLOCKED` metadata range and no equivalent was
  found in the traced Swarm paths.
  Libella's subprocess gap is the same one Swarm documents.

### (c) Smallest change, ranked

* **P0 — adopt the documented limit, not the aspiration:** add a line to the
  report limitations when any `network_unbounded` tool ran (see 3(c)), and add
  `ScopedDialContext`-style checking to the one place Libella owns the socket —
  `HttpProbe` already does it per hop; the missing case is the browser path
  (`browser_request`, `http_probe.py:196`) and subprocesses.
* **P1 — fact-triggered intents:** when `record_observation` or
  `propose_finding` stores an object identifier (id/uuid/email in an endpoint or
  quote), create one `authz` intent to replay it across sibling endpoints, capped
  at one per identifier. Small, and it is the cheapest "react to discovery"
  mechanism among the six.
* **P1 — one OOB oracle for SSRF/XXE-class findings:** reuse the existing
  `ssrf` check marker (an in-scope internal URL) as an oracle verdict recorded in
  `verifications` (`method='oob'`), so `validated` can rest on a callback rather
  than a body quote where the class allows it.

---

## 6. Shannon (`d72c082`)

### (a) Verified mechanism

1. **Next action.** A durable Temporal workflow with a fixed stage graph.
   `apps/worker/src/temporal/workflows.ts:380` `pentestPipeline` orchestrates
   activities; agents are declared with prerequisites in
   `apps/worker/src/session-manager.ts:20` `AGENTS` (`pre-recon` → `recon` →
   five per-class vuln agents → exploit → report). Per-class fan-out is
   `workflows.ts:736-780` (`injection`, `xss`, `auth`, `ssrf`, `authz`, plus a
   `miscellaneous` lane at `:1107`). Each agent is still a tool-using loop
   (`runPiPrompt`), but which agent runs, in what order and with which class is
   decided by the workflow, not by a free-running planner.
2. **Tools.** Each agent runs through the `pi` coding agent
   (`services/agent-execution.ts` → `runPiPrompt`, `ai/pi/pi-executor.ts`) with
   a fixed prompt template and a `submit_result` tool whose schema is
   per-class (`ai/queue-schemas.ts`, `createQueueSubmitTool`); custom tool
   definitions can be passed per execution (`customTools`,
   `agent-execution.ts:61`). No MCP and no runtime tool discovery. **[S]**
3. **Context/memory.** Durable by construction: each agent writes a deliverable
   file (`AGENTS[...].deliverableFilename`, `session-manager.ts:20-60`), git
   checkpoints are taken per attempt (`services/git-manager.ts`,
   `createGitCheckpoint`), and Temporal's event history is the workflow state.
   A workspace's `session.json` records the authoritative session/workflow ids
   (`apps/cli/src/session.ts:6-23`). **[S]**
4. **Plans from a standard.** Five fixed vulnerability classes, each with its
   own prompt (`apps/worker/prompts/vuln-injection.txt`, `vuln-xss.txt`,
   `vuln-auth.txt`, `vuln-ssrf.txt`, `vuln-authz.txt`; exploit and
   sast-enrichment prompts per class). The classes are OWASP-adjacent, not
   WSTG ids; the plan is the class list, not a standard's catalogue. **[S]**
5. **Verification.** A reconciliation pipeline between analysis and
   exploitation: `workflows.ts:644` `reconcileClass` runs
   prepare → enrich → form → materialize → publish
   (`ai/reconciliation/{prepare,enrich,form,materialize,publish}.ts`), joining
   vulnerability-analysis observations with SAST SARIF so every reported
   location traces to a pinned file/line
   (`ai/reconciliation/contracts.ts:23-31` `SastSourceLocation`). Structured
   answers are validated before capture (`ai/reconciliation/submit-validation.ts:1-40`,
   closed schema + retry). A finding is reported only after the exploit agent
   produced a PoC. This is evidence reconciliation, not request replay. **[S]**
6. **Incomplete/budget.** Partial results are first-class: `partialReasons`
   are appended throughout (`workflows.ts:444` `addPartialReason`), failed
   classes are tracked (`failedClasses`, `agent-execution.ts:62`), and the
   summary carries `status: 'partial'` with typed codes. Resume is a Temporal
   workflow restart that adopts prior work (`workflows.ts:410-411`,
   `resumeFromWorkspace`, `sessionId`). **[S]**
7. **Authorization/scope.** No target-scope engine was found. The scope that is
   enforced is the *analysis* scope: `types/run-state.ts`
   `assertFixedAnalysisScope` fixes the vulnerability classes so a prompt cannot
   widen them. Targets come from config (URL + repo) and tools run in the
   worker container; there is no per-host allowlist or egress gate in the traced
   paths. **[S]**
8. **Driving/resume.** CLI (`apps/cli/`, commands + `workspaces.ts`, `run-limits.ts`)
   over a Temporal server; `--workspace <name>` auto-resumes an existing
   workspace (help text, `apps/cli/src/help.ts:34`), and each resume is a new
   workflow id recorded in `session.json`. **[S]**

### (b) Gap or match in Libella

* **Gap:** Libella has no durable stage graph. Its intents are a DAG in SQLite
  with leases, which is close, but an agent run is a single opaque step: if the
  process dies mid-run, the intent is re-opened and re-executed from scratch
  (`orchestrator.py:368-373` reopens on pause; `_sweep_leases` at `:424` on
  expiry), losing the agent's conversation.
* **Gap:** no partial-result vocabulary at the agent level. Libella has
  `exit_reason` (`agent_runtime.py:616`) and degradation events, but a run that
  hit `max_iterations` is recorded as `status=blocked` at intent level
  (`orchestrator.py:484-490`) with the detail in a degradation event; Shannon's
  typed `partialReasons` is a cleaner report input.
* **Gap:** no reconciliation stage between "agent proposes" and "finding
  exists". Libella verifies by replay; Shannon additionally reconciles against a
  second, independent source (SAST) and pins the location. That is a model for
  code-audit findings, which Libella cannot replay.
* **Difference:** Libella has a runtime target scope check, and none was found in
  the traced Shannon paths. Verification differs in kind (replay against
  reconciliation with SAST); no comparative test was run.

### (c) Smallest change, ranked

* **P0 — none** (do not take Temporal or the git-checkpoint machinery; too much
  infrastructure for a single-process app).
* **P1 — typed partial reasons:** replace ad-hoc `degradation` codes at run end
  with a small enum stored on `agent_runs` (`exit_reason` already exists —
  extend its values: `budget|max_iterations|model_failed|no_action|converged`)
  and include the list in `report.py` limitations. Mostly wiring, no new store.
* **P1 — code-audit reconciliation:** for `code_audit` findings, require a
  `file:line` in the evidence and add a second, independent check (a second
  static pass or a targeted grep) before `validated`; replay does not exist for
  source findings, so today they can only reach `observed`. This mirrors
  Shannon's SARIF+observation join at a fraction of the cost.
* **P2 — resumable agent turn:** same as 2(c); Shannon's answer (durable
  workflow) is the expensive version of the same requirement.

---

## Summary table

Mechanism per platform; "—" means the mechanism is absent in the traced code.
`Libella` column is the current implementation at `f0b4a8d`.

| Question | PentAGI | Strix | ARTEX | HexStrike | Swarm | Shannon | Libella |
|---|---|---|---|---|---|---|---|
| Next action | per-subtask chain loop, 7 handler roles | SDK turn loop + lifecycle tools, coordinator | event-driven planner + leased workers | static decision table + external MCP client | blackboard predicates + scheduler | Temporal stage graph | ReAct per intent, leased intents |
| New tool at runtime | no (installer adds binaries) | MCP catalog via meta-tools; programmatic register pre-build | DB-bound catalog + tool-RAG; MCP rows | no (route + wrapper) | no (Go registry) | no (per-exec custom tools) | plugin dir at boot; agent sees 5 hard-coded |
| Memory across agents/restarts | msgchains + pgvector + Graphiti | SQLite session per agent + notes | transcript store + exploration DB + lessons | — | blackboard (PG) + keyword memory | deliverables + git + Temporal history | SQLite rows; conversation not persisted |
| Plan from standard | — (free text) | skills (markdown) | skills + coverage ledger | hard-coded step lists | OWASP/CWE taxonomy post-hoc | 5 fixed classes + prompts | WSTG 4.2 ledger post-hoc |
| Finding verification | LLM reflector and advice tool, no non-LLM check found | schema + exchange-id validation | traffic binding, receipt check, dedicated retest agent | none found | non-LLM oracles (OOB, differential, timing) behind the verify flag | reconciliation vs SAST + exploit | replay with typed proof contracts |
| Budget / incomplete | iteration cap + reflector shutdown | budget hooks, coverage gaps | budget ledger + wrap-up | — | pause-on-budget → report | typed partialReasons | verify+report at finish; no wrap-up |
| Scope at transport | — | prompt + docker caps | **PinnedDialer (dial-time)** | — | ScopedDialContext (Go clients) | — | per-hop HTTP check; subprocess pre-flight only |
| Drive / resume | React + GraphQL, DB rows | CLI --resume + session | web UI + operator pause | MCP config | Cobra CLI, workspace config | CLI + Temporal resume | FastAPI + React, intent resume |

## What NOT to copy

1. **Prompt-level authorization as the security boundary** (PentAGI
   `pentester.tmpl:5-11`, Strix `scope.jinja`). Libella already enforces in
   code; do not let a model-facing "you are authorized" block replace
   `Scope.check_url`.
2. **A generic command runner** (HexStrike `/api/command`, `shell=True` at
   `:5272`, no auth). It cannot be made scope-safe without a jail, and it
   destroys the audit story Libella's typed `ToolSpec`/argv model buys.
3. **A "decision engine" that is a lookup table** (HexStrike
   `IntelligentDecisionEngine`, `:971`). It reads like planning but routes
   static scores; it cannot adapt to evidence.
4. **A verifier that is a second model opinion** (PentAGI's reflector,
   Strix's confidence/counterevidence field, Swarm's paid model verifier when
   used alone). Useful as triage, not as proof. Swarm is explicit about this and
   adds non-LLM oracles; Libella replays the proof request. Which is more accurate
   is untested.
5. **Removing the scope engine and replacing it with per-target approvals**
   (ARTEX `guard/guard.go:1-6`, "RoE authorization-scope mechanism was
   removed"). Human pinning is a product feature for interactive red teams; an
   unattended engagement needs a declared allowlist, which Libella has.
6. **Unbounded interactive parking** (Strix `wait_for_user` /
   `_run_until_lifecycle` loops). Fine for a CLI with a human attached; in a
   server job it is a stuck run. Libella's bounded `max_iterations` and lease
   expiry are the right default.
7. **Heavy durable-execution infrastructure** (Shannon: Temporal + git
   checkpoints + workspace session files). The *requirement* (resumable,
   partial-result-honest runs) is right; the cost is not justified at Libella's
   size — a transcript table and typed `exit_reason` get most of it.
8. **AGPL code.** ARTEX, Swarm and Shannon are AGPL-3.0. Behaviour may be
   studied; code must not be transplanted into Libella.

## Ranked backlog (smallest complete changes across all six)

| Rank | Change | Reference | Where |
|---|---|---|---|
| P0 | Refuse or confine `network_unbounded` tool adapters; state the residual in report limitations | ARTEX dial gate, Swarm egress guard | `tools/__init__.py`, `tools/runner.py`, `report.py` |
| P0 | Add dial-time (or redirect-hop) scope checking to the browser path (the entry URL is checked at `http_probe.py:210`; navigations are not) | Swarm `ScopedDialContext`, ARTEX `PinnedDialer` | `tools/http_probe.py:196` |
| P1 | Persist the ReAct transcript; seed `history` on retry | Strix session, ARTEX transcript | `agent_runtime.py`, `db.py` |
| P1 | Recall cross-engagement memory into agent context, provenance-tagged | PentAGI memorist, ARTEX lessons | `agent_runtime.py:479` |
| P1 | Expose registered tools to the agent instead of the 5-name tuple | ARTEX catalog, Strix MCP meta-tools | `agent_runtime.py:504` |
| P1 | Wrap-up turn at 90 % budget / last 2 iterations | ARTEX `BeginWrapup` | `agent_runtime.py:531` |
| P1 | Fact-triggered follow-up intent for object ids (capped) | Swarm `OBJECT_REF` | `agent_runtime.py:401`, `orchestrator.py` |
| P1 | Typed partial reasons surfaced in the report | Shannon `partialReasons` | `agent_runtime.py:616`, `report.py` |
| P2 | Subagent fan-out cap | Strix budget reserve | `agent_runtime.py:450` |
| P2 | Coverage gaps returned to the agent at finish | Strix `_coverage_summary` | `coverage.py:304` |
| P2 | Code-audit second-source reconciliation | Shannon SARIF join | `codeaudit.py`, `verifier.py` |

## Limits of this trace

* No reference platform was installed or executed. Claims about their behaviour
  are read from source; anything about runtime behaviour under load, or about
  paths not traced here, is **[U]** and not asserted.
* Line numbers are exact at the SHAs in the table but will drift. Symbols and
  file paths are the durable identifiers.
* The trace covers the eight questions only. Provider handling, UI details,
  licensing compliance and deployment were out of scope (`reference-workflows.md`
  covers some of that at older SHAs).
* Libella runtime observation: the test suite result is recorded below.

## Appendix: Libella suite run

Command (from the task):

```
PYTHONPATH="$PWD/src" /home/computebox/project-pentest/libella/.venv/bin/python \
  -m pytest tests/ -q -p no:randomly
```

Result on the unmodified `f0b4a8d` checkout: **779 passed, 1 skipped, 26
warnings in 214.34 s (exit 0)**. **[R]** The document was added after this run,
so the run reflects the base commit, not the doc.