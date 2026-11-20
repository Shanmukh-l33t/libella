# Foundation inventory — audit at `d71d5a1`

Snapshot: branch `review/foundation-inventory`, commit `d71d5a1` (v0.4.0 + doc
corrections), 2026-11-20. Static, read-only audit of the repository as pinned:
no engagement was run, no lab or external host was contacted, no secrets work.
Executed for verification: `pytest --collect-only` (449 tests), the reporting +
audit2 suites (46 passed), and one in-process probe that rendered a report for a
seeded remediated finding. Everything else is source/doc reading at this commit;
sections state which is which.

Priority taxonomy used here (the brief's P0–P4, made explicit because the repo
does not define it):

| Level | Meaning |
|---|---|
| P0 | Governance: authorization object, execution boundary, stop/kill, audit trail, operator trust boundary |
| P1 | Reporting: what leaves the platform (MD/JSON/SARIF/PDF), version/provenance, evidence bundle |
| P2 | Imports: what enters the platform (OpenAPI specs, plugins, MCP tools, external findings) |
| P3 | Remediation: operator facts vs verified fixes, retest loop, historical comparison |
| P4 | Code vs claims: docs that overstate, understate, or contradict HEAD |

## 1. Module inventory

Verified = exercised by tests at this commit and consistent with its claim;
partial = works with a limit stated here; gap = claim without enforcement.

| Area | Modules | Tests | State |
|---|---|---|---|
| Authorization object | `scope.py` (385 L) — targets/exclusions/ports/categories, DNS resolve (redirect + peer-IP checks live in `http_probe.py`) | `tests/test_scope.py` (11), `tests/audit/test_scope_bypass.py` (18) | verified for targets/ports/categories; `window_start/end`, `max_concurrency`, `advanced_validation`, `profile` unenforced (P0-1..4) |
| Tool execution | `tools/__init__.py` (typed params, duplicate-name refusal), `tools/runner.py`, `tools/http_probe.py`, `tools/adapters.py` | `tests/audit/test_tool_injection.py` (29), `test_http_boundary.py` (3) | verified; stop/cancel does not reach running subprocesses (P0-3) |
| Evidence | `evidence.py` — content-addressed blobs, per-engagement hash chain, read-time re-hash | `tests/audit/test_evidence_integrity.py` (5) | verified per-row; chain has no out-of-band anchor (P0-6) |
| Findings/verification | `findings.py` (state machine), `verifier.py` (replay) | `test_finding_pipeline.py` (8), audit2 gate tests | verified |
| Planner/orchestrator | `orchestrator.py` (702 L) — leased intents, fencing, budgets, deterministic/LLM plans | `test_plan_dependencies.py` (2), `tests/audit/test_races.py` (3), `test_resource_caps.py` (5) | verified, with the blocked-dependency and `informed_by` gaps below |
| Agent runtime | `agent_runtime.py` (596 L) — ReAct loop, typed actions, evidence/quote gates | `test_agent_runtime.py` (6), `audit2/test_agent_gates.py` (6) | verified unit-level; benchmark numbers are not reproducible from committed artifacts (P4-3) |
| Assessment modules | `checks.py`, `api_audit.py`, `graphql_audit.py`, `tls_audit.py`, `codeaudit.py`, `cloud_audit.py`, `tech_modules.py`, `crawl.py`, `browser_crawl.py`, `auth_browser.py`, `traffic.py` | per-module dirs, 24 cloud + 15 traffic + 11 authbrowser + … | verified against local labs; not re-run in this audit |
| Reporting | `report.py` (MD/JSON/SARIF), `report_pdf.py` | `tests/report/` (15), `audit/test_secrets_report.py` (6) | redaction verified; remediation/retest data absent from artifacts (P1-1) |
| Remediation | `remediation.py` (board, compare) | `tests/report/test_remediation.py` (6) | state machine respects findings gates; comparison overstates "fixed" (P3-1) |
| Extensibility | `plugins.py`, `mcp_client.py` | `tests/plugins/` (41) | typed + scope-gated; load = in-process code execution by design (P2-3) |
| UI | `web/src` (29 tracked files; 9 pages + 9 engagement panels) | none | build-only CI, screenshots as evidence; `Passive` profile mislabelled (P0-2) |
| Packaging | `pyproject.toml`, `Dockerfile`, `docker-compose.yml` | CI build + `DOCKER_VERIFICATION.md` | single version source missing (P1-2); container is non-root, `no-new-privileges`, capped, loopback-bound |

## 2. Test and evidence inventory

- 449 tests collected at `d71d5a1`; the doc claim "448 passed, 1 skipped" is
  consistent (the 4 `tests/test_operator_cli.py` tests exist only in main-tip
  `2086b4c`, which is not this tree).
- `tests/audit/` 93, `tests/audit2/` 31 — matches AUDIT.md / AUDIT2.md.
- No frontend tests: CI builds `web/` and nothing asserts behaviour.
- No committed benchmark artifacts: `benchmark_runs/` is gitignored, so every
  README/matrix number (16/16, $0.17, 526 s, 153.7 s) is a claim with a script,
  not a stored result. Reproducible only by re-running on a matching host.
- CI gates that exist: ruff, `pytest tests/`, PairLab 16/16 + 0 FP + chain
  assertions, gitleaks, `pip-audit || true` (advisory).

## 3. Root document reconciliation

| Doc | Role at HEAD | What is wrong | Action |
|---|---|---|---|
| `README.md` | front door | stop-to-subprocess claim false (P0-3); "time window", "concurrency", profiles unenforced (P0-1..2); audit tally 35 vs 36 (P4-1); "remediation tracking + historical comparison" not in exports (P1-1) | fix wording, link this file |
| `ARCHITECTURE.md` | decision record | accurate on limits (kill propagation = roadmap); §1 lists window/concurrency/profile as enforced | align with P0 findings |
| `AUDIT.md` | audit 1 | 23 defects (5/12/6) — accurate; benchmark numbers are v0.1-era (13/13) and unmarked as historical | add date/version banner |
| `AUDIT2.md` | audit 2 | 13 defects / 31 tests — accurate | keep |
| `AUDIT_CURRENT.md` | pre-expansion snapshot | says 242 tests, 4 releases, agent runtime "MISSING", no cloud/traffic/PDF/plugins — all now exist; 6 tags exist | mark superseded, do not edit facts |
| `CAPABILITIES.md` | honest capability list | worst stale doc: PairLab "13 seeds" (16 in ground truth), "AWS/K8s posture PLANNED, not claimed" (README: moto-verified), zero mentions of agent runtime/traffic/remediation/PDF/plugins, evidence pointers into gitignored `benchmark_runs/` | regenerate from matrix + labs |
| `CAPABILITY_MATRIX.md` | workstream instrument | mostly accurate; one wrong test pointer (hypotheses → `test_agent_runtime`, actually `test_graph_memory`); 35-defect tally | fix two cells, keep statuses |
| `CONTRACTS.md` | module contracts | describes remediation/traffic/etc. as planned contracts; modules now exist and mostly match | mark met/diverged per section |
| `THREAT_MODEL.md` | security model | lists "local user tampering" as adversary with fail-closed evidence (true only per row, P0-6); omits that an API-token holder gets host code execution via plugins/MCP | extend trust-boundary table |
| `SECURITY.md` | disclosure + limits | accurate; residual risks honest | keep |
| `CONTRIBUTING.md` | dev workflow | benchmark gate "13/13" contradicts CI's 16/16 | update to 16 |
| `DOCKER_VERIFICATION.md` | install evidence | 8/16 validated without identities — internally consistent | add date + image digest |
| `UI_SPEC.md` | UI brief | demands "every control persists via API" — profile/advanced flags persist but do nothing (P0-2) | note profile semantics |

## 4. P0 — governance

**P0-1 Time window is decorative.** `window_start/window_end` are written at
creation (`src/libella/api.py:131-136`, `db.py:14`) and read nowhere. README,
ARCHITECTURE §1 and THREAT_MODEL all list the window as an enforced control.
Gate: `POST /start` and each intent claim refuse outside the window; test with a
past window.

**P0-2 Safety profiles do not gate anything.** `profile` is free text stored at
creation (`api.py:133`) and only rendered back (`report.py:99,132`). The UI
offers "Passive — Observe only. Fetches in-scope pages, changes nothing."
(`web/src/pages/NewEngagement.tsx:26`) and "Advanced validation — adds
independent replay proof" (replay is always on). `Scope.advanced`
(`scope.py:86`) is used only in the prompt block (`scope.py:379`) — no check or
adapter consults it. Selecting Passive runs the same active checks as
Safe active. Gate: profile → allowed intent/tool classes enforced in planning
and at the execution gate; test that a passive plan creates no attack intents.

**P0-3 Emergency stop does not stop tools.** `cancel()` only flips
engagement/intent rows (`orchestrator.py:65-70`); no subprocess is signalled.
README claims "cancel propagates to intents and subprocesses"; ARCHITECTURE §6
calls hard-kill roadmap and THREAT_MODEL relies on tool timeouts instead. A
running nuclei/nmap keeps egressing until its own timeout. Gate: cancel
terminates live children (or README stops claiming it).

**P0-4 Concurrency cap unenforced.** `max_concurrency` parsed at
`scope.py:88`, never read. README/ARCHITECTURE claim concurrency caps.
Gate: enforce, or delete the field from scope and docs.

**P0-5 No operator identity or API audit trail.** One shared bearer token
(`api.py:107-113`), no per-request audit, no audit export; `events` covers
engagement lifecycle only. A token holder also gets host code execution via
`plugins.py:144` (`exec_module` at load) and `POST /api/mcp/servers` — a trust
boundary THREAT_MODEL does not state. Gate: document the "token = trusted
operator, host execution" boundary; add request-level audit rows or explicitly
declare the platform single-operator.

**P0-6 Evidence chain cannot detect a consistent rewrite.** `verify_chain`
(`evidence.py:89-106`) recomputes hashes from the same DB/files it is checking.
Casual tampering is caught (tests); deleting rows and recomputing the chain from
a known point is not. Gate: anchor the head hash out-of-band (report manifest or
signed export) or narrow the threat-model claim to "tamper-evident within the
store".

**P0-7 Blocked upstream work still unblocks the report.** Dependencies count as
satisfied when status is `blocked` (`orchestrator.py:298`), so a blocked verify
intent lets the report intent run and the engagement finish `done`. Degradations
are emitted and rendered, so this is "visible but under-weighted": the MD/PDF
header still reads as a completed assessment. Gate: `done` requires zero blocked
intents, or the report headline carries "N intents blocked".

**P0-8 Untrusted import path.** `auth.openapi` is accepted unvalidated at
creation and read at run (`orchestrator.py:678-682` → `api_audit.py:36`). An API
client can point the engine at any readable JSON file; failure surfaces as a
blocked intent. Not confined like `repo` targets (`scope.check_repo`). Gate:
validate path at creation (absolute, exists, under a declared repo target),
record the spec as an engagement asset.

**P0-9 No retention or deletion.** No `DELETE` path for engagements or evidence
(grep: none). Assessment data and captured credentials accumulate for the life
of the data dir. Gate: documented retention policy and an audited delete.

Minor (not gated): unauthenticated `/api/health` discloses installed toolchain
(`api.py:117`); `GET /api/exchanges/{id}` returns `req_body` unredacted
(`api.py:359-380`, only the evidence blob body is redacted).

## 5. P1 — reporting

**P1-1 Exports contain no remediation or retest data.** The canonical finding
dict (`report.py:119-127`) has no `owner`, `fix_commit`, `remediation_notes`,
`remediated_at`, `retests`, while `report_pdf.py:115,139` renders exactly those
keys — so "Remediation owner / Fix commit" rows are dropped and "Retest history"
never appears. Verified by probe: rendered `report.json` keys =
`confidence, cwe, description, endpoint, evidence_ids, id, impact, owasp,
remediation, severity, state, title, verifications`; MD contains neither owner
nor "retest". Gate: report carries a remediation block + retest verdicts; test
asserts owner/fix commit appear in PDF text.

**P1-2 Version is wrong in every machine-readable surface.** `pyproject.toml:3`,
`api.py:103`, `api.py:117`, `report.py:181` all say `0.1.0` at tag v0.4.0.
SARIF exported to CI therefore attributes results to the wrong tool version.
Gate: single source (`importlib.metadata.version`) and a release check that tags
match package metadata.

**P1-3 Reports are not self-contained.** `report.json` cites `ev_*` ids that a
consumer cannot resolve without the database. Gate: evidence bundle (or manifest
with sha256 + size) written next to the report.

**P1-4 Report headline hides blocked coverage.** Only a degradations list and a
`status != done` note (never triggered under P0-7) qualify the result. Gate:
summary counters already include `intents_blocked` — surface them in the MD/PDF
header.

**P1-5 Dead CSV escaping.** `_csv_escape` (`report.py:65`) has no caller; the
only consumer is its own test (`tests/audit/test_secrets_report.py:79`), and
AUDIT.md cites it as a satisfied control. Remove it or implement CSV export.

## 6. P2 — imports

**P2-1 OpenAPI import is thin.** `load_openapi` (`api_audit.py:36-56`): JSON
only (no YAML), local path only, `$ref` resolved to the last path segment (no
nested/external refs), no schema validation, no record that a spec was imported
or from where. Gate: YAML + structural validation + provenance (spec stored as
evidence, digest in report).

**P2-2 No findings ingest.** There is no SARIF/Burp/REST import, so retest and
comparison only work on findings this platform produced. README's "CI/issue
hooks planned" is honest; the gate is a SARIF-in path with dedup keys before any
CI adapter is built.

**P2-3 Plugin/MCP import is code execution.** `plugins.py:144` executes plugin
modules in-process at startup; MCP servers are operator-registered commands.
Duplicate tool names are refused (`tools/__init__.py` `Registry.register`), which
closes the shadowing class. Gate: explicit `LIBELLA_PLUGINS=1` opt-in, manifest
allowlist, and the trust-boundary note from P0-5.

## 7. P3 — remediation

**P3-1 "Fixed" can mean "not scanned".** `compare_engagements` puts a finding
absent from B into `fixed` with `reason: absent_in_b`
(`remediation.py:134`), asserted by `tests/report/test_remediation.py:63`.
Nothing checks that B covered the same surface (coverage, degradations, blocked
intents), so a partial follow-up run reports fixes that were never tested.
Gate: separate `not_observed` bucket; count as fixed only with equal coverage or
a retest verdict.

**P3-2 No remediation→retest loop.** `remediated` is a legitimate operator fact
from a confirmed state (`remediation.py:36-57`) and `retested_fixed` requires a
recorded retest row (good), but nothing schedules or prompts the retest, so the
board can sit in "remediated" indefinitely. Gate: remediation timestamp + retest
due date, surfaced in the board.

**P3-3 Field semantics.** Any one of owner/notes/fix_commit moves a finding to
`in_progress` (`remediation.py:44-46`); notes/owner are unbounded and unredacted
in the board API. Gate: length caps, and the same redaction pass as report text.

## 8. P4 — code vs claims

**P4-1 Audit tally off by one.** AUDIT.md 23 (5 high / 12 medium / 6 low) +
AUDIT2 13 = 36; README, CAPABILITY_MATRIX and the HEAD commit message say 35.
Gate: state "36 (23 + 13)" or identify the merged defect.

**P4-2 CAPABILITIES.md is a pre-v0.4 document.** "13/13 PairLab" vs 16 seeds in
`labs/pairlab/ground_truth.json`; "AWS/K8s posture PLANNED, not claimed"
contradicts README's "AWS cloud posture (moto-verified)" and the matrix's IN-DEV;
no mention of agent runtime, traffic, remediation board, PDF, plugins/MCP; its
evidence column points at `benchmark_runs/results.json`, which is gitignored.
Gate: regenerate; every evidence pointer must be a tracked file.

**P4-3 Benchmark claims have no committed artifacts.** All v0.4 numbers are
reproducible-by-script only. Gate: commit a small results JSON per release
(hashes, counts, timings) or label the numbers "last observed, not archived".

**P4-4 `informed_by` lineage is inert.** Written as `[]` at every intent
creation (`orchestrator.py:85-95`; no caller passes `informed=`), returned empty
by the API (`api.py:217`), although ARCHITECTURE cites PentestGPT #568
(basis ≠ prerequisite) as the reason the field exists. Gate: populate it or
remove it from the API contract.

**P4-5 Test-pointer drift.** Matrix row "Hypothesis tracking … test_agent_runtime"
— hypotheses are only exercised in `tests/test_graph_memory.py`; AUDIT_CURRENT
still says 242 tests / 4 releases (6 tags, 449 tests). Gate: correct pointers;
banner stale docs.

**P4-6 "Independent" is self-audit.** Both audits are internal documents by the
same workstream; the word carries weight with buyers. Gate: reword to
"adversarial self-audit" or record an external review.

## 9. Requirements traceability (REA notes + public reference issues)

The repository has zero open issues, so the defensive requirements come from the
reference-project issues already cited in `ARCHITECTURE.md` (all six confirmed
public and still open on 2026-11-20) and from the out-of-repo reference
execution log kept by this workstream (not published).

| Requirement (source) | At HEAD | Gate |
|---|---|---|
| No false all-clear when a stage fails (swarm #66, shannon #529) | degradations emitted and rendered in MD/PDF; P0-7 still lets a blocked stage end `done` | P0-7 |
| Tamper-evident evidence (ARTEX #310) | per-row re-hash, no anchor | P0-6 |
| Provenance derived, not declared (ARTEX #124) | derived from evidence bindings; agent gates re-check quote + scope | met |
| No command injection via tool args (hexstrike #263/#224) | typed params, argv-only, 29 injection tests | met |
| Supervisor/planner cannot write invalid state (PentestGPT #568) | compile gate; `informed_by` unused | met / P4-4 |
| Prompt injection from targets cannot expand scope (strix #1760) | untrusted-data framing + gate; audit2 tests | met |
| Viewer/API must not be an unauthenticated surface (strix #1757) | token on all routes except health/UI; no API rate limit | partial (P0-5) |
| Execution isolation from the host (strix #1753) | non-root container, no-new-privileges, capped, loopback; no sandbox per scan | documented limit, no gate |
| Partial analysis must be reported as partial (reference-execution log limits) | degradation + `status_detail` mechanism exists | P1-4 |

## 10. Prioritized acceptance gates

Order is dependency order; each gate is falsifiable by a test.

1. **G-P0a Execution truth**: passive profile makes no active request; window
   and concurrency refuse out-of-bounds; cancel kills a live child. One test
   each, all at the scope/execution boundary.
2. **G-P0b Honest completion**: `done` implies zero blocked intents; report
   headline carries blocked count and degradations. One integration test.
3. **G-P0c Trust boundary**: THREAT_MODEL states token ⇒ host execution; either
   per-request audit rows or an explicit single-operator declaration; evidence
   anchor or narrowed claim.
4. **G-P1 Report fidelity**: report includes remediation + retest; PDF text
   contains owner/fix commit/retest verdict; versions come from package metadata;
   report dir includes an evidence manifest.
5. **G-P2 Import discipline**: OpenAPI validated at creation (path + structure),
   YAML supported, spec recorded as evidence; plugin load behind an explicit flag.
6. **G-P3 Remediation integrity**: `not_observed` split from `fixed`; retest
   due/verdict surfaced.
7. **G-P4 Doc truth**: single tally (36), CAPABILITIES regenerated, stale docs
   bannered, benchmark artifacts committed or claims dated.

## 11. Not verified here

- Full `pytest` run, PairLab benchmark, Docker build/run, cloudlab, ZAP, and any
  lab-driven module: not executed in this audit (tools/browser/moto not
  provisioned in this worktree).
- CI status on GitHub: not queried beyond reading `.github/workflows/ci.yml`.
- Secret handling, browser auth flows, and dependency CVEs: owned by other
  workstreams.
- Severity of P0-9/P1-3 is policy, not exploitability; no attack was attempted
  against a target.