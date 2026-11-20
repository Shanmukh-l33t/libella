# Libella UI Specification (frontend workstream)

Build the web frontend in `web/` (React + Vite + TypeScript + Tailwind).
Output `web/dist` is served by the FastAPI backend at `/`.

## Design direction (non-negotiable)

Premium security-engineering product. Primarily LIGHT theme. Clean, minimal,
modern but timeless. Careful typography (Inter or similar grotesque; tabular
nums for data). Excellent information hierarchy. High information density
without clutter. Refined micro-interactions (150-200ms ease transitions on
hover/focus/expand). Smooth purposeful animation only. NO gradients, NO
glassmorphism, NO neon, NO decorative security imagery (locks/shields/skulls),
NO unnecessary animation. Think Linear/Vercel/Datadog usability standards,
but an original visual identity. Accent color: a single restrained blue or
teal; severity colors: critical=#B42318, high=#D92D20, medium=#DC6803,
low=#039855, info=#667085 (accessible on white). Neutral grays for structure.
Subtle 1px borders (#E4E7EC), 8px radius, generous whitespace, 13-14px base
data font, clear section headers. Dark mode optional (skip if time-boxed).

## Hard rules

- EVERY button works. Every control persists its setting via the API.
- NO fake findings, NO mock scan counts, NO imaginary agent conversations.
- Empty states explain what to do next. Loading states are skeletons.
  Error states show the actual API error. Interrupted/cancelled engagements
  show their real status.
- All data comes from the real API (read src/libella/api.py for the contract).
- Auth: API token. On first load show a token entry screen; store in
  localStorage; send as `Authorization: Bearer <token>`. For SSE use
  `?token=<token>` query param (EventSource cannot set headers).
- Responsive down to 1024px; usable at 768px.

## API contract (backend at same origin; dev proxy to 127.0.0.1:8787)

- GET /api/health (no auth) -> {status, version, tools:[{name,available,...}]}
- POST /api/engagements {name, scope:{targets:[{kind:url|domain|cidr|ip,value,include_subdomains?}], exclusions:[...], allowed_ports?, categories:[recon,web,api,infra], rate_limit_rps, max_concurrency, advanced_validation?}, profile, auth:{identities:[{username,password,login_url,username_field,password_field}], test_hints?}, budgets:{max_duration_s,max_usd}, objectives?} -> {id}
- GET /api/engagements -> list (scope, budgets, auth sanitized, summary finding count)
- GET /api/engagements/{id} -> detail + spend
- POST /api/engagements/{id}/start {mode: deterministic|llm}
- POST /api/engagements/{id}/pause | /resume | /cancel
- GET /api/engagements/{id}/assets | /intents | /findings | /observations | /tool-calls | /events?since=seq
- GET /api/engagements/{id}/stream?since=seq&token=... (SSE; events: engagement_started, intent_created, intent_running, intent_done, asset_discovered, finding_new, finding_state, finding_dedup, verification, retest, tool_call, scope_refusal, degradation, checks_complete, report_rendered, engagement_finished, engagement_paused, engagement_resumed, engagement_cancelled, engagement_failed, compile_reject)
- GET /api/engagements/{id}/graph -> {nodes:[{id,type:asset|finding|intent,kind,label,data}], edges:[{source,target,kind,verified?}]}
- GET /api/findings/{id} -> finding + verifications + retests + exchanges
- POST /api/findings/{id}/verify | /retest | /state {state, reason}
- GET /api/evidence/{id} -> {kind, sha256, content(redacted)}
- GET /api/evidence/{id}/chain -> {ok, checked, head}
- GET /api/exchanges/{id} -> exchange + blob{request,response}
- GET /api/engagements/{id}/report?format=json|md|sarif
- GET /api/tools -> availability
- GET/PUT /api/settings {llm:{base_url, api_key, default_model, models:{role:model}, fallback:[...]}}

Finding states: suspected, observed, validated, reported, remediated,
retested_fixed, retested_persists, ruled_out.
Intent statuses: open, running, done, blocked, exhausted, stopped.

## Pages

1. Dashboard (/): engagement cards/table (name, status badge, profile,
   findings count by severity, created, duration), "New engagement" button,
   global tool availability strip. Real data only.
2. New engagement (/engagements/new): single-page form with sections:
   Targets (add/remove rows: kind select + value), Exclusions, Profile
   (passive/safe_active/advanced_validation radio with plain-language
   descriptions), Categories checkboxes, Limits (rps, concurrency, duration,
   budget), Identities (optional username/password/login_url rows),
   Advanced test hints (collapsible JSON textarea, optional).
   Client-side validation mirroring backend (fail-closed empty scope).
3. Engagement detail (/engagements/:id): header with name, status badge,
   start/pause/resume/cancel buttons (state-aware), spend, duration. Tabs:
   - Overview: summary counters (assets, findings by state/severity, tool
     calls, scope refusals), live activity feed (SSE, newest first, typed
     icons), degradation banner if any.
   - Operations: intents table (role, objective, status, attempts, deps)
     with live updates; tool calls table (tool, target, decision, exit,
     duration) expandable to argv.
   - Assets: table (kind, key, discovered_by, first/last seen) + filter.
   - Graph: @xyflow/react rendering of /graph. Asset nodes neutral, finding
     nodes severity-colored, intent nodes status-colored. Edge kinds styled
     (contains/depends_on/affects); verified affects edges solid, unverified
     dashed. Click node -> side panel with data. Layout: dagre or simple
     layered (assets left, findings right, intents bottom). Zoom/pan/minimap.
   - Findings: table (severity, title, CWE, state, confidence, endpoint)
     with filters (severity, state) and sort; row -> finding detail.
   - Report: render report.json summary + findings; buttons to download
     MD/SARIF (open /report?format=...&token=...); "Regenerate" calls GET.
4. Finding detail (/findings/:id): full metadata, description/impact/
   remediation, state badge + transition actions (rule out with reason),
   Verify button (POST verify, show verdict), Retest button. Evidence
   viewer: list bound exchanges; each shows method/url/status/duration and
   expandable request/response (monospace, redacted content from API).
   Verification history table (attempt, verdict, detail). Evidence chain
   status (GET chain) with ok/broken indicator.
5. Settings (/settings): LLM provider form (base_url, api_key password
   field, default_model, per-role model overrides for planner/worker/
   verifier/reporter, fallback list), save via PUT. Tool availability table
   from /api/tools with install hints for missing ones.

## Component system

Build reusable: Button (primary/secondary/ghost/danger, loading state),
Badge (status/severity/state), Card, Table (sortable, empty state), Tabs,
Input/Select/Textarea with labels+errors, Modal, Skeleton, EmptyState,
Toast (for action results), CodeBlock (monospace, copy button), JsonViewer.
Consistent spacing scale. Focus rings for accessibility. Aria labels on
icon buttons.

## Tech

React 18, Vite 5, TypeScript, Tailwind CSS 3 (stable), @xyflow/react,
lucide-react, react-router-dom. No Redux; React context + hooks. SSE via
native EventSource with reconnect + cursor. Fetch wrapper adds auth header,
handles 401 -> token screen. Dev: vite proxy /api -> http://127.0.0.1:8787.

## Verification required before handoff

1. `npm run build` succeeds; web/dist exists.
2. Start the backend with a fresh local data directory. In a second private terminal run `libella --show-token --data-dir <same-directory>`. Do not capture the token in screenshots or logs.
3. Create a real engagement via curl against lab http://127.0.0.1:8801 (scope url target), start it, wait for done.
4. Verify via curl that every API route the UI uses returns real data.
5. If a browser tool is available, load the UI, screenshot dashboard +
   engagement detail + finding detail + graph, confirm no console errors.
6. Report: files created, build output, verification results, screenshots paths.