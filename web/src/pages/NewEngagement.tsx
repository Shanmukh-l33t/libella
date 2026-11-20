import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ChevronDown, Plus, Trash2, ArrowLeft } from "lucide-react";
import { post } from "../api";
import type { TargetKind } from "../types";
import { Button, Card, ErrorNote, Field, Input, Select, Textarea, cx, useToast } from "../components/ui";

interface Row { kind: TargetKind; value: string; include_subdomains: boolean }
interface Identity { username: string; password: string; login_url: string }

const KINDS: TargetKind[] = ["url", "domain", "cidr", "ip", "repo", "image", "cloud"];
const CATEGORIES = [
  { id: "recon", label: "Recon", hint: "Host discovery, crawling, content mapping." },
  { id: "web", label: "Web", hint: "Header, cookie, transport and exposure checks." },
  { id: "api", label: "API", hint: "Endpoint discovery and schema probing." },
  { id: "infra", label: "Infra", hint: "Service and port posture checks." },
  { id: "code", label: "Code", hint: "Source audit: semgrep, secrets, dependencies." },
  { id: "cloud", label: "Cloud", hint: "Read-only AWS posture against a scoped endpoint." },
];
const MODES = [
  { id: "deterministic", label: "Deterministic", hint: "Fixed check pipeline. No model required, fully repeatable." },
  { id: "llm", label: "LLM planner", hint: "A model proposes extra intents inside the compile gate." },
  { id: "agent", label: "Agent", hint: "Specialist ReAct loops with hypotheses and delegations. Needs an LLM provider." },
];
const PROFILES = [
  { id: "passive", label: "Passive", hint: "Observe only. Fetches in-scope pages, changes nothing." },
  { id: "safe_active", label: "Safe active", hint: "Non-destructive checks. Default for most work." },
  { id: "advanced_validation", label: "Advanced validation", hint: "Adds independent replay proof for every candidate finding." },
];

export default function NewEngagement() {
  const navigate = useNavigate();
  const toast = useToast();
  const [name, setName] = useState("");
  const [targets, setTargets] = useState<Row[]>([{ kind: "url", value: "", include_subdomains: false }]);
  const [exclusions, setExclusions] = useState<Row[]>([]);
  const [profile, setProfile] = useState("safe_active");
  const [categories, setCategories] = useState<string[]>(["recon", "web"]);
  const [rps, setRps] = useState("10");
  const [concurrency, setConcurrency] = useState("4");
  const [duration, setDuration] = useState("");
  const [budget, setBudget] = useState("");
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [hintsOpen, setHintsOpen] = useState(false);
  const [hints, setHints] = useState("");
  const [openapi, setOpenapi] = useState("");
  const [graphql, setGraphql] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState("deterministic");
  const [login, setLogin] = useState({ base_url: "", login_url: "", username: "", password: "", success: "", selectors: "" });
  const [workflow, setWorkflow] = useState({ name: "", steps: "" });

  const setRow = (list: Row[], i: number, patch: Partial<Row>, set: (r: Row[]) => void) =>
    set(list.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const fe: Record<string, string> = {};
    if (!name.trim()) fe.name = "Give the engagement a name.";
    const cleanTargets = targets.filter((t) => t.value.trim());
    if (!cleanTargets.length) fe.targets = "At least one in-scope target is required (fail-closed).";
    if (targets.some((t) => !t.value.trim())) fe.targets = "Every target row needs a value, or remove the row.";
    if (exclusions.some((x) => !x.value.trim())) fe.exclusions = "Every exclusion row needs a value, or remove the row.";
    const nRps = Number(rps), nConc = Number(concurrency);
    if (!(nRps > 0)) fe.rps = "Rate limit must be greater than 0.";
    if (!(Number.isInteger(nConc) && nConc > 0)) fe.concurrency = "Concurrency must be a positive integer.";
    if (duration && !(Number(duration) > 0)) fe.duration = "Duration must be a positive number of seconds.";
    if (budget && Number(budget) < 0) fe.budget = "Budget cannot be negative.";
    let testHints: unknown = undefined;
    if (hints.trim()) {
      try { testHints = JSON.parse(hints); } catch { fe.hints = "Test hints must be valid JSON."; }
    }
    let selectors: unknown = undefined;
    if (login.selectors.trim()) {
      try { selectors = JSON.parse(login.selectors); } catch { fe.selectors = "Selectors must be a JSON object."; }
    }
    let steps: unknown = undefined;
    if (workflow.steps.trim()) {
      try {
        steps = JSON.parse(workflow.steps);
        if (!Array.isArray(steps) || !steps.length) fe.steps = "Steps must be a non-empty JSON array.";
      } catch { fe.steps = "Steps must be valid JSON."; }
    }
    const loginGiven = Object.values(login).some((v) => v.trim());
    if (loginGiven && !(login.base_url.trim() && login.login_url.trim() && login.username.trim())) {
      fe.login = "A login flow needs base URL, login URL and username (password optional).";
    }
    setFieldErrors(fe);
    if (Object.keys(fe).length) { setError("Fix the highlighted fields before creating the engagement."); return; }

    setBusy(true);
    setError(null);
    try {
      const body = {
        name: name.trim(),
        scope: {
          targets: cleanTargets.map((t) => ({
            kind: t.kind, value: t.value.trim(),
            ...(t.kind === "domain" && t.include_subdomains ? { include_subdomains: true } : {}),
          })),
          exclusions: exclusions.filter((x) => x.value.trim()).map((x) => ({ kind: x.kind, value: x.value.trim() })),
          categories,
          rate_limit_rps: nRps,
          max_concurrency: nConc,
          advanced_validation: profile === "advanced_validation",
        },
        profile,
        auth: {
          identities: identities
            .filter((i) => i.username || i.password || i.login_url)
            .map((i) => ({ username: i.username, password: i.password, login_url: i.login_url })),
          ...(openapi.trim() ? { openapi: openapi.trim() } : {}),
          ...(graphql.trim() ? { graphql: graphql.trim() } : {}),
          ...(testHints !== undefined ? { test_hints: testHints } : {}),
        },
        budgets: { ...(duration ? { max_duration_s: Number(duration) } : {}), ...(budget ? { max_usd: Number(budget) } : {}) },
      };
      const res = await post<{ id: string }>("/api/engagements", body);
      const warnings: string[] = [];
      if (loginGiven) {
        try {
          const ctx = await post<{ status?: string; reason?: string }>(`/api/engagements/${res.id}/auth-contexts`, {
            base_url: login.base_url.trim(), login_url: login.login_url.trim(),
            username: login.username.trim(), password: login.password,
            ...(selectors ? { selectors } : {}),
            ...(login.success.trim() ? { success_assertion: login.success.trim() } : {}),
          });
          if (ctx.status !== "active") warnings.push(`login flow: ${ctx.reason || ctx.status || "failed"}`);
        } catch (err) {
          warnings.push(`login flow: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      if (steps !== undefined) {
        try {
          await post(`/api/engagements/${res.id}/workflows`, {
            name: workflow.name.trim() || "wizard workflow", steps,
          });
        } catch (err) {
          warnings.push(`workflow: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      toast(warnings.length ? `Engagement created. Setup warnings — ${warnings.join("; ")}` : "Engagement created as draft.", warnings.length ? "warning" : "success");
      navigate(`/engagements/${res.id}${mode !== "deterministic" ? `?mode=${mode}` : ""}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="mx-auto max-w-[880px] space-y-5" noValidate>
      <div>
        <Link to="/" className="inline-flex items-center gap-1 text-xs text-ink-500 hover:text-ink-900"><ArrowLeft size={13} /> Engagements</Link>
        <h1 className="mt-2 text-xl font-semibold tracking-tight text-ink-900">New engagement</h1>
        <p className="mt-1 text-sm text-ink-500">Created as a draft. Nothing runs until you start it from the engagement page.</p>
      </div>

      <ErrorNote error={error} />

      <Card title="Targets" description="The authorization boundary. Every tool call is checked against this before it egresses.">
        <Field label="Engagement name" htmlFor="eng-name" error={fieldErrors.name} required>
          <Input id="eng-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. ACME portal — external web" error={!!fieldErrors.name} />
        </Field>
        <div className="mt-4 space-y-2">
          <div className="text-sm font-medium text-ink-700">In-scope targets</div>
          {targets.map((t, i) => (
            <div key={i} className="flex flex-wrap items-start gap-2">
              <Select aria-label={`Target ${i + 1} kind`} value={t.kind} className="w-28"
                onChange={(e) => setRow(targets, i, { kind: e.target.value as TargetKind }, setTargets)}>
                {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
              </Select>
              <Input aria-label={`Target ${i + 1} value`} value={t.value} placeholder={t.kind === "url" ? "https://app.example.com" : t.kind === "domain" ? "example.com" : t.kind === "cidr" ? "10.0.0.0/24" : t.kind === "repo" ? "/abs/path/to/repo (read-only audit)" : t.kind === "image" ? "local-image:tag (container scan)" : t.kind === "cloud" ? "123456789012 or https://127.0.0.1:5000 (lab)" : "10.0.0.5"}
                className="min-w-[240px] flex-1" error={!!fieldErrors.targets}
                onChange={(e) => setRow(targets, i, { value: e.target.value }, setTargets)} />
              {t.kind === "domain" && (
                <label className="flex h-9 items-center gap-1.5 text-xs text-ink-700">
                  <input type="checkbox" checked={t.include_subdomains} onChange={(e) => setRow(targets, i, { include_subdomains: e.target.checked }, setTargets)} />
                  subdomains
                </label>
              )}
              <Button type="button" variant="ghost" aria-label={`Remove target ${i + 1}`} icon={<Trash2 size={14} />}
                onClick={() => setTargets(targets.length === 1 ? [{ kind: "url", value: "", include_subdomains: false }] : targets.filter((_, idx) => idx !== i))} />
            </div>
          ))}
          {fieldErrors.targets && <p className="text-xs text-sev-high">{fieldErrors.targets}</p>}
          <Button type="button" size="sm" icon={<Plus size={13} />} onClick={() => setTargets([...targets, { kind: "url", value: "", include_subdomains: false }])}>Add target</Button>
        </div>
      </Card>

      <Card title="Exclusions" description="Optional. Explicitly out-of-scope hosts or ranges are refused even if inside a target.">
        {exclusions.map((x, i) => (
          <div key={i} className="mb-2 flex flex-wrap items-start gap-2">
            <Select aria-label={`Exclusion ${i + 1} kind`} value={x.kind} className="w-28"
              onChange={(e) => setRow(exclusions, i, { kind: e.target.value as TargetKind }, setExclusions)}>
              {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
            </Select>
            <Input aria-label={`Exclusion ${i + 1} value`} value={x.value} placeholder="e.g. billing.example.com" className="min-w-[240px] flex-1"
              onChange={(e) => setRow(exclusions, i, { value: e.target.value }, setExclusions)} />
            <Button type="button" variant="ghost" aria-label={`Remove exclusion ${i + 1}`} icon={<Trash2 size={14} />}
              onClick={() => setExclusions(exclusions.filter((_, idx) => idx !== i))} />
          </div>
        ))}
        {fieldErrors.exclusions && <p className="mb-2 text-xs text-sev-high">{fieldErrors.exclusions}</p>}
        <Button type="button" size="sm" icon={<Plus size={13} />} onClick={() => setExclusions([...exclusions, { kind: "domain", value: "", include_subdomains: false }])}>Add exclusion</Button>
      </Card>

      <Card title="Assessment mode" description="How the run is driven. Can be changed again when you start the engagement.">
        <div className="grid gap-2 sm:grid-cols-3">
          {MODES.map((m) => (
            <label key={m.id} className={cx("cursor-pointer rounded border p-3 transition-colors duration-150",
              mode === m.id ? "border-accent bg-accent-soft/50 ring-1 ring-accent/20" : "border-line hover:border-ink-300")}>
              <span className="flex items-center gap-2">
                <input type="radio" name="mode" value={m.id} checked={mode === m.id} onChange={() => setMode(m.id)} />
                <span className="text-sm font-medium text-ink-900">{m.label}</span>
              </span>
              <span className="mt-1 block pl-6 text-xs text-ink-500">{m.hint}</span>
            </label>
          ))}
        </div>
      </Card>

      <Card title="Profile" description="How much the engine is allowed to touch. Stored per engagement and enforced by the scope engine.">
        <div className="grid gap-2 sm:grid-cols-3">
          {PROFILES.map((p) => (
            <label key={p.id} className={cx("cursor-pointer rounded border p-3 transition-colors duration-150",
              profile === p.id ? "border-accent bg-accent-soft/50 ring-1 ring-accent/20" : "border-line hover:border-ink-300")}>
              <span className="flex items-center gap-2">
                <input type="radio" name="profile" value={p.id} checked={profile === p.id} onChange={() => setProfile(p.id)} />
                <span className="text-sm font-medium text-ink-900">{p.label}</span>
              </span>
              <span className="mt-1 block pl-6 text-xs text-ink-500">{p.hint}</span>
            </label>
          ))}
        </div>
      </Card>

      <Card title="Categories" description="Which check families to plan. At least one keeps the run meaningful.">
        <div className="grid gap-2 sm:grid-cols-2">
          {CATEGORIES.map((c) => (
            <label key={c.id} className="flex cursor-pointer items-start gap-2 rounded border border-line px-3 py-2 transition-colors hover:border-ink-300">
              <input type="checkbox" className="mt-0.5" checked={categories.includes(c.id)}
                onChange={(e) => setCategories(e.target.checked ? [...categories, c.id] : categories.filter((x) => x !== c.id))} />
              <span>
                <span className="block text-sm font-medium text-ink-900">{c.label}</span>
                <span className="block text-xs text-ink-500">{c.hint}</span>
              </span>
            </label>
          ))}
        </div>
      </Card>

      <Card title="Limits" description="Hard caps for rate, parallelism, runtime and model spend.">
        <div className="grid gap-4 sm:grid-cols-4">
          <Field label="Rate limit (req/s)" htmlFor="rps" error={fieldErrors.rps}>
            <Input id="rps" type="number" min={0.1} step="0.1" value={rps} onChange={(e) => setRps(e.target.value)} error={!!fieldErrors.rps} />
          </Field>
          <Field label="Max concurrency" htmlFor="conc" error={fieldErrors.concurrency}>
            <Input id="conc" type="number" min={1} step={1} value={concurrency} onChange={(e) => setConcurrency(e.target.value)} error={!!fieldErrors.concurrency} />
          </Field>
          <Field label="Max duration (s)" htmlFor="dur" error={fieldErrors.duration} hint="Blank = no cap">
            <Input id="dur" type="number" min={1} value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="1800" error={!!fieldErrors.duration} />
          </Field>
          <Field label="Max spend (USD)" htmlFor="budget" error={fieldErrors.budget} hint="Blank = no cap">
            <Input id="budget" type="number" min={0} step="0.01" value={budget} onChange={(e) => setBudget(e.target.value)} placeholder="5.00" error={!!fieldErrors.budget} />
          </Field>
        </div>
      </Card>

      <Card title="Identities" description="Optional test accounts for authenticated coverage. Passwords are stored server-side and never returned by the API.">
        {identities.length === 0 && <p className="text-sm text-ink-500">No identities added. Only unauthenticated surface will be assessed.</p>}
        {identities.map((id, i) => (
          <div key={i} className="mb-2 grid gap-2 sm:grid-cols-[1fr_1fr_1.4fr_auto]">
            <Input aria-label={`Identity ${i + 1} username`} placeholder="username" value={id.username}
              onChange={(e) => setIdentities(identities.map((x, idx) => idx === i ? { ...x, username: e.target.value } : x))} />
            <Input aria-label={`Identity ${i + 1} password`} type="password" placeholder="password" value={id.password} autoComplete="new-password"
              onChange={(e) => setIdentities(identities.map((x, idx) => idx === i ? { ...x, password: e.target.value } : x))} />
            <Input aria-label={`Identity ${i + 1} login url`} placeholder="https://app.example.com/login" value={id.login_url}
              onChange={(e) => setIdentities(identities.map((x, idx) => idx === i ? { ...x, login_url: e.target.value } : x))} />
            <Button type="button" variant="ghost" aria-label={`Remove identity ${i + 1}`} icon={<Trash2 size={14} />}
              onClick={() => setIdentities(identities.filter((_, idx) => idx !== i))} />
          </div>
        ))}
        <Button type="button" size="sm" icon={<Plus size={13} />} onClick={() => setIdentities([...identities, { username: "", password: "", login_url: "" }])}>Add identity</Button>
        <div className="mt-4 border-t border-line pt-3">
          <Field label="OpenAPI spec path (optional)" hint="Server-side path to an OpenAPI 3 JSON/YAML file. Enables schema-driven API audit: BOLA, BFLA, mass assignment, exposure, missing auth.">
            <Input aria-label="OpenAPI spec path" placeholder="/abs/path/to/openapi.json" value={openapi}
              onChange={(e) => setOpenapi(e.target.value)} />
          </Field>
          <Field label="GraphQL endpoint (optional)" hint="In-scope URL of a GraphQL endpoint. Enables introspection, injection, field-authz, depth/alias/batch abuse checks.">
            <Input aria-label="GraphQL endpoint URL" placeholder="https://app.example.com/graphql" value={graphql}
              onChange={(e) => setGraphql(e.target.value)} />
          </Field>
        </div>
      </Card>

      <Card title="Login flow (optional)" description="Captured by the browser runtime after the engagement is created: form fill, submit, success assertion, session cookies stored server-side. The password is used once and never persisted.">
        {fieldErrors.login && <p className="mb-2 text-xs text-sev-high">{fieldErrors.login}</p>}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Base URL" htmlFor="lf-base" hint="In-scope origin the session belongs to.">
            <Input id="lf-base" value={login.base_url} placeholder="https://app.example.com" onChange={(e) => setLogin({ ...login, base_url: e.target.value })} />
          </Field>
          <Field label="Login URL" htmlFor="lf-url" hint="Must be inside scope.">
            <Input id="lf-url" value={login.login_url} placeholder="https://app.example.com/login" onChange={(e) => setLogin({ ...login, login_url: e.target.value })} />
          </Field>
          <Field label="Username" htmlFor="lf-user">
            <Input id="lf-user" value={login.username} placeholder="tester" onChange={(e) => setLogin({ ...login, username: e.target.value })} />
          </Field>
          <Field label="Password" htmlFor="lf-pass" hint="Used for this attempt only.">
            <Input id="lf-pass" type="password" autoComplete="new-password" value={login.password} onChange={(e) => setLogin({ ...login, password: e.target.value })} />
          </Field>
          <Field label="Success assertion" htmlFor="lf-assert" hint="CSS selector that only exists after login.">
            <Input id="lf-assert" value={login.success} placeholder="[data-testid=dashboard]" onChange={(e) => setLogin({ ...login, success: e.target.value })} />
          </Field>
          <Field label="Field selectors (JSON)" htmlFor="lf-sel" error={fieldErrors.selectors} hint='Optional CSS selectors, e.g. {"username":"#user"} — omit to use standard login input names.'>
            <Input id="lf-sel" value={login.selectors} className="font-mono text-xs" placeholder='{"username":"#user"}' error={!!fieldErrors.selectors}
              onChange={(e) => setLogin({ ...login, selectors: e.target.value })} />
          </Field>
        </div>
      </Card>

      <Card title="Workflow (optional)" description="Recorded browser steps run after creation. Each navigation is scope-checked; extract/assert steps capture evidence.">
        <div className="grid gap-3">
          <Field label="Workflow name" htmlFor="wf-name">
            <Input id="wf-name" value={workflow.name} placeholder="checkout funnel" onChange={(e) => setWorkflow({ ...workflow, name: e.target.value })} />
          </Field>
          <Field label="Steps (JSON array)" htmlFor="wf-steps" error={fieldErrors.steps}
            hint='actions: navigate | click | fill | submit | extract | assert'>
            <Textarea id="wf-steps" rows={5} className="font-mono text-xs" value={workflow.steps} error={!!fieldErrors.steps}
              placeholder={'[\n  {"action":"navigate","url":"https://app.example.com/"},\n  {"action":"click","selector":"a[href=\\"/billing\\"]"},\n  {"action":"assert","selector":".invoice"}\n]'}
              onChange={(e) => setWorkflow({ ...workflow, steps: e.target.value })} />
          </Field>
        </div>
      </Card>

      <Card title="Advanced test hints" description="Optional JSON forwarded to the planner as structured hints. Not executable.">
        <button type="button" onClick={() => setHintsOpen(!hintsOpen)} className="inline-flex items-center gap-1 text-sm text-ink-700 hover:text-ink-900">
          <ChevronDown size={14} className={cx("transition-transform duration-150", hintsOpen && "rotate-180")} />
          {hintsOpen ? "Hide hints" : "Add hints"}
        </button>
        {hintsOpen && (
          <div className="mt-3">
            <Textarea aria-label="Test hints JSON" rows={6} value={hints} onChange={(e) => setHints(e.target.value)}
              placeholder={'{\n  "focus": "authentication",\n  "notes": "test account provided"\n}'}
              className="font-mono text-xs" error={!!fieldErrors.hints} />
            {fieldErrors.hints && <p className="mt-1 text-xs text-sev-high">{fieldErrors.hints}</p>}
          </div>
        )}
      </Card>

      <div className="flex items-center justify-between gap-3 border-t border-line pt-4">
        <p className="text-xs text-ink-500">Scope is validated server-side. Empty scope is rejected.</p>
        <div className="flex gap-2">
          <Button type="button" variant="ghost" onClick={() => navigate("/")}>Cancel</Button>
          <Button type="submit" variant="primary" loading={busy}>Create engagement</Button>
        </div>
      </div>
    </form>
  );
}