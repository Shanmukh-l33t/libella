import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Cpu, Save } from "lucide-react";
import { put } from "../api";
import type { AgentRun, Engagement, Settings as S } from "../types";
import { useApi } from "../lib/hooks";
import { fmtTime, money, runTone, title } from "../lib/format";
import { Badge, Button, Card, EmptyState, ErrorNote, Field, Input, Select, Skeleton, Table, TableSkeleton, useToast } from "../components/ui";

const ROLES = [
  { id: "planner", hint: "Decomposes objectives into intents." },
  { id: "recon", hint: "Maps hosts, routes and content." },
  { id: "web", hint: "Web checks and client-side surface." },
  { id: "api", hint: "Schema-driven API auditing." },
  { id: "authz", hint: "Authentication and authorization paths." },
  { id: "infra", hint: "Service and transport posture." },
  { id: "code", hint: "Source and supply-chain review." },
  { id: "cloud", hint: "Read-only cloud posture." },
  { id: "verifier", hint: "Independent replay verification." },
  { id: "correlator", hint: "Links observations across surfaces." },
  { id: "risk", hint: "Severity and impact reasoning." },
  { id: "reporter", hint: "Narrative only — never evidence." },
  { id: "retester", hint: "Re-checks remediated findings." },
  { id: "auditor", hint: "Reviews agent output against policy." },
];

export default function Models() {
  const cfg = useApi<S>("/api/settings");
  const engagements = useApi<Engagement[]>("/api/engagements");
  const toast = useToast();
  const [eid, setEid] = useState("");
  const [models, setModels] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected = eid || engagements.data?.[0]?.id || "";
  const runs = useApi<AgentRun[]>(selected ? `/api/engagements/${selected}/agent-runs?live=1` : null);

  useEffect(() => { if (cfg.data) setModels(cfg.data.llm?.models || {}); }, [cfg.data]);

  const usage = useMemo(() => {
    const m = new Map<string, { runs: number; iter: number; tin: number; tout: number; cost: number; models: Set<string>; failed: number }>();
    for (const r of runs.data || []) {
      const u = m.get(r.role) || { runs: 0, iter: 0, tin: 0, tout: 0, cost: 0, models: new Set<string>(), failed: 0 };
      u.runs += 1; u.iter += r.iterations || 0; u.tin += r.tokens_in || 0; u.tout += r.tokens_out || 0;
      u.cost += r.cost_usd || 0;
      if (r.model) u.models.add(r.model);
      if (r.status === "failed" || r.status === "budget_exhausted") u.failed += 1;
      m.set(r.role, u);
    }
    return m;
  }, [runs.data]);

  const total = [...usage.values()].reduce((a, u) => ({ tin: a.tin + u.tin, tout: a.tout + u.tout, cost: a.cost + u.cost }), { tin: 0, tout: 0, cost: 0 });
  const engagement = (engagements.data || []).find((e) => e.id === selected);
  const budget = engagement?.budgets?.max_usd;

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await put("/api/settings", { llm: { models: Object.fromEntries(Object.entries(models).filter(([, v]) => v && v.trim())) } });
      toast("Role model assignments saved.", "success");
      cfg.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const defaultModel = cfg.data?.llm?.default_model || "";

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-ink-900">Models &amp; usage</h1>
          <p className="mt-1 text-sm text-ink-500">
            Per-role routing and the token/cost accounting recorded by the agent runtime.
            {defaultModel ? <> Default model <span className="font-mono text-ink-700">{defaultModel}</span>.</> : " No default model configured."}
          </p>
        </div>
        <Link to="/settings" className="link text-xs">Provider &amp; API key</Link>
      </div>

      <ErrorNote error={error || cfg.error} />

      <Card title={<span className="inline-flex items-center gap-1.5"><Cpu size={14} className="text-ink-500" /> Role assignment</span>}
        description="Each specialist role can use a different model. Blank inherits the default."
        actions={<Button size="sm" variant="primary" icon={<Save size={13} />} loading={busy} onClick={save}>Save assignments</Button>}>
        {cfg.loading && !cfg.data ? <Skeleton className="h-40 w-full" /> : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {ROLES.map((r) => (
              <Field key={r.id} label={title(r.id)} htmlFor={`model-${r.id}`} hint={r.hint}>
                <Input id={`model-${r.id}`} value={models[r.id] || ""} placeholder={defaultModel || "inherit default"}
                  onChange={(e) => setModels({ ...models, [r.id]: e.target.value })} className="font-mono text-xs" />
              </Field>
            ))}
          </div>
        )}
      </Card>

      <Card title="Usage" description="Recorded per agent run: iterations, tokens and cost. Nothing is estimated."
        padded={false}
        actions={<Select aria-label="Engagement for usage" value={selected} onChange={(e) => setEid(e.target.value)} className="h-7 w-[220px] text-xs">
          {(engagements.data || []).map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
        </Select>}>
        <ErrorNote error={runs.error} />
        <div className="grid gap-3 border-b border-line p-4 sm:grid-cols-4">
          <Mini label="Input tokens" value={total.tin.toLocaleString()} />
          <Mini label="Output tokens" value={total.tout.toLocaleString()} />
          <Mini label="Cost" value={money(total.cost)} />
          <Mini label="Budget" value={budget !== undefined && budget !== null ? money(budget) : "no cap"}
            hint={budget ? `${Math.round((total.cost / budget) * 100)}% used` : undefined} />
        </div>
        {!selected ? <EmptyState title="No engagements" description="Usage appears once an engagement has run." />
          : runs.loading && !runs.data ? <TableSkeleton rows={4} cols={5} />
          : !(runs.data || []).length ? <EmptyState title="No runs recorded" description="Agent runs appear when an engagement runs in agent mode." />
          : (
            <Table<AgentRun>
              rows={runs.data || []}
              getKey={(r) => r.id}
              columns={[
                { key: "role", label: "Role", sortValue: (r) => r.role, render: (r) => <span className="font-medium">{title(r.role)}</span> },
                { key: "model", label: "Model", render: (r) => <span className="font-mono text-2xs text-ink-700">{r.model || "—"}</span> },
                { key: "status", label: "Status", sortValue: (r) => r.status, render: (r) => <Badge tone={runTone(r.status)} dot>{title(r.status)}</Badge> },
                { key: "iterations", label: "Iter", align: "right", sortValue: (r) => r.iterations, render: (r) => <span className="tabular-nums">{r.iterations}</span> },
                { key: "tokens", label: "Tokens", align: "right", sortValue: (r) => (r.tokens_in || 0) + (r.tokens_out || 0), render: (r) => (
                  <span className="tabular-nums text-ink-700">{(r.tokens_in || 0).toLocaleString()} / {(r.tokens_out || 0).toLocaleString()}</span>
                ) },
                { key: "cost", label: "Cost", align: "right", sortValue: (r) => r.cost_usd, render: (r) => <span className="tabular-nums">{money(r.cost_usd)}</span> },
                { key: "started", label: "Started", sortValue: (r) => r.started_at || 0, render: (r) => <span className="whitespace-nowrap text-xs text-ink-500">{fmtTime(r.started_at)}</span> },
              ]}
            />
          )}
        {usage.size > 0 && (
          <div className="border-t border-line p-4">
            <div className="mb-2 text-xs font-medium text-ink-700">By role</div>
            <div className="flex flex-wrap gap-2">
              {[...usage.entries()].map(([role, u]) => (
                <span key={role} className="rounded border border-line px-2.5 py-1.5 text-2xs text-ink-700">
                  <span className="font-medium text-ink-900">{title(role)}</span> · {u.runs} runs · {(u.tin + u.tout).toLocaleString()} tok · {money(u.cost)}
                  {u.failed ? <span className="text-sev-high"> · {u.failed} failed</span> : null}
                </span>
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function Mini({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <div className="text-2xs text-ink-500">{label}</div>
      <div className="text-base font-semibold tabular-nums text-ink-900">{value}</div>
      {hint && <div className="text-2xs text-ink-500">{hint}</div>}
    </div>
  );
}