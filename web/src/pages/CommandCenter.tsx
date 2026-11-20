import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Activity, AlertTriangle, ArrowRight, Bot, Plus, RefreshCw } from "lucide-react";
import { get } from "../api";
import type { AgentRun, Engagement, Event, Finding, GraphCoverage, ToolInfo } from "../types";
import { useApi } from "../lib/hooks";
import { SEV_COLOR, SEV_ORDER, elapsed, fmtTime, money, runTone, statusTone, title } from "../lib/format";
import { Badge, Button, Card, EmptyState, ErrorNote, Skeleton, Stat, Table, TableSkeleton, cx } from "../components/ui";
import { SeverityCounts } from "../components/bits";

interface Live {
  findings: Finding[]; runs: AgentRun[]; coverage?: GraphCoverage; events: Event[];
}

const ACTIVE = ["running", "paused"];

export default function CommandCenter() {
  const navigate = useNavigate();
  const list = useApi<Engagement[]>("/api/engagements");
  const health = useApi<{ version: string; tools: ToolInfo[] }>("/api/health");
  const [live, setLive] = useState<Record<string, Live>>({});
  const [loading, setLoading] = useState(false);
  const [partial, setPartial] = useState<string | null>(null);

  const engagements = useMemo(() => (list.data || []).slice(0, 8), [list.data]);

  // Event feed: every running assessment, plus the three most recent so a finished
  // run still shows what happened.
  const watched = useMemo(() => {
    const activeIds = new Set(engagements.filter((e) => ACTIVE.includes(e.status)).map((e) => e.id));
    return engagements.filter((e, i) => activeIds.has(e.id) || i < 3);
  }, [engagements]);

  useEffect(() => {
    if (!engagements.length) return;
    let alive = true;
    setLoading(true);
    const failed: string[] = [];
    Promise.all(engagements.map(async (e) => {
      const [findings, runs, graph, events] = await Promise.all([
        get<Finding[]>(`/api/engagements/${e.id}/findings`).catch(() => { failed.push(e.id); return [] as Finding[]; }),
        get<AgentRun[]>(`/api/engagements/${e.id}/agent-runs`).catch(() => [] as AgentRun[]),
        get<{ coverage?: GraphCoverage }>(`/api/engagements/${e.id}/graph`).catch(() => ({} as { coverage?: GraphCoverage })),
        ACTIVE.includes(e.status) || watched.some((w) => w.id === e.id)
          ? get<Event[]>(`/api/engagements/${e.id}/events?since=0`).catch(() => [] as Event[])
          : Promise.resolve([] as Event[]),
      ]);
      return [e.id, { findings, runs, coverage: graph?.coverage, events }] as const;
    })).then((rows) => {
      if (!alive) return;
      setLive(Object.fromEntries(rows));
      setPartial(failed.length ? `Partial data: findings unavailable for ${failed.length} engagement${failed.length === 1 ? "" : "s"}.` : null);
      setLoading(false);
    });
    return () => { alive = false; };
  }, [engagements]);

  const all = Object.values(live);
  const findings = all.flatMap((l) => l.findings);
  const runs = all.flatMap((l) => l.runs);
  const bySeverity: Record<string, number> = {};
  const byState: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byState[f.state] = (byState[f.state] || 0) + 1;
  }
  const validated = findings.filter((f) => ["validated", "reported", "retested_persists"].includes(f.state)).length;
  const openHyp = all.reduce((n, l) => n + (l.coverage?.hypotheses_open || 0), 0);
  const cost = runs.reduce((n, r) => n + (r.cost_usd || 0), 0);
  const active = engagements.filter((e) => ACTIVE.includes(e.status));
  const failedRuns = runs.filter((r) => r.status === "failed" || r.status === "budget_exhausted");
  const missingTools = (health.data?.tools || []).filter((t) => !t.available);
  const degradations = all.flatMap((l) => l.events.filter((ev) => ev.kind === "degradation"));

  const recent = useMemo(() =>
    all.flatMap((l) => l.events)
      .sort((a, b) => b.seq - a.seq)
      .filter((ev, i, arr) => i === 0 || `${ev.kind}|${detail(ev)}` !== `${arr[i - 1].kind}|${detail(arr[i - 1])}`)
      .slice(0, 18), [all]);

  const alerts = [
    ...degradations.slice(0, 4).map((d) => ({ key: `deg-${d.seq}`, tone: "warning" as const, title: d.payload?.code || "degradation", detail: d.payload?.detail || "" })),
    ...failedRuns.slice(0, 4).map((r) => ({ key: `run-${r.id}`, tone: "danger" as const, title: `${title(r.role)} run ${r.status.replace("_", " ")}`, detail: r.exit_reason || r.summary || "no exit reason recorded" })),
    ...(missingTools.length ? [{ key: "tools", tone: "warning" as const, title: `${missingTools.length} tool${missingTools.length === 1 ? "" : "s"} not installed`, detail: missingTools.map((t) => t.name).join(", ") }] : []),
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-ink-900">Command center</h1>
          <p className="mt-1 text-sm text-ink-500">
            {list.loading ? "Loading…" : `${active.length} active · ${engagements.length} monitored · every number traced to captured evidence`}
          </p>
        </div>
        <div className="flex gap-2">
          <Button icon={<RefreshCw size={14} />} aria-label="Refresh command center" disabled={list.loading}
            onClick={() => { list.reload(); health.reload(); }}>Refresh</Button>
          <Button variant="primary" icon={<Plus size={15} />} onClick={() => navigate("/engagements/new")}>New engagement</Button>
        </div>
      </div>

      <ErrorNote error={list.error} />
      <ErrorNote error={partial} />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Active assessments" value={list.loading ? <Skeleton className="h-6 w-8" /> : active.length}
          hint={engagements.filter((e) => e.status === "draft").length ? `${engagements.filter((e) => e.status === "draft").length} draft` : "running or paused"} />
        <Stat label="Findings" value={list.loading ? <Skeleton className="h-6 w-8" /> : findings.length} hint={`${validated} validated or persisting`} />
        <Stat label="Open hypotheses" value={list.loading ? <Skeleton className="h-6 w-8" /> : openHyp} hint="awaiting evidence" />
        <Stat label="Agent runs" value={list.loading ? <Skeleton className="h-6 w-8" /> : runs.length}
          hint={`${runs.filter((r) => r.status === "running").length} running · ${failedRuns.length} failed`} />
        <Stat label="Model spend" value={list.loading ? <Skeleton className="h-6 w-14" /> : money(cost)} hint="accounted per run" />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_380px]">
        <div className="space-y-4">
          <Card title="Active assessments" description="Live engagements with coverage and independent-validation depth." padded={false}
            actions={<Link to="/engagements" className="link text-xs">All engagements</Link>}>
            {list.loading && !list.data ? <TableSkeleton rows={3} cols={5} /> : !active.length ? (
              <EmptyState title="Nothing running" description="Start a draft engagement to see live coverage here."
                action={<Button variant="primary" icon={<Plus size={15} />} onClick={() => navigate("/engagements/new")}>New engagement</Button>} />
            ) : (
              <Table<Engagement>
                rows={active}
                getKey={(e) => e.id}
                onRowClick={(e) => navigate(`/engagements/${e.id}`)}
                columns={[
                  {
                    key: "name", label: "Engagement",
                    render: (e) => (
                      <div>
                        <div className="font-medium text-ink-900">{e.name}</div>
                        <div className="mt-0.5 text-2xs text-ink-500">{e.scope?.targets?.length || 0} target{(e.scope?.targets?.length || 0) === 1 ? "" : "s"} · {elapsed(e.started_at, e.finished_at)}</div>
                      </div>
                    ),
                  },
                  { key: "status", label: "Status", render: (e) => <Badge tone={statusTone(e.status)} dot>{title(e.status)}</Badge> },
                  {
                    key: "coverage", label: "Coverage",
                    render: (e) => {
                      const c = live[e.id]?.coverage;
                      if (!c) return <span className="text-ink-300">—</span>;
                      const pct = c.assets_total ? Math.round((c.assets_investigated / c.assets_total) * 100) : 0;
                      return (
                        <div className="w-28">
                          <div className="h-1.5 overflow-hidden rounded-full bg-ink-100">
                            <div className="h-full rounded-full bg-accent transition-all duration-300" style={{ width: `${pct}%` }} />
                          </div>
                          <div className="mt-1 text-2xs tabular-nums text-ink-500">{c.assets_investigated}/{c.assets_total} assets</div>
                        </div>
                      );
                    },
                  },
                  { key: "findings", label: "Findings", render: (e) => <SeverityCounts counts={countBy(live[e.id]?.findings || [])} /> },
                  {
                    key: "runs", label: "Agents", align: "right",
                    render: (e) => {
                      const rs = live[e.id]?.runs || [];
                      const bad = rs.filter((r) => r.status === "failed").length;
                      return <span className={cx("tabular-nums", bad ? "text-sev-high" : "text-ink-700")}>{rs.length}{bad ? ` · ${bad} failed` : ""}</span>;
                    },
                  },
                  { key: "updated", label: "Started", render: (e) => <span className="whitespace-nowrap text-xs text-ink-500">{fmtTime(e.started_at)}</span> },
                ]}
              />
            )}
          </Card>

          <Card title="Recent activity" description="Live event stream from active assessments, newest first." padded={false}
            actions={<span className="text-2xs tabular-nums text-ink-500">{recent.length} events</span>}>
            {!recent.length ? (
              <EmptyState icon={<Activity size={22} />} title="No live activity"
                description="Events appear while an assessment runs. Finished engagements keep their full event history in the engagement view." />
            ) : (
              <ol className="max-h-[420px] divide-y divide-line/70 overflow-y-auto">
                {recent.map((ev) => {
                  const bad = ev.kind === "degradation" || ev.kind === "engagement_failed" || ev.kind === "scope_refusal";
                  const eid = engagements.find((e) => live[e.id]?.events.some((x) => x.seq === ev.seq && x.kind === ev.kind))?.id;
                  return (
                    <li key={`${ev.seq}-${ev.kind}`} className="flex items-baseline gap-3 px-4 py-2">
                      <span className={cx("mt-1 h-1.5 w-1.5 shrink-0 rounded-full", bad ? "bg-[#B54708]" : "bg-ink-300")} />
                      <span className="min-w-0 flex-1">
                        <span className="text-xs font-medium text-ink-900">{title(ev.kind)}</span>
                        <span className="ml-2 break-words font-mono text-2xs text-ink-500">{detail(ev).slice(0, 160)}</span>
                      </span>
                      <span className="shrink-0 text-2xs tabular-nums text-ink-300">{fmtTime(ev.created_at)}</span>
                      {eid && <Link to={`/engagements/${eid}`} className="shrink-0 text-2xs text-ink-300 hover:text-ink-900" aria-label="Open engagement"><ArrowRight size={12} /></Link>}
                    </li>
                  );
                })}
              </ol>
            )}
          </Card>
        </div>

        <div className="space-y-4">
          <Card title={<span className="inline-flex items-center gap-1.5"><AlertTriangle size={14} className="text-ink-500" /> Operational alerts</span>}
            description="Degradations, failed runs and missing tools reduce coverage." padded={false}>
            {!alerts.length ? (
              <div className="px-4 py-6 text-sm text-ink-500">No degradations recorded. Unsupported checks would appear here rather than as clean results.</div>
            ) : (
              <ul className="divide-y divide-line/70">
                {alerts.map((a) => (
                  <li key={a.key} className="flex gap-2.5 px-4 py-2.5">
                    <span className={cx("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", a.tone === "danger" ? "bg-sev-high" : "bg-[#DC6803]")} />
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-ink-900">{a.title}</div>
                      <div className="break-words text-2xs text-ink-500">{a.detail}</div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title={<span className="inline-flex items-center gap-1.5"><Bot size={14} className="text-ink-500" /> Agent health</span>}
            description="Specialist runs by terminal state.">
            {loading && !runs.length ? <Skeleton className="h-24 w-full" /> : (
              <>
                <div className="grid grid-cols-3 gap-2">
                  {["running", "completed", "failed"].map((s) => (
                    <div key={s} className="rounded border border-line px-3 py-2">
                      <div className="text-lg font-semibold tabular-nums">{runs.filter((r) => r.status === s).length}</div>
                      <div className="text-2xs capitalize text-ink-500">{title(s)}</div>
                    </div>
                  ))}
                </div>
                {runs.length > 0 && (
                  <div className="mt-3 space-y-1.5">
                    {runs.filter((r) => r.status !== "running").slice(-4).reverse().map((r) => (
                      <div key={r.id} className="flex items-center justify-between gap-2 text-2xs">
                        <span className="truncate text-ink-700">{title(r.role)} <span className="text-ink-300">· {r.model || "no model"}</span></span>
                        <Badge tone={runTone(r.status)}>{title(r.status)}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </Card>

          <Card title="Findings by state" description="Only replay-verified findings count as validated.">
            {!findings.length ? <p className="text-sm text-ink-500">{list.loading ? "Loading…" : "No findings recorded yet."}</p> : (
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(byState).sort((a, b) => b[1] - a[1]).map(([s, n]) => (
                  <div key={s} className="rounded border border-line px-3 py-2">
                    <div className="text-base font-semibold tabular-nums">{n}</div>
                    <div className="text-2xs capitalize text-ink-500">{title(s)}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="mt-3 flex flex-wrap gap-3 border-t border-line pt-3 text-2xs text-ink-500">
              {SEV_ORDER.map((s) => (
                <span key={s} className="inline-flex items-center gap-1">
                  <span className="h-2 w-2 rounded-sm" style={{ background: SEV_COLOR[s] }} />{bySeverity[s] || 0} {s}
                </span>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function countBy(fs: Finding[]) {
  const c: Record<string, number> = {};
  for (const f of fs) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

function detail(ev: Event) {
  const p = ev.payload || {};
  return String(p.title || p.objective || p.summary || p.detail || p.code || p.role || p.key || p.state || "");
}