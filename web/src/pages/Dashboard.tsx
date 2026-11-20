import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Plus, RefreshCw, Wrench } from "lucide-react";
import { get } from "../api";
import type { Engagement, Finding, ToolInfo } from "../types";
import { useApi } from "../lib/hooks";
import { SEV_COLOR, SEV_ORDER, elapsed, fmtDate, fmtTime, statusTone, title } from "../lib/format";
import { Badge, Button, Card, ErrorNote, TableSkeleton, Table, EmptyState, cx } from "../components/ui";
import { SeverityCounts } from "../components/bits";

type SevMap = Record<string, Record<string, number>>;

export default function Dashboard() {
  const navigate = useNavigate();
  const list = useApi<Engagement[]>("/api/engagements");
  const health = useApi<{ version: string; tools: ToolInfo[] }>("/api/health");
  const [sev, setSev] = useState<SevMap>({});

  useEffect(() => {
    if (!list.data) return;
    let alive = true;
    Promise.all(
      list.data.map((e) =>
        get<Finding[]>(`/api/engagements/${e.id}/findings`)
          .then((fs) => {
            const counts: Record<string, number> = {};
            for (const f of fs) counts[f.severity] = (counts[f.severity] || 0) + 1;
            return [e.id, counts] as const;
          })
          .catch(() => [e.id, {}] as const),
      ),
    ).then((entries) => { if (alive) setSev(Object.fromEntries(entries)); });
    return () => { alive = false; };
  }, [list.data]);

  const engagements = list.data || [];
  const tools = health.data?.tools || [];
  const available = tools.filter((t) => t.available).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-ink-900">Engagements</h1>
          <p className="mt-1 text-sm text-ink-500">
            {list.loading ? "Loading…" : `${engagements.length} total · every result traced to captured evidence`}
          </p>
        </div>
        <div className="flex gap-2">
          <Button icon={<RefreshCw size={14} />} onClick={() => { list.reload(); health.reload(); }} disabled={list.loading}
            aria-label="Refresh engagements">Refresh</Button>
          <Button variant="primary" icon={<Plus size={15} />} onClick={() => navigate("/engagements/new")}>New engagement</Button>
        </div>
      </div>

      <ErrorNote error={list.error} />

      <Card padded={false}>
        {list.loading && !list.data ? (
          <TableSkeleton rows={4} cols={6} />
        ) : (
          <Table<Engagement>
            rows={engagements}
            getKey={(e) => e.id}
            onRowClick={(e) => navigate(`/engagements/${e.id}`)}
            empty={
              <EmptyState
                title="No engagements yet"
                description="Create an engagement with an in-scope target, then start it. Findings appear only after evidence is captured."
                action={<Button variant="primary" icon={<Plus size={15} />} onClick={() => navigate("/engagements/new")}>New engagement</Button>}
              />
            }
            columns={[
              {
                key: "name", label: "Engagement", sortValue: (e) => e.name,
                render: (e) => (
                  <div>
                    <div className="font-medium text-ink-900">{e.name}</div>
                    <div className="mt-0.5 font-mono text-2xs text-ink-500">{e.id} · {e.scope?.targets?.length || 0} target{(e.scope?.targets?.length || 0) === 1 ? "" : "s"}</div>
                  </div>
                ),
              },
              {
                key: "status", label: "Status", sortValue: (e) => e.status,
                render: (e) => (
                  <div title={e.status_detail || undefined}>
                    <Badge tone={statusTone(e.status)} dot>{title(e.status)}</Badge>
                    {e.status_detail && !["running", "paused", "draft"].includes(e.status) && (
                      <div className="mt-1 max-w-[180px] truncate text-2xs text-ink-500" title={e.status_detail}>{e.status_detail}</div>
                    )}
                  </div>
                ),
              },
              { key: "profile", label: "Profile", sortValue: (e) => e.profile, render: (e) => <span className="text-sm text-ink-700">{title(e.profile)}</span> },
              {
                key: "findings", label: "Findings",
                render: (e) => <SeverityCounts counts={sev[e.id] || {}} />,
              },
              { key: "created", label: "Created", sortValue: (e) => e.created_at, render: (e) => <span className="whitespace-nowrap text-ink-700" title={fmtTime(e.created_at)}>{fmtDate(e.created_at)}</span> },
              {
                key: "duration", label: "Duration", align: "right", sortValue: (e) => (e.started_at ? (e.finished_at || Date.now() / 1000) - e.started_at : -1),
                render: (e) => <span className="text-ink-700">{e.started_at ? elapsed(e.started_at, e.finished_at) : "—"}</span>,
              },
            ]}
          />
        )}
      </Card>
      {engagements.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-1 text-2xs text-ink-500">
          <span>Findings by severity:</span>
          {SEV_ORDER.map((s) => (
            <span key={s} className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-sm" style={{ background: SEV_COLOR[s] }} />{s}
            </span>
          ))}
        </div>
      )}

      <Card
        title={<span className="inline-flex items-center gap-1.5"><Wrench size={14} className="text-ink-500" /> Tool availability</span>}
        description={health.error ? "Backend unreachable" : `${available} of ${tools.length} tools installed · missing tools reduce coverage and appear as degradations`}
        actions={<Link to="/settings" className="link text-xs">Manage</Link>}
      >
        {health.loading && !health.data ? (
          <div className="flex flex-wrap gap-2">{Array.from({ length: 8 }).map((_, i) => <div key={i} className="h-6 w-24 animate-pulse rounded bg-ink-100" />)}</div>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {tools.map((t) => (
              <span key={t.name} title={`${t.category} · ${t.available ? "installed" : "not installed"} — ${t.description}`}
                className={cx("inline-flex items-center gap-1.5 rounded border px-2 py-1 font-mono text-2xs transition-colors",
                  t.available ? "border-line bg-white text-ink-700" : "border-dashed border-line bg-canvas text-ink-300")}>
                <span className={cx("h-1.5 w-1.5 rounded-full", t.available ? "bg-sev-low" : "bg-ink-300")} />
                {t.name}
              </span>
            ))}
            {!tools.length && <span className="text-sm text-ink-500">No tool registry reported.</span>}
          </div>
        )}
      </Card>

      <ErrorNote error={health.error} />
      <p className="text-xs text-ink-500">
        Profiles — <span className="text-ink-700">passive</span>: observe only · <span className="text-ink-700">safe active</span>: non-destructive checks ·
        <span className="text-ink-700"> advanced validation</span>: adds independent replay proof. Findings only exist with captured evidence.
      </p>
    </div>
  );
}