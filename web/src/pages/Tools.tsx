import { Fragment, useState } from "react";
import { CheckCircle2, CircleSlash, Wrench, X } from "lucide-react";
import { qs } from "../api";
import type { Engagement, ToolCall, ToolInfo } from "../types";
import { useApi } from "../lib/hooks";
import { fmtDuration, fmtTime } from "../lib/format";
import { Badge, Card, CodeBlock, EmptyState, ErrorNote, JsonViewer, Select, Table, TableSkeleton } from "../components/ui";

export default function Tools() {
  const registry = useApi<{ version: string; tools: ToolInfo[] }>("/api/health");
  const engagements = useApi<Engagement[]>("/api/engagements");
  const [eid, setEid] = useState("");
  const selected = eid || engagements.data?.[0]?.id || "";
  const calls = useApi<ToolCall[]>(selected ? `/api/engagements/${selected}/tool-calls${qs({ live: 1 })}` : null);
  const [spec, setSpec] = useState<ToolInfo | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const tools = registry.data?.tools || [];
  const available = tools.filter((t) => t.available).length;
  const failed = (calls.data || []).filter((c) => c.error || (c.exit_code && c.exit_code !== 0));

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-900">Tool center</h1>
        <p className="mt-1 text-sm text-ink-500">
          {registry.loading ? "Loading…" : `${available} of ${tools.length} tools available`} · every invocation is scope-checked and audited
          {registry.data?.version ? ` · backend ${registry.data.version}` : ""}
        </p>
      </div>

      <ErrorNote error={registry.error} />

      <Card padded={false} title={<span className="inline-flex items-center gap-1.5"><Wrench size={14} className="text-ink-500" /> Registry</span>}
        description="Available tools with their contract. Missing tools reduce coverage and surface as degradations.">
        {registry.loading && !registry.data ? <TableSkeleton rows={6} cols={4} /> : !tools.length ? (
          <EmptyState title="No tool registry" description="The backend reported no tools." />
        ) : (
          <Table<ToolInfo>
            rows={tools}
            getKey={(t) => t.name}
            onRowClick={(t) => setSpec(t)}
            columns={[
              { key: "name", label: "Tool", render: (t) => <span className="font-mono text-xs font-medium">{t.name}</span> },
              { key: "category", label: "Category", sortValue: (t) => t.category, render: (t) => <span className="text-xs capitalize text-ink-700">{t.category}</span> },
              {
                key: "available", label: "Availability", sortValue: (t) => (t.available ? 0 : 1),
                render: (t) => t.available
                  ? <span className="inline-flex items-center gap-1 text-xs text-[#027A48]"><CheckCircle2 size={12} /> installed</span>
                  : <span className="inline-flex items-center gap-1 text-xs text-ink-500"><CircleSlash size={12} /> missing</span>,
              },
              {
                key: "flags", label: "Contract",
                render: (t) => <span className="flex gap-1">{t.read_only && <Badge tone="info">read-only</Badge>}{t.destructive && <Badge tone="danger">destructive</Badge>}</span>,
              },
              { key: "params", label: "Parameters", align: "right", render: (t) => <span className="tabular-nums text-ink-700">{Object.keys(t.parameters?.properties || {}).length}</span> },
              { key: "description", label: "Description", render: (t) => <span className="block max-w-[420px] text-xs text-ink-500">{t.description}</span> },
            ]}
          />
        )}
      </Card>

      {spec && (
        <Card title={<span className="inline-flex items-center gap-2 font-mono text-xs">{spec.name}
          <Badge tone={spec.available ? "success" : "neutral"}>{spec.available ? "installed" : "missing"}</Badge></span>}
          description={spec.description}
          actions={<button onClick={() => setSpec(null)} aria-label="Close tool spec" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900"><X size={14} /></button>}>
          <div className="grid gap-4 lg:grid-cols-2">
            <JsonViewer value={spec.parameters || {}} maxHeight={360} />
            <div className="space-y-2 text-xs">
              <div><span className="text-ink-500">category</span> <span className="text-ink-900">{spec.category}</span></div>
              <div><span className="text-ink-500">read-only</span> <span className="text-ink-900">{String(spec.read_only)}</span></div>
              <div><span className="text-ink-500">destructive</span> <span className="text-ink-900">{String(spec.destructive)}</span></div>
              <div><span className="text-ink-500">required</span> <span className="font-mono text-ink-900">{(spec.parameters?.required || []).join(", ") || "none"}</span></div>
              <p className="pt-2 leading-relaxed text-ink-500">
                Parameters are validated deterministically before execution: unknown, missing or mistyped parameters are rejected, then the
                scope engine decides whether the call may egress.
              </p>
            </div>
          </div>
        </Card>
      )}

      <Card padded={false} title="Execution history" description="Every recorded invocation for one engagement, with the structured invocation and any error."
        actions={
          <div className="flex items-center gap-2">
            {failed.length > 0 && <Badge tone="danger">{failed.length} failing</Badge>}
            <Select aria-label="Engagement for execution history" value={selected} onChange={(e) => setEid(e.target.value)} className="h-7 w-[220px] text-xs">
              {(engagements.data || []).map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
            </Select>
          </div>
        }>
        <ErrorNote error={calls.error} />
        {!selected ? <EmptyState title="No engagements" description="Create an engagement to see tool execution history." />
          : calls.loading && !calls.data ? <TableSkeleton rows={5} cols={6} />
          : !(calls.data || []).length ? <EmptyState title="No tool calls recorded" description="Calls appear once the engagement runs a check." />
          : (
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr><th>Tool</th><th>Target</th><th>Scope</th><th className="text-right">Exit</th><th className="text-right">Duration</th><th>When</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {(calls.data || []).map((c) => (
                    <Fragment key={c.id}>
                      <tr className="cursor-pointer" onClick={() => setOpen(open === c.id ? null : c.id)}>
                        <td><span className="font-mono text-xs font-medium">{c.tool}</span></td>
                        <td><span className="block max-w-[160px] truncate font-mono text-2xs text-ink-700 sm:max-w-[300px]" title={c.target || ""}>{c.target || "—"}</span></td>
                        <td>{c.scope_decision
                          ? <Badge tone={c.scope_decision.startsWith("refused") ? "critical" : "success"}>{c.scope_decision.startsWith("refused") ? "refused" : "allowed"}</Badge>
                          : <span className="text-ink-300">—</span>}</td>
                        <td className="text-right tabular-nums"><span className={c.exit_code ? "text-sev-high" : "text-ink-700"}>{c.exit_code ?? "—"}</span></td>
                        <td className="text-right tabular-nums text-ink-700">{fmtDuration(c.duration_ms)}</td>
                        <td className="whitespace-nowrap text-xs text-ink-500">{fmtTime(c.created_at)}</td>
                        <td>{c.error ? <Badge tone="danger" dot>error</Badge> : <Badge tone="success" dot>ok</Badge>}</td>
                      </tr>
                      {open === c.id && (
                        <tr>
                          <td colSpan={7} className="bg-canvas">
                            <div className="space-y-2">
                              {c.scope_decision && <div className="text-xs text-ink-500">scope decision: <span className="font-mono text-ink-700">{c.scope_decision}</span></div>}
                              {c.error && <ErrorNote error={c.error} />}
                              <CodeBlock label="argv (structured)" content={JSON.stringify({ tool: c.tool, argv: c.argv || [], target: c.target, exit_code: c.exit_code }, null, 2)} maxHeight={200} />
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </Card>
    </div>
  );
}