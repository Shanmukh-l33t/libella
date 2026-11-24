import { Fragment, useState } from "react";
import { Gauge, Wrench, X } from "lucide-react";
import { post, qs } from "../api";
import type { Engagement, ToolCall, ToolInfo, ToolReadiness, ToolReadinessReport } from "../types";
import { useApi } from "../lib/hooks";
import { callVerdict, fmtDuration, fmtTime } from "../lib/format";
import { Badge, Button, Card, CodeBlock, EmptyState, ErrorNote, JsonViewer, Select, Table, TableSkeleton } from "../components/ui";

// A readiness badge must never read "ready" for a degraded tool.
const TONE: Record<string, "success" | "info" | "warning" | "danger" | "neutral"> = {
  assessment_ready: "success", functional: "info", compatible: "warning",
  degraded: "warning", installed: "danger", missing: "neutral", unverified: "neutral",
};
const label = (status: string) => status.replace(/_/g, " ");

export default function Tools() {
  const registry = useApi<ToolInfo[]>("/api/tools");
  const readinessReport = useApi<ToolReadinessReport>("/api/tools/readiness");
  const info = useApi<{ version: string }>("/api/health");
  const engagements = useApi<Engagement[]>("/api/engagements");
  const [eid, setEid] = useState("");
  const selected = eid || engagements.data?.[0]?.id || "";
  const calls = useApi<ToolCall[]>(selected ? `/api/engagements/${selected}/tool-calls${qs({ live: 1 })}` : null);
  const [spec, setSpec] = useState<ToolInfo | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [checking, setChecking] = useState<string | null>(null);
  const [rows, setRows] = useState<Record<string, ToolReadiness>>({});

  const readiness = Object.fromEntries((readinessReport.data?.tools || []).map((r) => [r.name, r]));
  const rowFor = (name: string) => rows[name] || readiness[name];

  async function runDiagnostic(name: string) {
    setChecking(name);
    try {
      const result = await post<ToolReadiness>(`/api/tools/${encodeURIComponent(name)}/readiness`);
      setRows((prev) => ({ ...prev, [name]: result }));
    } catch {
      setRows((prev) => ({ ...prev, [name]: {
        name, status: "unverified", level: "unverified", version: null, minimum: null,
        degraded: false, limitations: [], detail: "The backend could not complete the diagnostic.",
      } }));
    } finally {
      setChecking(null);
    }
  }

  const tools = registry.data || [];
  const available = tools.filter((t) => t.available).length;
  const proven = tools.filter((t) => rowFor(t.name)?.status === "assessment_ready").length;
  const extras = (readinessReport.data?.tools || []).filter((r) => !tools.some((t) => t.name === r.name));
  const failed = (calls.data || []).filter((c) => c.error || (c.exit_code && c.exit_code !== 0));

  const cell = (name: string) => {
    const row = rowFor(name);
    if (!row) return <span className="text-xs text-ink-500">not checked</span>;
    return (
      <div className="max-w-[320px] space-y-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge tone={TONE[row.status] || "neutral"} dot>{label(row.status)}</Badge>
          {row.version && <span className="font-mono text-2xs text-ink-500">v{row.version}</span>}
          <Button size="sm" variant="ghost" disabled={checking !== null}
            loading={checking === name}
            onClick={(e) => { e.stopPropagation(); void runDiagnostic(name); }}>
            Run diagnostic
          </Button>
        </div>
        {row.limitations.length > 0 && (
          <p className="text-2xs leading-snug text-[#B54708]" title={row.limitations.join(" · ")}>
            {row.limitations[0]}
          </p>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-900">Tool center</h1>
        <p className="mt-1 text-sm text-ink-500">
          {registry.loading ? "Loading…" : `${available} of ${tools.length} tools installed`}
          {readinessReport.data ? ` · ${proven} assessment-ready` : ""} · every invocation is scope-checked and audited
          {info.data?.version ? ` · backend ${info.data.version}` : ""}
        </p>
      </div>

      <ErrorNote error={registry.error} />
      <ErrorNote error={readinessReport.error} />

      <Card padded={false} title={<span className="inline-flex items-center gap-1.5"><Wrench size={14} className="text-ink-500" /> Registry</span>}
        description="Each tool is probed for real: installed, compatible, functional, and assessment-ready against a local fixture. A degenerate build shows as degraded, never ready.">
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
                key: "readiness", label: "Readiness",
                sortValue: (t) => ["assessment_ready", "functional", "compatible", "installed", "degraded", "missing"].indexOf(rowFor(t.name)?.status || "missing"),
                render: (t) => cell(t.name),
              },
              {
                key: "flags", label: "Contract",
                render: (t) => <span className="flex gap-1">{t.read_only && <Badge tone="info">read-only</Badge>}{t.destructive && <Badge tone="danger">destructive</Badge>}</span>,
              },
              { key: "description", label: "Description", render: (t) => <span className="block max-w-[420px] text-xs text-ink-500">{t.description}</span> },
            ]}
          />
        )}
      </Card>

      {extras.length > 0 && (
        <Card padded={false} title={<span className="inline-flex items-center gap-1.5"><Gauge size={14} className="text-ink-500" /> Gated capabilities</span>}
          description="Capabilities Libella uses mid-assessment that are not scanner binaries. Same levels, same local-fixture checks.">
          <ul className="divide-y divide-line/70">
            {extras.map((r) => (
              <li key={r.name} className="flex flex-wrap items-center justify-between gap-3 px-3 py-3">
                <span className="font-mono text-xs font-medium">{r.name}</span>
                {cell(r.name)}
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card title={<span className="inline-flex items-center gap-1.5"><Gauge size={14} className="text-ink-500" /> What the levels mean</span>}
        description="A higher level is a stronger claim. Only assessment-ready means Libella ran the tool against a controlled local fixture and parsed its output.">
        <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
          {(readinessReport.data?.levels || []).map((level) => (
            <div key={level.name} className="flex gap-2">
              <dt className="w-[122px] shrink-0"><Badge tone={TONE[level.name] || "neutral"}>{label(level.name)}</Badge></dt>
              <dd className="text-ink-700">{level.meaning}</dd>
            </div>
          ))}
        </dl>
      </Card>

      {spec && (
        <Card title={<span className="inline-flex items-center gap-2 font-mono text-xs">{spec.name}
          <Badge tone={TONE[rowFor(spec.name)?.status || (spec.available ? "installed" : "missing")] || "neutral"}>
            {label(rowFor(spec.name)?.status || (spec.available ? "installed" : "missing"))}
          </Badge></span>}
          description={spec.description}
          actions={<button onClick={() => setSpec(null)} aria-label="Close tool spec" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900"><X size={14} /></button>}>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Button size="sm" disabled={checking !== null} loading={checking === spec.name} onClick={() => void runDiagnostic(spec.name)}>Run diagnostic</Button>
            <p className="text-xs text-ink-500">Runs the tool against a local fixture (127.0.0.1). It never touches an external target.</p>
            {rowFor(spec.name) && <p role="status" className="w-full text-sm text-ink-700">{rowFor(spec.name)!.detail}</p>}
            {rowFor(spec.name)?.limitations.length ? (
              <ul className="w-full list-disc space-y-1 pl-5 text-xs text-[#B54708]">
                {rowFor(spec.name)!.limitations.map((text) => <li key={text}>{text}</li>)}
              </ul>
            ) : null}
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <JsonViewer value={spec.parameters || {}} maxHeight={360} />
            <div className="space-y-2 text-xs">
              <div><span className="text-ink-500">category</span> <span className="text-ink-900">{spec.category}</span></div>
              <div><span className="text-ink-500">read-only</span> <span className="text-ink-900">{String(spec.read_only)}</span></div>
              <div><span className="text-ink-500">destructive</span> <span className="text-ink-900">{String(spec.destructive)}</span></div>
              <div><span className="text-ink-500">version</span> <span className="font-mono text-ink-900">{rowFor(spec.name)?.version || "unknown"}</span>
                {rowFor(spec.name)?.minimum && <span className="text-ink-500"> · minimum {rowFor(spec.name)!.minimum}</span>}</div>
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
                          ? <Badge tone={callVerdict(c.scope_decision).tone}>{callVerdict(c.scope_decision).label}</Badge>
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