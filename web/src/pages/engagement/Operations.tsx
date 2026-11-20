import { Fragment, useState } from "react";
import { ChevronRight } from "lucide-react";
import type { Intent, ToolCall } from "../../types";
import { useApi } from "../../lib/hooks";
import { fmtDuration, fmtTime, intentTone, title } from "../../lib/format";
import { Badge, Card, CodeBlock, EmptyState, ErrorNote, Table, TableSkeleton, cx } from "../../components/ui";

export default function Operations({ eid, live }: { eid: string; live: number }) {
  const intents = useApi<Intent[]>(`/api/engagements/${eid}/intents?live=${live}`);
  const calls = useApi<ToolCall[]>(`/api/engagements/${eid}/tool-calls?live=${live}`);
  const [open, setOpen] = useState<string | null>(null);

  return (
    <div className="space-y-4">
      <ErrorNote error={intents.error} />
      <Card title="Intents" description="Planned units of work. Blocked intents explain why coverage stopped." padded={false}>
        {intents.loading && !intents.data ? <TableSkeleton rows={4} cols={5} /> : (
          <Table<Intent>
            rows={intents.data || []}
            getKey={(r) => r.id}
            empty={<EmptyState title="No intents yet" description="Intents are created when the engagement starts." />}
            columns={[
              { key: "role", label: "Role", sortValue: (r) => r.role, render: (r) => <span className="font-medium">{title(r.role)}</span> },
              { key: "objective", label: "Objective", render: (r) => <span className="block max-w-[560px] text-ink-700">{r.objective}</span> },
              { key: "status", label: "Status", sortValue: (r) => r.status, render: (r) => <Badge tone={intentTone(r.status)} dot>{title(r.status)}</Badge> },
              { key: "attempts", label: "Attempts", align: "right", sortValue: (r) => r.attempts, render: (r) => <span className="tabular-nums">{r.attempts}</span> },
              {
                key: "deps", label: "Deps", align: "right", sortValue: (r) => r.depends_on.length,
                render: (r) => r.depends_on.length
                  ? <span className="tabular-nums" title={r.depends_on.join("\n")}>{r.depends_on.length}</span>
                  : <span className="text-ink-300">—</span>,
              },
              { key: "created", label: "Created", sortValue: (r) => r.created_at || 0, render: (r) => <span className="whitespace-nowrap text-xs text-ink-500">{fmtTime(r.created_at)}</span> },
            ]}
          />
        )}
      </Card>

      <ErrorNote error={calls.error} />
      <Card title="Tool calls" description="Every external command is scope-checked before it runs. Expand a row for its argv." padded={false}>
        {calls.loading && !calls.data ? <TableSkeleton rows={5} cols={6} /> : !(calls.data || []).length ? (
          <EmptyState title="No tool calls yet" description="Tool calls appear when the orchestrator executes a check." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th className="w-8" />
                  <th>Tool</th><th>Target</th><th>Scope</th><th className="text-right">Exit</th><th className="text-right">Duration</th><th>When</th>
                </tr>
              </thead>
              <tbody>
                {(calls.data || []).map((c) => (
                  <Fragment key={c.id}>
                    <tr className="cursor-pointer" onClick={() => setOpen(open === c.id ? null : c.id)}>
                      <td>
                        <button aria-label={open === c.id ? "Collapse tool call" : "Expand tool call argv"} aria-expanded={open === c.id}
                          className="rounded p-0.5 text-ink-500 hover:bg-ink-100 hover:text-ink-900">
                          <ChevronRight size={13} className={cx("transition-transform duration-150", open === c.id && "rotate-90")} />
                        </button>
                      </td>
                      <td><span className="font-mono text-xs font-medium">{c.tool}</span></td>
                      <td><span className="block max-w-[320px] truncate font-mono text-xs text-ink-700" title={c.target || ""}>{c.target || "—"}</span></td>
                      <td>
                        {c.scope_decision
                          ? <Badge tone={c.scope_decision.startsWith("refused") ? "critical" : "success"}>{c.scope_decision.startsWith("refused") ? "refused" : "allowed"}</Badge>
                          : <span className="text-ink-300">—</span>}
                      </td>
                      <td className="text-right tabular-nums">
                        <span className={cx(c.exit_code ? "text-sev-high" : "text-ink-700")}>{c.exit_code ?? "—"}</span>
                      </td>
                      <td className="text-right tabular-nums text-ink-700">{fmtDuration(c.duration_ms)}</td>
                      <td className="whitespace-nowrap text-xs text-ink-500">{fmtTime(c.created_at)}</td>
                    </tr>
                    {open === c.id && (
                      <tr>
                        <td colSpan={7} className="bg-canvas">
                          {c.scope_decision && <div className="mb-2 text-xs text-ink-500">scope decision: <span className="font-mono text-ink-700">{c.scope_decision}</span></div>}
                          {c.error && <div className="mb-2 text-xs text-sev-high">{c.error}</div>}
                          <CodeBlock label="argv" content={(c.argv || []).map((a) => JSON.stringify(a)).join(" ")} maxHeight={160} />
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
