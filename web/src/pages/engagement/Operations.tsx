import { Fragment, useMemo, useState } from "react";
import { ChevronRight, ClipboardList } from "lucide-react";
import type { AgentRun, Hypothesis, Intent, InvestigationStep, ToolCall } from "../../types";
import { useApi } from "../../lib/hooks";
import { ACTION_KIND, fmtDuration, fmtTime, hypothesisTone, intentTone, money, runTone, title } from "../../lib/format";
import { Badge, Card, CodeBlock, EmptyState, ErrorNote, Table, TableSkeleton, cx } from "../../components/ui";

const KIND_TONE: Record<string, string> = {
  reason: "#98A2B3", tool_call: "#175CD3", observation: "#039855",
  hypothesis: "#DC6803", conclusion: "#027A48", delegation: "#667085",
};

export default function Operations({ eid, live }: { eid: string; live: number }) {
  const intents = useApi<Intent[]>(`/api/engagements/${eid}/intents?live=${live}`);
  const calls = useApi<ToolCall[]>(`/api/engagements/${eid}/tool-calls?live=${live}`);
  const runs = useApi<AgentRun[]>(`/api/engagements/${eid}/agent-runs?live=${live}`);
  const steps = useApi<InvestigationStep[]>(`/api/engagements/${eid}/investigation?live=${live}`);
  const hyps = useApi<Hypothesis[]>(`/api/engagements/${eid}/hypotheses?live=${live}`);
  const [openRun, setOpenRun] = useState<string | null>(null);
  const [openCall, setOpenCall] = useState<string | null>(null);

  const stepsByRun = useMemo(() => {
    const m = new Map<string, InvestigationStep[]>();
    for (const s of steps.data || []) {
      const k = s.agent_run_id || "";
      m.set(k, [...(m.get(k) || []), s]);
    }
    for (const list of m.values()) list.sort((a, b) => a.seq - b.seq);
    return m;
  }, [steps.data]);

  const intentObjective = useMemo(() => {
    const m = new Map<string, string>();
    for (const i of intents.data || []) m.set(i.id, i.objective);
    return m;
  }, [intents.data]);

  return (
    <div className="space-y-4">
      <ErrorNote error={runs.error} />
      <Card title="Agent runs" description="Specialist reasoning loops. Expand a run for its full investigation timeline."
        padded={false}
        actions={runs.data?.length ? (
          <span className="text-2xs tabular-nums text-ink-500">
            {money(runs.data.reduce((n, r) => n + (r.cost_usd || 0), 0))} · {runs.data.reduce((n, r) => n + (r.tokens_in || 0) + (r.tokens_out || 0), 0).toLocaleString()} tokens
          </span>
        ) : undefined}>
        {runs.loading && !runs.data ? <TableSkeleton rows={3} cols={7} /> : !(runs.data || []).length ? (
          <EmptyState icon={<ClipboardList size={22} />} title="No agent runs yet"
            description="Runs appear when an assessment starts in agent mode. Deterministic mode produces intents and tool calls without a reasoning loop." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th className="w-8" />
                  <th>Role</th><th>Model</th><th>Status</th>
                  <th className="text-right">Iter</th><th className="text-right">Tokens</th>
                  <th className="text-right">Cost</th><th>Exit</th>
                </tr>
              </thead>
              <tbody>
                {(runs.data || []).map((r) => (
                  <Fragment key={r.id}>
                    <tr className="cursor-pointer" onClick={() => setOpenRun(openRun === r.id ? null : r.id)}>
                      <td>
                        <button aria-label={openRun === r.id ? "Collapse run" : "Expand run timeline"} aria-expanded={openRun === r.id}
                          className="rounded p-0.5 text-ink-500 hover:bg-ink-100 hover:text-ink-900">
                          <ChevronRight size={13} className={cx("transition-transform duration-150", openRun === r.id && "rotate-90")} />
                        </button>
                      </td>
                      <td>
                        <span className="font-medium">{title(r.role)}</span>
                        {r.intent_id && intentObjective.get(r.intent_id) && (
                          <span className="mt-0.5 block max-w-[320px] truncate text-2xs text-ink-500" title={intentObjective.get(r.intent_id)}>
                            {intentObjective.get(r.intent_id)}
                          </span>
                        )}
                      </td>
                      <td><span className="font-mono text-2xs text-ink-700">{r.model || "—"}</span></td>
                      <td><Badge tone={runTone(r.status)} dot>{title(r.status)}</Badge></td>
                      <td className="text-right tabular-nums">{r.iterations ?? 0}</td>
                      <td className="text-right tabular-nums text-ink-700">{((r.tokens_in || 0) + (r.tokens_out || 0)).toLocaleString()}</td>
                      <td className="text-right tabular-nums text-ink-700">{money(r.cost_usd)}</td>
                      <td><span className="block max-w-[220px] truncate text-2xs text-ink-500" title={r.exit_reason || ""}>{r.exit_reason || "—"}</span></td>
                    </tr>
                    {openRun === r.id && (
                      <tr>
                        <td colSpan={8} className="bg-canvas">
                          <div className="space-y-3 py-1">
                            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs text-ink-500">
                              <span>run <span className="font-mono text-ink-700">{r.id}</span></span>
                              <span>started {fmtTime(r.started_at)}</span>
                              <span>finished {fmtTime(r.finished_at)}</span>
                              <span>duration {fmtDuration(r.started_at && r.finished_at ? (r.finished_at - r.started_at) * 1000 : null)}</span>
                              <span>{r.tokens_in || 0} in / {r.tokens_out || 0} out</span>
                            </div>
                            {r.summary && <p className="max-w-[820px] text-sm text-ink-700">{r.summary}</p>}
                            <Timeline steps={stepsByRun.get(r.id) || []} loading={steps.loading} />
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

      <ErrorNote error={hyps.error} />
      <Card title="Hypotheses" description="Claims the agents raised, with the confidence the runtime recorded. Hypotheses never become findings without bound evidence."
        padded={false}
        actions={hyps.data?.length ? <span className="text-2xs text-ink-500">{hyps.data.filter((h) => h.status === "supported").length} supported · {hyps.data.filter((h) => h.status === "open").length} open</span> : undefined}>
        {hyps.loading && !hyps.data ? <TableSkeleton rows={3} cols={4} /> : (
          <Table<Hypothesis>
            rows={hyps.data || []}
            getKey={(h) => h.id}
            empty={<EmptyState title="No hypotheses yet" description="Agents record hypotheses while investigating; they appear here with status and confidence." />}
            columns={[
              { key: "statement", label: "Statement", render: (h) => <span className="block max-w-[620px] text-ink-900">{h.statement}</span> },
              { key: "status", label: "Status", sortValue: (h) => h.status, render: (h) => <Badge tone={hypothesisTone(h.status)} dot>{title(h.status)}</Badge> },
              {
                key: "confidence", label: "Confidence", align: "right", sortValue: (h) => h.confidence || 0,
                render: (h) => (
                  <div className="ml-auto flex w-24 items-center gap-2">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-ink-100">
                      <div className="h-full rounded-full bg-accent" style={{ width: `${Math.round((h.confidence || 0) * 100)}%` }} />
                    </div>
                    <span className="w-8 text-right text-2xs tabular-nums text-ink-700">{Math.round((h.confidence || 0) * 100)}%</span>
                  </div>
                ),
              },
              { key: "by", label: "Raised by", render: (h) => <span className="text-xs capitalize text-ink-700">{title(h.created_by || h.kind || "agent")}</span> },
              { key: "at", label: "When", render: (h) => <span className="whitespace-nowrap text-xs text-ink-500">{fmtTime(h.updated_at || h.created_at)}</span> },
            ]}
          />
        )}
      </Card>

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
                    <tr className="cursor-pointer" onClick={() => setOpenCall(openCall === c.id ? null : c.id)}>
                      <td>
                        <button aria-label={openCall === c.id ? "Collapse tool call" : "Expand tool call argv"} aria-expanded={openCall === c.id}
                          className="rounded p-0.5 text-ink-500 hover:bg-ink-100 hover:text-ink-900">
                          <ChevronRight size={13} className={cx("transition-transform duration-150", openCall === c.id && "rotate-90")} />
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
                    {openCall === c.id && (
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

function Timeline({ steps, loading }: { steps: InvestigationStep[]; loading: boolean }) {
  if (loading && !steps.length) return <div className="text-xs text-ink-500">Loading timeline…</div>;
  if (!steps.length) return <div className="text-xs text-ink-500">No investigation steps recorded for this run.</div>;
  return (
    <ol className="relative max-w-[900px] space-y-0 border-l border-line pl-4">
      {steps.map((s) => (
        <li key={s.id} className="relative py-1.5">
          <span className="absolute -left-[21px] top-3 h-2 w-2 rounded-full ring-2 ring-white"
            style={{ background: KIND_TONE[s.action_kind] || "#98A2B3" }} aria-hidden="true" />
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-2xs font-medium uppercase tracking-wide text-ink-500">{ACTION_KIND[s.action_kind] || title(s.action_kind)}</span>
            <span className="text-2xs tabular-nums text-ink-300">#{s.seq}</span>
            {s.tokens ? <span className="text-2xs tabular-nums text-ink-300">{s.tokens} tok</span> : null}
            <span className="ml-auto text-2xs text-ink-300">{fmtTime(s.created_at)}</span>
          </div>
          <p className="mt-0.5 break-words text-xs leading-relaxed text-ink-700">{s.summary || "—"}</p>
          {(s.tool_call_id || s.evidence_id || s.hypothesis_id) && (
            <div className="mt-0.5 flex flex-wrap gap-2 font-mono text-2xs text-ink-300">
              {s.tool_call_id && <span>tool_call {s.tool_call_id}</span>}
              {s.evidence_id && <span>evidence {s.evidence_id}</span>}
              {s.hypothesis_id && <span>hypothesis {s.hypothesis_id}</span>}
            </div>
          )}
        </li>
      ))}
    </ol>
  );
}