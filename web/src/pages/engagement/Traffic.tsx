import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, Play, Search, X } from "lucide-react";
import { ApiError, post, qs } from "../../api";
import type { Correlation, CorrelationGroup, ExchangeDetail, ReplayResult, Tone, TrafficPage } from "../../types";
import { useApi } from "../../lib/hooks";
import { fmtDuration, fmtTime, severityTone } from "../../lib/format";
import { Badge, Button, Card, CodeBlock, EmptyState, ErrorNote, Field, Input, Select, Skeleton, TableSkeleton, Tabs, cx, useToast } from "../../components/ui";
import { KeyVal } from "../../components/bits";

const METHODS = ["", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export default function Traffic({ eid, live }: { eid: string; live: number }) {
  const toast = useToast();
  const [view, setView] = useState("exchanges");
  const [form, setForm] = useState({ url: "", method: "", status: "", tool: "", body_text: "" });
  const [query, setQuery] = useState(form);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => { setQuery(form); setPage(1); }, 350);
    return () => clearTimeout(t);
  }, [form]);

  const path = `/api/engagements/${eid}/traffic${qs({ ...query, page, page_size: 25, live })}`;
  const { data, error, loading } = useApi<TrafficPage>(path);
  const corr = useApi<Correlation>(`/api/engagements/${eid}/traffic/correlate?live=${live}`);
  const missing = error && error.startsWith("404");

  const items = data?.items || [];
  const set = (patch: Partial<typeof form>) => setForm((f) => ({ ...f, ...patch }));

  return (
    <div className="space-y-4">
      <Tabs value={view} onChange={setView} tabs={[
        { id: "exchanges", label: "Exchanges", count: data?.total },
        { id: "endpoints", label: "By endpoint", count: corr.data?.endpoints },
      ]} />
      {missing ? (
        <>
          <div className="rounded border border-dashed border-line bg-canvas px-4 py-3 text-sm text-ink-500">
            <span className="font-medium text-ink-700">Traffic intelligence</span> is unavailable on this backend build — it becomes available after the backend update.
          </div>
          <ErrorNote error={error} />
        </>
      ) : view === "exchanges" ? (
        <>
          <Card title="Search captured exchanges" description="Every request the engine made, with its captured response. Body search scans the evidence blob."
            actions={data ? <span className="text-2xs tabular-nums text-ink-500">{data.total} of {data.scanned ?? data.total} scanned{data.scan_truncated ? " (body scan truncated)" : ""}</span> : undefined}>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
              <Field label="URL contains" htmlFor="t-url">
                <Input id="t-url" value={form.url} placeholder="app.example.com/api" onChange={(e) => set({ url: e.target.value })} />
              </Field>
              <Field label="Method" htmlFor="t-method">
                <Select id="t-method" value={form.method} onChange={(e) => set({ method: e.target.value })}>
                  {METHODS.map((m) => <option key={m} value={m}>{m || "Any"}</option>)}
                </Select>
              </Field>
              <Field label="Status" htmlFor="t-status">
                <Input id="t-status" value={form.status} inputMode="numeric" placeholder="200" onChange={(e) => set({ status: e.target.value.replace(/\D/g, "") })} />
              </Field>
              <Field label="Tool" htmlFor="t-tool">
                <Input id="t-tool" value={form.tool} placeholder="http_probe" onChange={(e) => set({ tool: e.target.value })} />
              </Field>
              <Field label="Body contains" htmlFor="t-body">
                <Input id="t-body" value={form.body_text} placeholder="password" onChange={(e) => set({ body_text: e.target.value })} />
              </Field>
            </div>
          </Card>

          <Card padded={false} title="Exchanges"
            description="Click a row to inspect the captured request and response, then replay it under scope."
            actions={<span className="text-2xs text-ink-500">{loading ? "searching…" : `page ${data?.page ?? 1} of ${data?.pages || 1}`}</span>}>
            <ErrorNote error={error} />
            {loading && !data ? <TableSkeleton rows={6} cols={6} /> : !items.length ? (
              <EmptyState icon={<Search size={22} />} title={query.url || query.method || query.status || query.tool || query.body_text ? "No exchanges match these filters" : "No captured traffic yet"}
                description={query.url ? "Loosen the filters." : "Exchanges are stored whenever a check or crawl fetches a URL inside scope."} />
            ) : (
              <div className="overflow-x-auto">
                <table className="table-base">
                  <thead>
                    <tr><th>Method</th><th>URL</th><th className="text-right">Status</th><th>Tool</th><th className="text-right">Duration</th><th>When</th></tr>
                  </thead>
                  <tbody>
                    {items.map((x) => (
                      <tr key={x.id} className={cx("cursor-pointer", selected === x.id && "bg-accent-soft/40")} onClick={() => setSelected(x.id)}>
                        <td><span className="font-mono text-xs font-medium">{x.method || "—"}</span></td>
                        <td>
                          <span className="block max-w-[200px] truncate font-mono text-xs text-ink-700 sm:max-w-[420px]" title={x.url || ""}>{x.url || "—"}</span>
                          {x.match && <span className="mt-0.5 block max-w-[200px] truncate text-2xs text-ink-500 sm:max-w-[420px]" title={x.match}>…{x.match}…</span>}
                          {x.replay_of && <Badge tone="info" className="mt-1">replay</Badge>}
                        </td>
                        <td className="text-right"><StatusBadge status={x.status} /></td>
                        <td><span className="font-mono text-2xs text-ink-500">{x.tool || "—"}</span></td>
                        <td className="text-right tabular-nums text-ink-700">{fmtDuration(x.duration_ms)}</td>
                        <td className="whitespace-nowrap text-xs text-ink-500">{fmtTime(x.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {(data?.pages || 1) > 1 && (
              <div className="flex items-center justify-between border-t border-line px-4 py-2">
                <span className="text-2xs text-ink-500">{(data!.page - 1) * data!.page_size + 1}–{Math.min(data!.page * data!.page_size, data!.total)} of {data!.total}</span>
                <div className="flex gap-1">
                  <Button size="sm" variant="ghost" icon={<ChevronLeft size={13} />} disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</Button>
                  <Button size="sm" variant="ghost" disabled={page >= (data?.pages || 1)} onClick={() => setPage((p) => p + 1)}>Next <ChevronRight size={13} /></Button>
                </div>
              </div>
            )}
          </Card>

          {selected && <Inspector xid={selected} onClose={() => setSelected(null)} onSelect={setSelected} toast={toast} />}
        </>
      ) : (
        <>
          <ErrorNote error={corr.error} />
          <Card title="Correlation" description="Exchanges grouped by endpoint, with the findings and observations bound to them."
            padded={false}
            actions={<span className="text-2xs text-ink-500">{corr.data?.exchanges ?? 0} exchanges · {corr.data?.endpoints ?? 0} endpoints</span>}>
            {corr.loading && !corr.data ? <TableSkeleton rows={5} cols={5} /> : !(corr.data?.groups || []).length ? (
              <EmptyState title="Nothing to correlate yet" description="Endpoints appear here once requests have been captured." />
            ) : (
              <div className="overflow-x-auto">
                <table className="table-base">
                  <thead>
                    <tr><th>Endpoint</th><th className="text-right">Requests</th><th>Methods</th><th>Statuses</th><th>Findings</th><th>Observations</th></tr>
                  </thead>
                  <tbody>
                    {(corr.data?.groups || []).map((g: CorrelationGroup) => (
                      <tr key={g.endpoint} className="cursor-pointer"
                        onClick={() => { set({ url: endpointPath(g.endpoint) }); setView("exchanges"); }}>
                        <td><span className="block max-w-[420px] truncate font-mono text-xs" title={g.endpoint}>{endpointPath(g.endpoint)}</span></td>
                        <td className="text-right tabular-nums">{g.requests}</td>
                        <td><span className="font-mono text-2xs text-ink-700">{g.methods.join(" ") || "—"}</span></td>
                        <td>
                          <span className="flex flex-wrap gap-1">
                            {Object.entries(g.statuses).map(([s, n]) => (
                              <span key={s} className="text-2xs tabular-nums text-ink-500">{s}×{n}</span>
                            ))}
                          </span>
                        </td>
                        <td>
                          {g.findings.length ? (
                            <span className="flex flex-wrap gap-1">
                              {g.findings.slice(0, 3).map((f) => <Badge key={f.id} tone={severityTone(f.severity)}>{f.severity}</Badge>)}
                              {g.findings.length > 3 && <span className="text-2xs text-ink-500">+{g.findings.length - 3}</span>}
                            </span>
                          ) : <span className="text-ink-300">—</span>}
                        </td>
                        <td className="text-xs tabular-nums text-ink-700">{g.observations.length || <span className="text-ink-300">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}

function endpointPath(url: string) {
  try { const u = new URL(url); return u.pathname + (u.search || ""); } catch { return url; }
}

function StatusBadge({ status }: { status?: number | null }) {
  if (status === null || status === undefined) return <span className="text-ink-300">—</span>;
  const tone = status >= 500 ? "critical" : status >= 400 ? "danger" : status >= 300 ? "info" : "success";
  return <Badge tone={tone}>{status}</Badge>;
}

function Inspector({ xid, onClose, onSelect, toast }: {
  xid: string; onClose: () => void; onSelect: (id: string) => void; toast: (m: string, t?: Tone) => void;
}) {
  const { data, error, loading } = useApi<ExchangeDetail>(`/api/exchanges/${xid}`);
  const [busy, setBusy] = useState(false);
  const [replay, setReplay] = useState<ReplayResult | null>(null);
  const [replayError, setReplayError] = useState<string | null>(null);

  useEffect(() => { setReplay(null); setReplayError(null); }, [xid]);

  const run = async () => {
    setBusy(true);
    setReplayError(null);
    try {
      const res = await post<ReplayResult>(`/api/exchanges/${xid}/replay`);
      setReplay(res);
      toast(res.diff?.body_identical ? "Replayed — response identical to the original." : "Replayed — response differs from the original.", "success");
    } catch (e) {
      const msg = e instanceof ApiError && e.status === 404
        ? "Replay is unavailable on this backend build (route not shipped)."
        : e instanceof Error ? e.message : String(e);
      setReplayError(msg);
      toast(msg, "danger");
    } finally {
      setBusy(false);
    }
  };

  const req = data?.blob?.request;
  const resp = data?.blob?.response;

  return (
    <aside className="rounded border border-line bg-white shadow-card">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-semibold">{data?.method || "—"}</span>
            <StatusBadge status={data?.status} />
            <span className="text-2xs text-ink-500">{fmtDuration(data?.duration_ms)} · {data?.peer_ip || "peer unknown"}</span>
          </div>
          <div className="mt-0.5 break-all font-mono text-xs text-ink-700">{data?.url || xid}</div>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="primary" icon={<Play size={12} />} loading={busy} onClick={run}
            title="Re-issue this request under the engagement scope and diff the response">Replay</Button>
          <button onClick={onClose} aria-label="Close inspector" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900"><X size={14} /></button>
        </div>
      </header>

      <div className="grid gap-4 p-4 lg:grid-cols-2">
        <div className="space-y-3">
          <ErrorNote error={error} />
          {loading && !data ? <Skeleton className="h-40 w-full" /> : (
            <>
              <dl className="grid grid-cols-2 gap-3">
                <KeyVal label="Exchange">{<span className="font-mono text-2xs">{data?.id}</span>}</KeyVal>
                <KeyVal label="Tool">{data?.tool || "—"}</KeyVal>
                <KeyVal label="Evidence">{data?.evidence_id ? <span className="font-mono text-2xs">{data.evidence_id}</span> : "—"}</KeyVal>
                <KeyVal label="Captured">{fmtTime(data?.created_at)}</KeyVal>
              </dl>
              <div>
                <div className="mb-1 text-2xs uppercase tracking-wide text-ink-500">Request headers</div>
                <HeaderTable headers={req?.headers} />
              </div>
              <CodeBlock label="request body" content={req?.body || "(empty)"} maxHeight={220} />
            </>
          )}
        </div>
        <div className="space-y-3">
          <div className="mb-1 text-2xs uppercase tracking-wide text-ink-500">Response headers</div>
          <HeaderTable headers={resp?.headers} />
          <CodeBlock label="response body" content={resp?.body || "(empty — binary or not captured)"} maxHeight={260} />
          {replayError && <ErrorNote error={replayError} />}
          {replay?.ok && replay.diff && <DiffPanel diff={replay.diff} newExchange={replay.exchange_id} onOpen={onSelect} />}
        </div>
      </div>
    </aside>
  );
}

function HeaderTable({ headers }: { headers?: Record<string, string> }) {
  const entries = Object.entries(headers || {});
  if (!entries.length) return <div className="text-2xs text-ink-300">not captured</div>;
  return (
    <div className="max-h-40 overflow-y-auto rounded border border-line bg-canvas">
      <table className="w-full text-2xs">
        <tbody>
          {entries.map(([k, v]) => (
            <tr key={k} className="border-b border-line/60 last:border-0">
              <td className="w-[38%] break-all px-2 py-1 font-mono text-ink-500">{k}</td>
              <td className="break-all px-2 py-1 font-mono text-ink-700">{String(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DiffPanel({ diff, newExchange, onOpen }: { diff: NonNullable<ReplayResult["diff"]>; newExchange?: string; onOpen: (id: string) => void }) {
  const same = diff.body_identical;
  return (
    <div className={cx("rounded border px-3 py-2.5", same ? "border-[#ABEFC6] bg-[#ECFDF3]" : "border-[#FEDF89] bg-[#FFFAEB]")}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-ink-900">{same ? "Replay matches the original" : "Replay differs from the original"}</span>
        {newExchange && <span className="font-mono text-2xs text-ink-500">{newExchange}</span>}
      </div>
      <dl className="mt-1.5 grid grid-cols-2 gap-x-3 gap-y-1 text-2xs text-ink-700">
        <div>status <span className="font-mono">{String(diff.status_original)} → {String(diff.status_replay)}</span>{diff.status_changed ? " (changed)" : ""}</div>
        <div>length <span className="tabular-nums">{(diff.length_original ?? 0).toLocaleString()} → {(diff.length_replay ?? 0).toLocaleString()}</span> ({diff.length_delta! >= 0 ? "+" : ""}{diff.length_delta})</div>
        <div>similarity <span className="tabular-nums">{Math.round((diff.similarity ?? 0) * 100)}%</span></div>
        <div>body <span>{same ? "identical" : "differs"}</span>{diff.truncated_compare ? " · truncated compare" : ""}</div>
      </dl>
      <button onClick={() => newExchange && onOpen(newExchange)} className="mt-1.5 text-2xs text-accent hover:underline">load the replayed exchange</button>
    </div>
  );
}