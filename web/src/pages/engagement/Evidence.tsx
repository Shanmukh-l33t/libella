import { useCallback, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Fingerprint, ShieldCheck, X } from "lucide-react";
import { qs } from "../../api";
import type { ChainStatus, EvidenceDetail, Finding, TrafficPage } from "../../types";
import { useApi, usePagedApi } from "../../lib/hooks";
import { severityTone } from "../../lib/format";
import { Badge, Card, CodeBlock, EmptyState, ErrorNote, Input, Skeleton, TableSkeleton, cx } from "../../components/ui";
import { KeyVal } from "../../components/bits";

interface EvRow {
  id: string;
  observations: { id: string; kind: string; summary: string }[];
  findings: { id: string; title: string; severity: string }[];
  exchanges: { id: string; method?: string; url?: string; status?: number | null; tool?: string }[];
}

type Observation = { id: string; kind: string; summary: string; evidence_id?: string | null; created_at?: number };

export default function EvidenceTab({ eid, live }: { eid: string; live: number }) {
  const obs = useApi<Observation[]>(`/api/engagements/${eid}/observations?live=${live}`);
  const findings = useApi<Finding[]>(`/api/engagements/${eid}/findings?live=${live}`);
  // Every captured exchange, not the first page: a real run produces several hundred and
  // the API caps one page at 200 (MAX_PAGE), so artifacts silently vanished from this tab.
  // The ordering must not depend on the request, so `build` is memoised.
  const traffic = usePagedApi<TrafficPage>(
    useCallback((page: number) => `/api/engagements/${eid}/traffic${qs({ page_size: 200, page, live })}`,
      [eid, live]),
  );
  const [term, setTerm] = useState("");
  const [source, setSource] = useState("all");
  const [selected, setSelected] = useState<string | null>(null);

  const rows = useMemo(() => {
    const m = new Map<string, EvRow>();
    const get = (id: string) => m.get(id) || m.set(id, { id, observations: [], findings: [], exchanges: [] }).get(id)!;
    for (const o of obs.data || []) if (o.evidence_id) get(o.evidence_id).observations.push({ id: o.id, kind: o.kind, summary: o.summary });
    for (const f of findings.data || []) for (const ev of f.evidence_ids || []) get(ev).findings.push({ id: f.id, title: f.title, severity: f.severity });
    for (const page of traffic.pages || []) {
      for (const x of page.items || []) if (x.evidence_id) get(x.evidence_id).exchanges.push({ id: x.id, method: x.method, url: x.url, status: x.status, tool: x.tool });
    }
    const needle = term.trim().toLowerCase();
    return [...m.values()]
      .filter((r) => source === "all" || (source === "observation" && r.observations.length) || (source === "finding" && r.findings.length) || (source === "exchange" && r.exchanges.length))
      .filter((r) => !needle || r.id.toLowerCase().includes(needle)
        || r.observations.some((o) => (o.summary + o.kind).toLowerCase().includes(needle))
        || r.findings.some((f) => f.title.toLowerCase().includes(needle))
        || r.exchanges.some((x) => (x.url || "").toLowerCase().includes(needle)))
      .sort((a, b) => (b.findings.length + b.observations.length + b.exchanges.length) - (a.findings.length + a.observations.length + a.exchanges.length));
  }, [obs.data, findings.data, traffic.pages, term, source]);

  const loading = obs.loading || findings.loading || traffic.loading;
  const errors = [obs.error, findings.error, traffic.error].filter(Boolean) as string[];

  return (
    <div className="space-y-4">
      {errors.map((e) => <ErrorNote key={e} error={e} />)}
      <Card title="Evidence" description="Content-addressed artifacts and everything that cites them. An artifact without a citation proves nothing."
        actions={
          <div className="flex gap-2">
            <Input aria-label="Search evidence" value={term} onChange={(e) => setTerm(e.target.value)} placeholder="search id, claim or url" className="h-7 w-[220px] text-xs" />
            <select aria-label="Filter by source" value={source} onChange={(e) => setSource(e.target.value)} className="input h-7 w-[150px] text-xs">
              <option value="all">All sources</option>
              <option value="observation">Observations</option>
              <option value="finding">Findings</option>
              <option value="exchange">Exchanges</option>
            </select>
          </div>
        }>
        {loading && !rows.length ? <TableSkeleton rows={6} cols={4} /> : !rows.length ? (
          <EmptyState icon={<Fingerprint size={22} />} title={term || source !== "all" ? "No evidence matches" : "No evidence captured yet"}
            description={term ? "Clear the search or change the source filter." : "Evidence is written whenever a check fetches or observes something inside scope."} />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr><th>Evidence</th><th>Sources</th><th>Cited by</th><th>Claims</th><th className="text-right">Links</th></tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className={cx("cursor-pointer", selected === r.id && "bg-accent-soft/40")} onClick={() => setSelected(r.id)}>
                    <td><span className="font-mono text-xs">{r.id}</span></td>
                    <td>
                      <span className="flex flex-wrap gap-1">
                        {r.exchanges.length > 0 && <Badge tone="info">exchange</Badge>}
                        {r.observations.length > 0 && <Badge tone="accent">observation</Badge>}
                        {r.findings.length > 0 && <Badge tone="success">finding</Badge>}
                      </span>
                    </td>
                    <td>
                      {r.findings.length ? (
                        <span className="flex flex-wrap gap-1">
                          {r.findings.slice(0, 2).map((f) => <Badge key={f.id} tone={severityTone(f.severity)}>{f.severity}</Badge>)}
                          <span className="text-2xs text-ink-500">{r.findings.length} finding{r.findings.length === 1 ? "" : "s"}</span>
                        </span>
                      ) : <span className="text-ink-300">—</span>}
                    </td>
                    <td>
                      <span className="block max-w-[420px] truncate text-xs text-ink-700" title={r.observations[0]?.summary || r.findings[0]?.title || ""}>
                        {r.observations[0]?.summary || r.findings[0]?.title || r.exchanges[0]?.url || "—"}
                      </span>
                    </td>
                    <td className="text-right tabular-nums text-ink-700">{r.observations.length + r.findings.length + r.exchanges.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && <EvidencePanel evid={selected} row={rows.find((r) => r.id === selected)} onClose={() => setSelected(null)} />}
    </div>
  );
}

function EvidencePanel({ evid, row, onClose }: { evid: string; row?: EvRow; onClose: () => void }) {
  const detail = useApi<EvidenceDetail>(`/api/evidence/${evid}`);
  const chain = useApi<ChainStatus>(`/api/evidence/${evid}/chain`);

  return (
    <aside className="rounded border border-line bg-white shadow-card">
      <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-ink-900">Evidence artifact</span>
            {detail.data?.kind && <Badge tone="info">{detail.data.kind}</Badge>}
          </div>
          <div className="mt-0.5 break-all font-mono text-2xs text-ink-500">{evid}</div>
        </div>
        <button onClick={onClose} aria-label="Close evidence panel" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900"><X size={14} /></button>
      </header>

      <div className="grid gap-4 p-4 lg:grid-cols-[1fr_360px]">
        <div className="space-y-2">
          <ErrorNote error={detail.error} />
          {detail.loading && !detail.data ? <Skeleton className="h-64 w-full" /> : (
            <CodeBlock label={`content · ${detail.data?.kind || "artifact"}`} content={detail.data?.content || "(empty)"} maxHeight={460} />
          )}
        </div>

        <div className="space-y-4">
          <dl className="grid grid-cols-1 gap-3">
            <KeyVal label="SHA-256"><span className="break-all font-mono text-2xs">{detail.data?.sha256 || "—"}</span></KeyVal>
            <KeyVal label="Provenance">
                          <ul className="space-y-1 text-xs">
                            {(row?.exchanges || []).map((x) => (
                              <li key={x.id} className="flex items-center gap-1.5">
                                <span className="font-mono">{x.method}</span>
                                <span className="truncate text-ink-700" title={x.url || ""}>{x.url}</span>
                                <Badge tone={(x.status || 0) >= 400 ? "danger" : "success"}>{x.status ?? "—"}</Badge>
                              </li>
                            ))}
                            {(row?.observations || []).map((o) => (
                              <li key={o.id} className="text-ink-700"><span className="capitalize text-ink-500">{o.kind}</span> · {o.summary}</li>
                            ))}
                            {(row?.findings || []).map((f) => (
                              <li key={f.id}><Link to={`/findings/${f.id}`} className="link">{f.title}</Link></li>
                            ))}
                            {(row?.exchanges.length || row?.observations.length || row?.findings.length) ? null : <li className="text-ink-300">no citation found</li>}
                          </ul>
                        </KeyVal>
          </dl>

          <div className="rounded border border-line px-3 py-2.5">
            <div className="flex items-center gap-1.5 text-xs font-medium text-ink-900"><ShieldCheck size={13} className="text-ink-500" /> Hash chain</div>
            {chain.error ? <ErrorNote error={chain.error} /> : chain.data ? (
              <div className="mt-1 space-y-1 text-xs">
                <div className={chain.data.ok ? "text-[#027A48]" : "text-sev-high"}>
                  {chain.data.ok ? "intact" : `broken at ${chain.data.broken_at || "unknown"}`}
                </div>
                <div className="text-ink-500">{chain.data.checked} artifacts verified{chain.data.head ? ` · head ${chain.data.head.slice(0, 16)}…` : ""}</div>
              </div>
            ) : <div className="mt-1 text-xs text-ink-500">{chain.loading ? "Verifying…" : "Not checked yet."}</div>}
          </div>
          <p className="text-2xs text-ink-500">Evidence is content-addressed and chain-linked per engagement; a modified blob breaks verification rather than silently changing a claim.</p>
        </div>
      </div>
    </aside>
  );
}