import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ReactFlow, Background, Controls, MiniMap, Handle, Position, type Node, type Edge, type NodeProps, type NodeMouseHandler } from "@xyflow/react";
import { X } from "lucide-react";
import type { GraphData, GraphNodeType } from "../../types";
import { useApi } from "../../lib/hooks";
import { ACTION_KIND, SEV_COLOR, fmtTime, hypothesisTone, runTone, stateTone, title } from "../../lib/format";
import { Badge, Card, EmptyState, ErrorNote, JsonViewer, Skeleton, cx } from "../../components/ui";

type EntityData = {
  nid: string; label: string; etype: GraphNodeType; kind: string; data: Record<string, any>;
  severity?: string; status?: string; state?: string;
};

/** One colour per node type; findings keep the severity palette. */
const TYPE_COLOR: Record<string, string> = {
  asset: "#667085", endpoint: "#175CD3", auth_context: "#6941C6", intent: "#475467",
  agent_run: "#0E9384", observation: "#039855", evidence: "#DC6803", hypothesis: "#C11574",
  finding: "#B42318", verification: "#027A48", retest: "#B54718",
};

const TYPE_ORDER: GraphNodeType[] = [
  "asset", "endpoint", "auth_context", "intent", "agent_run",
  "observation", "evidence", "hypothesis", "finding", "verification", "retest",
];

const PILL = new Set(["evidence", "hypothesis", "verification", "retest"]);

function EntityNode({ data }: NodeProps) {
  const d = data as unknown as EntityData;
  const accent = d.etype === "finding" && d.severity ? SEV_COLOR[d.severity] || TYPE_COLOR.finding : TYPE_COLOR[d.etype] || "#98A2B3";
  const right = d.etype === "finding" ? d.severity : d.etype === "hypothesis" ? `conf ${Math.round((d.data?.confidence ?? 0) * 100)}%` : d.kind;
  return (
    <div className={cx("group w-[196px] border border-line bg-white px-2.5 py-2 text-left shadow-card transition-shadow duration-150 hover:shadow-md",
      PILL.has(d.etype) ? "rounded-full px-3" : d.etype === "asset" || d.etype === "endpoint" ? "rounded-sm" : "rounded")}>
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-0 !bg-ink-300" />
      <div className="flex items-center gap-1.5">
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: accent }} aria-hidden="true" />
        <span className="text-2xs uppercase tracking-wide text-ink-500">{title(d.etype)}</span>
        <span className="ml-auto truncate text-2xs capitalize text-ink-300" title={String(right)}>{right}</span>
      </div>
      <div className="mt-0.5 line-clamp-2 text-xs font-medium leading-snug text-ink-900" title={d.label}>{d.label}</div>
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-0 !bg-ink-300" />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

const EDGE_STYLE: Record<string, { color: string; dash?: string; label?: string }> = {
  contains: { color: "#D0D5DD" },
  depends_on: { color: "#98A2B3", dash: "5 4" },
  delegates: { color: "#98A2B3", dash: "2 3" },
  executed_by: { color: "#0E9384" },
  produced: { color: "#039855" },
  observed_on: { color: "#98A2B3", dash: "2 3" },
  supported_by: { color: "#DC6803" },
  about: { color: "#C11574", dash: "2 3" },
  raised_by: { color: "#C11574", dash: "5 4" },
  affects: { color: "#475467" },
  verified_by: { color: "#027A48" },
  retested: { color: "#B54718" },
};

export default function GraphTab({ eid, live }: { eid: string; live: number }) {
  const { data, error, loading } = useApi<GraphData>(`/api/engagements/${eid}/graph?live=${live}`);
  const [selected, setSelected] = useState<EntityData | null>(null);
  const [hidden, setHidden] = useState<Set<string>>(new Set());

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of data?.nodes || []) c[n.type] = (c[n.type] || 0) + 1;
    return c;
  }, [data]);

  const { nodes, edges, maxRows } = useMemo(() => {
    const visible = (data?.nodes || []).filter((n) => !hidden.has(n.type));
    // Compact the columns: only types actually present take a slot, so the fit zoom stays readable.
    const slot = new Map(TYPE_ORDER.filter((t) => visible.some((n) => n.type === t)).map((t, i) => [t, i]));
    const cols = new Map<string, number>();
    const pos: Record<string, { x: number; y: number }> = {};
    let rows = 0;
    for (const n of visible) {
      const c = cols.get(n.type) ?? 0;
      cols.set(n.type, c + 1);
      pos[n.id] = { x: (slot.get(n.type) ?? 0) * 210, y: c * 66 };
      rows = Math.max(rows, c + 1);
    }
    const ns: Node[] = visible.map((n) => ({
      id: n.id,
      type: "entity",
      position: pos[n.id] || { x: 0, y: 0 },
      width: 196,
      height: 54,
      data: {
        nid: n.id, label: n.label, etype: n.type, kind: n.kind, data: n.data,
        severity: n.type === "finding" ? n.kind : undefined,
        status: n.type === "intent" || n.type === "agent_run" ? n.kind : undefined,
        state: n.data?.state,
      } satisfies EntityData,
    }));
    const ids = new Set(ns.map((n) => n.id));
    const es: Edge[] = (data?.edges || [])
      .filter((e) => ids.has(e.source) && ids.has(e.target))
      .map((e, i) => {
        const st = EDGE_STYLE[e.kind] || { color: "#C3C8D1" };
        return {
          id: `e${i}`,
          source: e.source,
          target: e.target,
          type: e.kind === "contains" || e.kind === "executed_by" ? "smoothstep" : "default",
          animated: false,
          style: {
            stroke: st.color,
            strokeWidth: e.verified === false ? 1.2 : 1.5,
            strokeDasharray: e.verified === false ? "3 3" : st.dash,
            opacity: e.verified === false ? 0.75 : 1,
          },
          label: e.verified ? `${title(e.kind)} · verified` : e.verified === false ? title(e.kind) : undefined,
          labelStyle: { fontSize: 9, fill: "#475467" },
          labelBgStyle: { fill: "#ffffff", fillOpacity: 0.9 },
        };
      });
    return { nodes: ns, edges: es, maxRows: rows };
  }, [data, hidden]);

  const onNodeClick: NodeMouseHandler = (_, node) => setSelected(node.data as unknown as EntityData);
  const toggle = (t: string) => setHidden((s) => {
    const next = new Set(s);
    if (next.has(t)) next.delete(t); else next.add(t);
    return next;
  });

  if (error) return <ErrorNote error={error} />;
  if (loading && !data) return <Skeleton className="h-[560px] w-full" />;
  if (!data?.nodes.length) {
    return <Card padded={false}><EmptyState title="Nothing to graph yet" description="Assets, observations, hypotheses and findings appear here once the engagement produces results." /></Card>;
  }

  const cov = data.coverage;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <CovStat label="Assets" value={cov ? `${cov.assets_investigated}/${cov.assets_total}` : "—"} hint="investigated" />
        <CovStat label="Findings" value={cov?.findings ?? "—"} hint={`${cov?.validated ?? 0} validated`} />
        <CovStat label="Open hypotheses" value={cov?.hypotheses_open ?? "—"} hint="need evidence" />
        <CovStat label="Agent runs" value={cov?.agent_runs ?? "—"} hint="reasoning loops" />
        <CovStat label="Nodes" value={data.nodes.length} hint={`${data.edges.length} edges`} />
        <CovStat label="Timeline" value={data.timeline?.length ?? 0} hint="investigation steps" />
      </div>

      <Card padded={false} title="Investigation graph"
        description="Full lineage: assets and endpoints, intent → run → observation → evidence, hypothesis → finding → verification → retest."
        actions={<span className="text-2xs text-ink-700">{nodes.length} shown · {edges.length} edges</span>}>
        <div className="no-scrollbar flex flex-wrap gap-1 overflow-x-auto border-b border-line px-3 py-2">
          {TYPE_ORDER.filter((t) => counts[t]).map((t) => (
            <button key={t} onClick={() => toggle(t)} aria-pressed={!hidden.has(t)}
              className={cx("inline-flex items-center gap-1.5 rounded border px-2 py-1 text-2xs transition-colors",
                hidden.has(t) ? "border-dashed border-line bg-white text-ink-300" : "border-line bg-canvas text-ink-700")}>
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: hidden.has(t) ? "#D0D5DD" : TYPE_COLOR[t] }} />
              {title(t)}
              <span className="tabular-nums text-ink-500">{counts[t]}</span>
            </button>
          ))}
        </div>
        <div className="flex" style={{ height: Math.min(1500, Math.max(540, maxRows * 62 + 60)) }}>
          <div className="relative min-w-0 flex-1" style={{ background: "#FCFCFD" }}>
            <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodeClick={onNodeClick}
              fitView fitViewOptions={{ padding: 0.08 }} minZoom={0.15} maxZoom={1.6} proOptions={{ hideAttribution: true }}
              nodesConnectable={false} nodesDraggable={false} elementsSelectable>
              <Background color="#E4E7EC" gap={16} size={1} />
              <Controls showInteractive={false} className="!rounded !border !border-line !bg-white !shadow-card" />
              <MiniMap pannable zoomable className="!rounded !border !border-line !bg-white"
                nodeColor={(n) => {
                  const d = n.data as unknown as EntityData;
                  return d.etype === "finding" ? SEV_COLOR[d.severity || "info"] : TYPE_COLOR[d.etype] || "#D0D5DD";
                }} maskColor="rgba(249,250,251,0.7)" />
            </ReactFlow>
            <div className="pointer-events-none absolute bottom-3 left-3 flex flex-wrap gap-3 rounded border border-line bg-white/95 px-2.5 py-1.5 text-2xs text-ink-700">
              <span className="inline-flex items-center gap-1"><span className="h-0 w-3 border-t border-ink-500" /> verified</span>
              <span className="inline-flex items-center gap-1"><span className="h-0 w-3 border-t border-dashed border-ink-300" /> unverified</span>
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-ink-300" /> dot colour = node type</span>
            </div>
          </div>
          {selected && (
            <aside className="w-[320px] shrink-0 overflow-y-auto border-l border-line p-4">
              <div className="mb-2 flex items-start justify-between gap-2">
                <div>
                  <div className="text-2xs uppercase tracking-wide text-ink-500">{title(selected.etype)} · {selected.kind}</div>
                  <h3 className="mt-0.5 break-words text-sm font-medium text-ink-900">{selected.label}</h3>
                </div>
                <button onClick={() => setSelected(null)} aria-label="Close node panel" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900"><X size={14} /></button>
              </div>
              <div className="mb-3 flex flex-wrap gap-1.5">
                {selected.etype === "finding" && selected.severity && <Badge tone={selected.severity === "critical" ? "critical" : selected.severity === "high" ? "danger" : selected.severity === "medium" ? "warning" : selected.severity === "low" ? "success" : "info"}>{selected.severity}</Badge>}
                {selected.state && <Badge tone={stateTone(selected.state)}>{title(selected.state)}</Badge>}
                {selected.etype === "hypothesis" && <Badge tone={hypothesisTone(selected.kind)}>{title(selected.kind)}</Badge>}
                {selected.etype === "agent_run" && <Badge tone={runTone(selected.kind)}>{title(selected.kind)}</Badge>}
              </div>
              <div className="mb-3 flex flex-wrap gap-2 text-2xs">
                {selected.etype === "finding" && <Link to={`/findings/${selected.nid}`} className="link">open finding</Link>}
                {selected.etype === "intent" && <Link to={`/engagements/${eid}?tab=operations`} className="link">open run timeline</Link>}
                {selected.etype === "evidence" && <Link to={`/engagements/${eid}?tab=evidence`} className="link">open evidence</Link>}
                {selected.etype === "observation" && <Link to={`/engagements/${eid}?tab=evidence`} className="link">provenance</Link>}
              </div>
              <JsonViewer value={selected.data} maxHeight={360} />
              <p className="mt-2 text-2xs text-ink-700">Node colour encodes type; findings use severity. Dashed edges are claims without independent replay proof.</p>
            </aside>
          )}
        </div>
      </Card>

      <Card title="Investigation timeline" description="Every reasoning step, tool call, observation and conclusion the runtime recorded."
        padded={false} actions={<span className="text-2xs tabular-nums text-ink-500">{data.timeline?.length || 0} steps</span>}>
        {!(data.timeline || []).length ? (
          <EmptyState title="No investigation steps" description="Steps appear when an agent run reasons over an intent (agent mode)." />
        ) : (
          <ol className="max-h-[320px] divide-y divide-line/70 overflow-y-auto">
            {[...(data.timeline || [])].reverse().map((s, i) => (
              <li key={`${s.seq}-${i}`} className="flex items-start gap-3 px-4 py-2">
                <span className="mt-0.5 w-10 shrink-0 text-2xs tabular-nums text-ink-300">#{s.seq}</span>
                <span className="w-20 shrink-0 text-2xs font-medium uppercase tracking-wide text-ink-500">{ACTION_KIND[s.kind] || title(s.kind)}</span>
                <span className="min-w-0 flex-1 break-words text-xs text-ink-700">{s.summary}</span>
                <span className="shrink-0 text-2xs tabular-nums text-ink-300">{fmtTime(s.at)}</span>
              </li>
            ))}
          </ol>
        )}
      </Card>
    </div>
  );
}

function CovStat({ label, value, hint }: { label: string; value: ReactNode; hint: string }) {
  return (
    <div className="rounded border border-line bg-white px-3 py-2">
      <div className="text-2xs text-ink-500">{label}</div>
      <div className="mt-0.5 text-base font-semibold tabular-nums text-ink-900">{value}</div>
      <div className="text-2xs text-ink-500">{hint}</div>
    </div>
  );
}