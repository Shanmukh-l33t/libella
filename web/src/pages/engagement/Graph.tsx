import { useMemo, useState } from "react";
import { ReactFlow, Background, Controls, MiniMap, Handle, Position, type Node, type Edge, type NodeProps, type NodeMouseHandler } from "@xyflow/react";
import { X } from "lucide-react";
import type { GraphData } from "../../types";
import { useApi } from "../../lib/hooks";
import { SEV_COLOR, intentTone, stateTone, title } from "../../lib/format";
import { Badge, Card, EmptyState, ErrorNote, JsonViewer, Skeleton, cx } from "../../components/ui";

type EntityData = { label: string; etype: string; kind: string; data: Record<string, unknown>; severity?: string; status?: string; state?: string };

function EntityNode({ data }: NodeProps) {
  const d = data as unknown as EntityData;
  const accent = d.etype === "finding" ? SEV_COLOR[d.severity || "info"] : d.etype === "intent" ? (intentTone(d.status || "") === "success" ? "#039855" : intentTone(d.status || "") === "accent" ? "#175CD3" : "#98A2B3") : "#98A2B3";
  return (
    <div className={cx("group w-[240px] rounded border bg-white px-3 py-2 text-left shadow-card transition-shadow duration-150 hover:shadow-md",
      d.etype === "finding" ? "border-line" : "border-line")}
      style={{ borderLeft: `3px solid ${accent}` }}>
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-0 !bg-ink-300" />
      <div className="flex items-center gap-1.5">
        <span className="text-2xs uppercase tracking-wide text-ink-500">{d.etype}</span>
        <span className="ml-auto text-2xs capitalize text-ink-300">{d.etype === "finding" ? d.state : d.kind}</span>
      </div>
      <div className="mt-0.5 line-clamp-2 text-xs font-medium leading-snug text-ink-900" title={d.label}>{d.label}</div>
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-0 !bg-ink-300" />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

export default function GraphTab({ eid, live }: { eid: string; live: number }) {
  const { data, error, loading } = useApi<GraphData>(`/api/engagements/${eid}/graph?live=${live}`);
  const [selected, setSelected] = useState<EntityData | null>(null);

  const { nodes, edges } = useMemo(() => {
    const assets = (data?.nodes || []).filter((n) => n.type === "asset");
    const findings = (data?.nodes || []).filter((n) => n.type === "finding");
    const intents = (data?.nodes || []).filter((n) => n.type === "intent");
    const pos: Record<string, { x: number; y: number }> = {};
    assets.forEach((n, i) => { pos[n.id] = { x: 0, y: i * 88 }; });
    findings.forEach((n, i) => { pos[n.id] = { x: 560, y: i * 96 }; });
    const baseY = Math.max(assets.length * 88, findings.length * 96, 200) + 100;
    intents.forEach((n, i) => { pos[n.id] = { x: (i % 5) * 260, y: baseY + Math.floor(i / 5) * 110 }; });

    const ns: Node[] = (data?.nodes || []).map((n) => ({
      id: n.id,
      type: "entity",
      position: pos[n.id] || { x: 0, y: 0 },
      width: 240,
      height: 56,
      data: {
        label: n.label, etype: n.type, kind: n.kind, data: n.data,
        severity: n.type === "finding" ? n.kind : undefined,
        status: n.type === "intent" ? n.kind : undefined,
        state: n.data?.state,
      } satisfies EntityData,
    }));

    const es: Edge[] = (data?.edges || []).map((e, i) => {
      const verified = e.kind === "affects" && e.verified;
      const color = e.kind === "affects" ? (verified ? "#667085" : "#98A2B3") : e.kind === "depends_on" ? "#98A2B3" : "#C3C8D1";
      return {
        id: `e${i}`,
        source: e.source,
        target: e.target,
        type: e.kind === "contains" ? "smoothstep" : "default",
        animated: false,
        style: { stroke: color, strokeWidth: e.kind === "affects" && !verified ? 1.2 : 1.4, strokeDasharray: e.kind === "affects" && !verified ? "4 3" : e.kind === "depends_on" ? "5 4" : undefined },
        label: e.kind === "affects" ? (verified ? "affects · verified" : "affects") : undefined,
        labelStyle: { fontSize: 10, fill: "#475467" },
        labelBgStyle: { fill: "#ffffff", fillOpacity: 0.9 },
      };
    });
    return { nodes: ns, edges: es };
  }, [data]);

  const onNodeClick: NodeMouseHandler = (_, node) => setSelected(node.data as unknown as EntityData);

  if (error) return <ErrorNote error={error} />;
  if (loading && !data) return <Skeleton className="h-[560px] w-full" />;
  if (!data?.nodes.length) {
    return <Card padded={false}><EmptyState title="Nothing to graph yet" description="Assets, findings and intents appear here once the engagement starts producing results." /></Card>;
  }

  return (
    <Card padded={false} title="Attack surface graph" description="Assets on the left, findings on the right, intents along the bottom. Solid affects edges are independently verified."
      actions={<span className="text-2xs text-ink-500">{data.nodes.length} nodes · {data.edges.length} edges</span>}>
      <div className="flex h-[600px]">
        <div className="relative min-w-0 flex-1" style={{ background: "#FCFCFD" }}>
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodeClick={onNodeClick}
            fitView fitViewOptions={{ padding: 0.15 }} minZoom={0.2} maxZoom={1.6} proOptions={{ hideAttribution: true }}
            nodesConnectable={false} nodesDraggable={false} elementsSelectable>
            <Background color="#E4E7EC" gap={16} size={1} />
            <Controls showInteractive={false} className="!rounded !border !border-line !bg-white !shadow-card" />
            <MiniMap pannable zoomable className="!rounded !border !border-line !bg-white"
              nodeColor={(n) => {
                const d = n.data as unknown as EntityData;
                return d.etype === "finding" ? SEV_COLOR[d.severity || "info"] : d.etype === "intent" ? "#98A2B3" : "#D0D5DD";
              }} maskColor="rgba(249,250,251,0.7)" />
          </ReactFlow>
          <div className="pointer-events-none absolute bottom-3 left-3 flex gap-3 rounded border border-line bg-white/95 px-2.5 py-1.5 text-2xs text-ink-500">
            <span className="inline-flex items-center gap-1"><span className="h-0 w-3 border-t border-ink-300" /> contains</span>
            <span className="inline-flex items-center gap-1"><span className="h-0 w-3 border-t border-dashed border-ink-300" /> depends on</span>
            <span className="inline-flex items-center gap-1"><span className="h-0 w-3 border-t border-ink-500" /> affects verified</span>
            <span className="inline-flex items-center gap-1"><span className="h-0 w-3 border-t border-dashed border-ink-300" /> affects unverified</span>
          </div>
        </div>
        {selected && (
          <aside className="w-[320px] shrink-0 overflow-y-auto border-l border-line p-4">
            <div className="mb-2 flex items-start justify-between gap-2">
              <div>
                <div className="text-2xs uppercase tracking-wide text-ink-500">{selected.etype} · {selected.kind}</div>
                <h3 className="mt-0.5 break-words text-sm font-medium text-ink-900">{selected.label}</h3>
              </div>
              <button onClick={() => setSelected(null)} aria-label="Close node panel" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900"><X size={14} /></button>
            </div>
            <div className="mb-3 flex gap-1.5">
              {selected.etype === "finding" && <Badge tone={selected.severity === "critical" ? "critical" : selected.severity === "high" ? "danger" : selected.severity === "medium" ? "warning" : selected.severity === "low" ? "success" : "info"}>{selected.severity}</Badge>}
              {selected.state && <Badge tone={stateTone(selected.state)}>{title(selected.state)}</Badge>}
              {selected.etype === "intent" && <Badge tone={intentTone(selected.status || "")}>{title(selected.status || "")}</Badge>}
            </div>
            <JsonViewer value={selected.data} maxHeight={420} />
            <div className="mt-2 text-2xs text-ink-500">Node colours follow severity for findings and status for intents.</div>
          </aside>
        )}
      </div>
    </Card>
  );
}