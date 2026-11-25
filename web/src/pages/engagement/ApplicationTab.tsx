import { useMemo, useState } from "react";
import { useApi } from "../../lib/hooks";
import { Badge, Card, EmptyState, ErrorNote, Input, Table, TableSkeleton } from "../../components/ui";

/** One node of the application model, as the API reports it. */
interface AppNode {
  id: string;
  kind: string;
  key: string;
  label: string;
  provenance: string;
  confidence: number;
  data: Record<string, unknown>;
  evidence_id?: string | null;
  source_ref?: string | null;
}

interface Feature {
  feature: string;
  property: string;
  raised_by: string;
  provenance: string;
  test: string;
}

interface Gap {
  gap: string;
  detail: string;
  would_close_with: string;
  endpoint?: string;
}

interface SecurityHypothesis {
  id: string;
  class: string;
  statement: string;
  property: string;
  endpoint?: string | null;
  param?: string | null;
  resource?: string | null;
  owner_field?: string | null;
  status: string;
  provenance: string;
  score: number;
  missing: string[];
  test: Record<string, unknown>;
  factors?: Record<string, number>;
  blocked_reason?: string | null;
  finding_id?: string | null;
}

interface ApplicationModel {
  shape: {
    total: number;
    supported: number;
    hypothesized: number;
    routes: number;
    resources: number;
    workflows: number;
    by_kind: Record<string, Record<string, number>>;
  };
  nodes: AppNode[];
  gaps: Gap[];
  candidate_features: Feature[];
}

/**
 * Provenance is the point of this screen, not a detail: an observed route and a hypothesised
 * one look identical in a list, and the difference is exactly what a reader must not lose.
 */
const PROVENANCE_TONE: Record<string, "success" | "warning" | "neutral" | "danger"> = {
  observed: "success",
  spec: "success",
  source: "neutral",
  inferred: "warning",
  hypothesized: "warning",
};

export default function ApplicationTab({ eid, live }: { eid: string; live: number }) {
  const { data, error, loading } = useApi<ApplicationModel>(`/api/engagements/${eid}/application?live=${live}`);
  const hyp = useApi<{ ranked: SecurityHypothesis[]; counts: Record<string, number> }>(
    `/api/engagements/${eid}/security-hypotheses?live=${live}`,
  );
  const [filter, setFilter] = useState("");
  const [kind, setKind] = useState("all");

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return (data?.nodes || []).filter(
      (n) =>
        (kind === "all" || n.kind === kind) &&
        (!q || `${n.kind} ${n.key} ${n.label}`.toLowerCase().includes(q)),
    );
  }, [data, filter, kind]);

  const kinds = useMemo(() => [...new Set((data?.nodes || []).map((n) => n.kind))].sort(), [data]);
  const shape = data?.shape;

  return (
    <div className="space-y-4">
      <Card
        title="Application"
        description="What the engine understands about this application: its functionality, the input surfaces it accepts, and how each fact is known. Nothing here is asserted by a model without evidence."
        actions={
          <div className="flex gap-2">
            <select
              aria-label="Filter by kind"
              value={kind}
              onChange={(e) => setKind(e.target.value)}
              className="input h-7 w-[140px] text-xs"
            >
              <option value="all">All kinds</option>
              {kinds.map((k) => (
                <option key={k} value={k}>{k}</option>
              ))}
            </select>
            <Input
              aria-label="Filter application model"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter…"
              className="h-7 w-48 text-xs"
            />
          </div>
        }
      >
        <ErrorNote error={error} />
        {shape && (
          <div className="grid grid-cols-2 gap-3 pb-3 sm:grid-cols-5">
            {[
              ["Known facts", shape.total],
              ["Evidence-backed", shape.supported],
              ["Hypothesised", shape.hypothesized],
              ["Routes", shape.routes],
              ["Resources", shape.resources],
            ].map(([label, value]) => (
              <div key={String(label)} className="rounded border border-ink-100 px-3 py-2">
                <div className="text-[11px] uppercase tracking-wide text-ink-400">{label}</div>
                <div className="text-lg text-ink-900">{String(value)}</div>
              </div>
            ))}
          </div>
        )}
        {loading && !data ? (
          <TableSkeleton rows={6} cols={4} />
        ) : (
          <Table<AppNode>
            rows={rows}
            getKey={(n) => n.id}
            empty={
              <EmptyState
                title={data?.nodes.length ? "No facts match the filter" : "Nothing understood yet"}
                description={
                  data?.nodes.length
                    ? "Clear the filter to see the whole model."
                    : "The model fills as crawling and discovery observe the application."
                }
              />
            }
            columns={[
              { key: "kind", label: "Kind", render: (n) => <span className="text-xs text-ink-500">{n.kind}</span> },
              {
                key: "key",
                label: "Functionality",
                render: (n) => <span className="text-xs text-ink-900">{n.label || n.key}</span>,
              },
              {
                key: "provenance",
                label: "Known by",
                render: (n) => (
                  <Badge tone={PROVENANCE_TONE[n.provenance] || "neutral"}>{n.provenance}</Badge>
                ),
              },
              {
                key: "evidence",
                label: "Evidence",
                render: (n) =>
                  n.evidence_id ? (
                    <span className="font-mono text-[11px] text-ink-500">{n.evidence_id}</span>
                  ) : (
                    <span className="text-[11px] text-ink-400">
                      {n.source_ref || "no direct evidence"}
                    </span>
                  ),
              },
            ]}
          />
        )}
      </Card>

      {!!data?.candidate_features.length && (
        <Card
          title="Security questions raised by this application"
          description="Each one names a property that should hold and the evidence that raised it. They are hypotheses to test, not findings."
          padded={false}
        >
          <ul className="divide-y divide-ink-100">
            {data.candidate_features.map((f) => (
              <li key={`${f.raised_by}-${f.property}`} className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-ink-900">{f.feature}</span>
                  <Badge tone={PROVENANCE_TONE[f.provenance] || "neutral"}>{f.provenance}</Badge>
                </div>
                <p className="mt-1 text-xs text-ink-600">{f.property}</p>
                <p className="mt-1 text-[11px] text-ink-400">How to test: {f.test}</p>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {!!hyp.data?.ranked.length && (
        <Card
          title="Security questions and their tests"
          description="Derived from the evidence above and ranked deterministically. A question that cannot be tested says what is missing; a question that was answered says so. None of these is a vulnerability until the verifier accepts evidence."
          padded={false}
        >
          <ul className="divide-y divide-ink-100">
            {hyp.data.ranked.slice(0, 12).map((h) => (
              <li key={h.id} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={h.class === "authorization" ? "warning" : "neutral"}>{h.class}</Badge>
                  <Badge tone={h.status === "verified" ? "success" : h.status === "refuted" ? "neutral" : h.status === "blocked" ? "danger" : "warning"}>
                    {h.status}
                  </Badge>
                  <span className="text-xs text-ink-400">score {h.score}</span>
                  {h.factors && (
                    <span className="text-[11px] text-ink-300">
                      {Object.entries(h.factors).map(([k, v]) => `${k} ${v}`).join(" · ")}
                    </span>
                  )}
                </div>
                <p className="mt-1 text-xs text-ink-800">{h.statement}</p>
                <p className="text-[11px] text-ink-500">
                  {h.endpoint || "no endpoint"}
                  {h.param ? ` · param ${h.param}` : ""}
                  {h.resource ? ` · resource ${h.resource}` : ""}
                  {h.owner_field ? ` · owner ${h.owner_field}` : ""}
                </p>
                {!!h.missing.length && (
                  <p className="text-[11px] text-ink-400">Cannot run yet: needs {h.missing.join(", ")}</p>
                )}
                {h.blocked_reason && <p className="text-[11px] text-ink-400">{h.blocked_reason}</p>}
                {!!Object.keys(h.test || {}).length && (
                  <p className="text-[11px] text-ink-400">
                    Test: {String((h.test as Record<string, unknown>).method || "")} —{" "}
                    {String((h.test as Record<string, unknown>).expect || "")}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {!!data?.gaps.length && (
        <Card
          title="Where understanding stops"
          description="Stated so a reader does not mistake silence for coverage."
          padded={false}
        >
          <ul className="divide-y divide-ink-100">
            {data.gaps.slice(0, 12).map((g, i) => (
              <li key={`${g.gap}-${g.endpoint || i}`} className="px-4 py-2">
                <div className="text-xs text-ink-800">
                  {g.gap}
                  {g.endpoint ? <span className="text-ink-500"> · {g.endpoint}</span> : null}
                </div>
                <p className="text-[11px] text-ink-500">{g.detail}</p>
                <p className="text-[11px] text-ink-400">Closes with: {g.would_close_with}</p>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
