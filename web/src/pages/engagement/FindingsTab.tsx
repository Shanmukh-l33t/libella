import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Finding } from "../../types";
import { useApi } from "../../lib/hooks";
import { SEV_ORDER, severityTone, stateTone, title } from "../../lib/format";
import { Badge, Card, EmptyState, ErrorNote, Select, Table, TableSkeleton } from "../../components/ui";

const STATES = ["suspected", "observed", "validated", "reported", "remediated", "retested_fixed", "retested_persists", "ruled_out"];
const CONF = { low: 0, medium: 1, high: 2 } as Record<string, number>;

export default function FindingsTab({ eid, live }: { eid: string; live: number }) {
  const navigate = useNavigate();
  const { data, error, loading } = useApi<Finding[]>(`/api/engagements/${eid}/findings?live=${live}`);
  const [sev, setSev] = useState("all");
  const [state, setState] = useState("all");

  const rows = useMemo(
    () => (data || []).filter((f) => (sev === "all" || f.severity === sev) && (state === "all" || f.state === state)),
    [data, sev, state],
  );

  return (
    <Card
      title="Findings"
      description="Only what the checks produced and evidence supports. Suspected items have not been reproduced yet."
      padded={false}
      actions={
        <div className="flex gap-2">
          <Select aria-label="Filter by severity" value={sev} onChange={(e) => setSev(e.target.value)} className="h-7 w-[130px] text-xs">
            <option value="all">All severities</option>
            {SEV_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Select aria-label="Filter by state" value={state} onChange={(e) => setState(e.target.value)} className="h-7 w-[150px] text-xs">
            <option value="all">All states</option>
            {STATES.map((s) => <option key={s} value={s}>{title(s)}</option>)}
          </Select>
        </div>
      }
    >
      <ErrorNote error={error} />
      {loading && !data ? <TableSkeleton rows={5} cols={6} /> : (
        <Table<Finding>
          rows={rows}
          getKey={(f) => f.id}
          onRowClick={(f) => navigate(`/findings/${f.id}`)}
          empty={
            <EmptyState
              title={data?.length ? "No findings match these filters" : "No findings yet"}
              description={data?.length ? "Adjust severity or state." : "Findings appear here when a check produces evidence that supports a claim."}
            />
          }
          columns={[
            { key: "severity", label: "Severity", sortValue: (f) => SEV_ORDER.indexOf(f.severity), render: (f) => <Badge tone={severityTone(f.severity)}>{f.severity}</Badge> },
            { key: "title", label: "Title", sortValue: (f) => f.title, render: (f) => <span className="block max-w-[420px] font-medium text-ink-900">{f.title}</span> },
            { key: "cwe", label: "CWE", sortValue: (f) => f.cwe || "", render: (f) => <span className="font-mono text-xs text-ink-500">{f.cwe || "—"}</span> },
            { key: "state", label: "State", sortValue: (f) => STATES.indexOf(f.state), render: (f) => <Badge tone={stateTone(f.state)} dot>{title(f.state)}</Badge> },
            { key: "confidence", label: "Confidence", sortValue: (f) => CONF[f.confidence] ?? 0, render: (f) => <span className="text-xs capitalize text-ink-700">{f.confidence}</span> },
            { key: "endpoint", label: "Endpoint", render: (f) => <span className="block max-w-[260px] truncate font-mono text-2xs text-ink-500" title={f.endpoint || ""}>{f.endpoint || "—"}</span> },
          ]}
        />
      )}
    </Card>
  );
}