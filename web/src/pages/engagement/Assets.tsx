import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import type { Asset } from "../../types";
import { useApi } from "../../lib/hooks";
import { fmtTime } from "../../lib/format";
import { Badge, Card, EmptyState, ErrorNote, Input, Table, TableSkeleton } from "../../components/ui";

export default function AssetsTab({ eid, live }: { eid: string; live: number }) {
  const { data, error, loading } = useApi<Asset[]>(`/api/engagements/${eid}/assets?live=${live}`);
  const [filter, setFilter] = useState("");

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return data || [];
    return (data || []).filter((a) =>
      [a.kind, a.key, a.discovered_by || "", JSON.stringify(a.value)].some((v) => v.toLowerCase().includes(q)),
    );
  }, [data, filter]);

  return (
    <Card
      title="Assets"
      description="Everything discovered inside scope, with the tool that found it and when it was last seen."
      padded={false}
      actions={
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-300" />
          <Input aria-label="Filter assets" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter…" className="h-7 w-52 pl-7 text-xs" />
        </div>
      }
    >
      <ErrorNote error={error} />
      {loading && !data ? <TableSkeleton rows={6} cols={5} /> : (
        <Table<Asset>
          rows={rows}
          getKey={(a) => a.id}
          empty={
            <EmptyState
              title={data?.length ? "No assets match the filter" : "No assets discovered yet"}
              description={data?.length ? "Clear the filter to see all discovered assets." : "Assets are recorded as crawling and discovery run inside scope."}
            />
          }
          columns={[
            { key: "kind", label: "Kind", sortValue: (a) => a.kind, render: (a) => <Badge>{a.kind}</Badge> },
            { key: "key", label: "Key", sortValue: (a) => a.key, render: (a) => <span className="font-mono text-xs text-ink-900 break-all">{a.key}</span> },
            { key: "discovered_by", label: "Discovered by", sortValue: (a) => a.discovered_by || "", render: (a) => <span className="font-mono text-xs text-ink-500">{a.discovered_by || "—"}</span> },
            { key: "value", label: "Attributes", render: (a) => <span className="block max-w-[280px] truncate font-mono text-2xs text-ink-500" title={JSON.stringify(a.value)}>{Object.keys(a.value || {}).length ? JSON.stringify(a.value) : "—"}</span> },
            { key: "first_seen", label: "First seen", sortValue: (a) => a.first_seen || 0, render: (a) => <span className="whitespace-nowrap text-xs text-ink-700">{fmtTime(a.first_seen)}</span> },
            { key: "last_seen", label: "Last seen", sortValue: (a) => a.last_seen || 0, render: (a) => <span className="whitespace-nowrap text-xs text-ink-500">{fmtTime(a.last_seen)}</span> },
          ]}
        />
      )}
    </Card>
  );
}