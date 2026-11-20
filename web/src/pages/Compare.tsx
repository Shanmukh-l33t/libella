import { Link, useSearchParams } from "react-router-dom";
import { GitCompare } from "lucide-react";
import type { CompareResult, Engagement, Finding } from "../types";
import { useApi } from "../lib/hooks";
import { severityTone, stateTone, title } from "../lib/format";
import { Badge, Card, EmptyState, ErrorNote, Select, Skeleton, cx } from "../components/ui";

export default function Compare() {
  const [params, setParams] = useSearchParams();
  const engagements = useApi<Engagement[]>("/api/engagements");
  const a = params.get("a") || "";
  const b = params.get("b") || "";
  const set = (k: "a" | "b", v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };

  const cmp = useApi<CompareResult>(a && b ? `/api/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}` : null);
  const missing = cmp.error?.startsWith("404") && !cmp.data;
  const list = engagements.data || [];
  const d = cmp.data;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-900">Historical comparison</h1>
        <p className="mt-1 text-sm text-ink-500">
          Diff two assessments by dedup key: what is new, what was fixed, what persists, what changed severity.
          Read it against the coverage limits of both runs.
        </p>
      </div>

      <Card title="Compare engagements" description="Pick a baseline and a follow-up run."
        actions={<Link to="/engagements" className="link text-xs">All engagements</Link>}>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="label">Baseline (a)</span>
            <Select aria-label="Baseline engagement" value={a} onChange={(e) => set("a", e.target.value)}>
              <option value="">Select baseline…</option>
              {list.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
            </Select>
          </label>
          <label className="block">
            <span className="label">Follow-up (b)</span>
            <Select aria-label="Follow-up engagement" value={b} onChange={(e) => set("b", e.target.value)}>
              <option value="">Select follow-up…</option>
              {list.filter((e) => e.id !== a).map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
            </Select>
          </label>
        </div>
      </Card>

      {!a || !b ? (
        <Card><EmptyState icon={<GitCompare size={22} />} title="Choose two engagements"
          description="Findings are matched by dedup key: new, fixed, persisting and severity changes are reported separately." /></Card>
      ) : missing ? (
        <div className="rounded border border-dashed border-line bg-canvas px-4 py-3 text-sm text-ink-500">
          <span className="font-medium text-ink-700">Engagement comparison</span> is unavailable on this backend build — it becomes available after the backend update.
        </div>
      ) : cmp.loading && !d ? <Skeleton className="h-64 w-full" /> : !d ? <ErrorNote error={cmp.error} /> : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-6">
            <Mini label="New in follow-up" value={d.counts?.new ?? 0} />
            <Mini label="Retested fixed" value={d.counts?.fixed ?? 0} tone={d.counts?.fixed ? "success" : undefined} />
            <Mini label="Not observed" value={d.counts?.not_observed ?? 0} />
            <Mini label="Persisting" value={d.counts?.persisting ?? 0} />
            <Mini label="Severity changed" value={d.counts?.severity_changed ?? 0} />
            <Mini label="Findings a → b" value={`${d.a?.findings ?? 0} → ${d.b?.findings ?? 0}`} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <DiffList title={`New in ${d.b?.name || "follow-up"}`} hint="Not present in the baseline (by dedup key)." rows={d.new || []} empty="nothing new" />
            <DiffList title="Retested fixed" hint="Marked fixed by a follow-up retest." rows={d.fixed || []} empty="no confirmed fixes" tone="success" />
            <DiffList title="Not observed" hint="Absent from the follow-up. This is not evidence of a fix." rows={d.not_observed || []} empty="no missing baseline findings" />
            <DiffList title="Persisting" hint="Same dedup key, still present. A retest verdict decides whether it is really fixed." rows={d.persisting || []} empty="nothing persisting" />
            <SeverityList rows={d.severity_changed || []} />
          </div>
        </>
      )}
    </div>
  );
}

function DiffList({ title: heading, hint, rows, empty, tone }: { title: string; hint: string; rows: Finding[]; empty: string; tone?: "success" }) {
  return (
    <Card title={heading} description={hint} padded={false}
      actions={<span className="text-2xs tabular-nums text-ink-500">{rows.length}</span>}>
      {!rows.length ? <p className="px-4 py-5 text-sm text-ink-500">{empty}</p> : (
        <ul className="max-h-[420px] divide-y divide-line/70 overflow-y-auto">
          {rows.map((f) => (
            <li key={f.id} className="px-4 py-2.5">
              <div className="flex items-start gap-2">
                <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                <Link to={`/findings/${f.id}`} className="line-clamp-2 text-xs font-medium text-ink-900 hover:text-accent">{f.title}</Link>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-2xs text-ink-500">
                <Badge tone={tone === "success" ? "success" : stateTone(f.state)}>{title(f.state)}</Badge>
                {(f as Finding & { reason?: string }).reason && <span>{title((f as Finding & { reason?: string }).reason!)}</span>}
                {f.owner && <span>owner {f.owner}</span>}
                <span className="truncate font-mono">{f.endpoint || ""}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function SeverityList({ rows }: { rows: (Finding & { previous_severity?: string; direction?: string })[] }) {
  return (
    <Card title="Severity changed" description="Same finding, different severity between runs." padded={false}
      actions={<span className="text-2xs tabular-nums text-ink-500">{rows.length}</span>}>
      {!rows.length ? <p className="px-4 py-5 text-sm text-ink-500">no severity changes</p> : (
        <ul className="max-h-[420px] divide-y divide-line/70 overflow-y-auto">
          {rows.map((f) => (
            <li key={f.id} className="px-4 py-2.5">
              <Link to={`/findings/${f.id}`} className="line-clamp-2 text-xs font-medium text-ink-900 hover:text-accent">{f.title}</Link>
              <div className="mt-1 flex items-center gap-2 text-2xs">
                <Badge tone={severityTone(f.previous_severity || "info")}>{f.previous_severity}</Badge>
                <span className="text-ink-300">→</span>
                <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                <span className={f.direction === "worse" ? "text-sev-high" : "text-[#027A48]"}>{f.direction}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function Mini({ label, value, tone }: { label: string; value: number | string; tone?: "success" }) {
  return (
    <div className="rounded border border-line bg-white px-3 py-2">
      <div className="text-2xs text-ink-500">{label}</div>
      <div className={cx("mt-0.5 text-base font-semibold tabular-nums", tone === "success" ? "text-[#027A48]" : "text-ink-900")}>{value}</div>
    </div>
  );
}