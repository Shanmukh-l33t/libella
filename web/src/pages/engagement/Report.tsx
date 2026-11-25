import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Download, FileText, RefreshCw } from "lucide-react";
import type { Engagement, Report } from "../../types";
import { downloadReport, type ReportFormat, type ReportKind } from "../../api";
import { useApi } from "../../lib/hooks";
import { fmtTime, money, severityTone, stateTone, title } from "../../lib/format";
import { Badge, Button, Card, EmptyState, ErrorNote, Select, Skeleton, Stat, Table } from "../../components/ui";

const FORMAT_LABEL: Record<string, string> = {
  pdf: "PDF", html: "HTML", md: "Markdown", docx: "Word", xlsx: "Excel",
  csv: "CSV", json: "JSON", sarif: "SARIF", dojo: "DefectDojo",
};

export default function ReportTab({ eid, eng, live }: { eid: string; eng: Engagement; live: number }) {
  const navigate = useNavigate();
  const { data, error, loading, reload } = useApi<Report>(`/api/engagements/${eid}/report?format=json&live=${live}`);
  const [dlError, setDlError] = useState<string | null>(null);
  const kinds = useApi<{ kinds: { id: ReportKind; title: string; description: string; formats: string[] }[] }>(
    `/api/engagements/${eid}/report/kinds`);
  const [kind, setKind] = useState<ReportKind>("technical");
  const formats = kinds.data?.kinds.find((k) => k.id === kind)?.formats || [];
  const download = (format: ReportFormat) => {
    setDlError(null);
    downloadReport(eid, format, kind).catch((e) => setDlError(e instanceof Error ? e.message : String(e)));
  };

  // Keep the last good report and the controls on screen: a failed re-render must
  // leave the operator a way to retry, not replace the whole tab with an error.
  if (error && !data) return (
    <div className="space-y-3">
      <ErrorNote error={error} />
      <Button size="sm" icon={<RefreshCw size={13} />} onClick={reload} loading={loading}>Retry</Button>
    </div>
  );
  if (loading && !data) return <Skeleton className="h-64 w-full" />;
  if (!data) return <EmptyState title="Report unavailable" description="The API returned no report for this engagement." />;

  const s = data.summary as Record<string, any>;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-ink-900">Report</h2>
          <p className="mt-0.5 text-xs text-ink-500">
            Deterministically rendered from captured evidence · generated {fmtTime(data.generated_at)} ·
            status <span className="text-ink-700">{title(data.engagement.status)}</span>
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" icon={<RefreshCw size={13} />} onClick={reload} loading={loading}>Regenerate</Button>
          <Select aria-label="Report type" className="w-auto" value={kind}
            onChange={(e) => setKind(e.target.value as ReportKind)}>
            {(kinds.data?.kinds || [{ id: "technical" as ReportKind, title: "Technical report", description: "", formats: [] }])
              .map((k) => <option key={k.id} value={k.id}>{k.title}</option>)}
          </Select>
          {formats.map((f) => (
            <Button key={f} size="sm" icon={<Download size={13} />} onClick={() => download(f as ReportFormat)}>
              {FORMAT_LABEL[f] || f.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>

      <ErrorNote error={error || dlError} />

      {data.engagement.status !== "done" && (
        <div className="rounded border border-[#FEDF89] bg-[#FFFAEB] px-4 py-3 text-sm text-ink-700">
          Assessment status is <span className="font-medium">{title(data.engagement.status)}</span>
          {data.engagement.status_detail ? ` — ${data.engagement.status_detail}` : ""}. Results may be incomplete.
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Assets" value={s.assets ?? 0} />
        <Stat label="Findings" value={s.findings_total ?? 0} hint={`${s.confirmed ?? 0} validated`} />
        <Stat label="Intents done" value={`${s.intents_done ?? 0}/${s.intents ?? 0}`} hint={`${s.intents_blocked ?? 0} blocked`} />
        <Stat label="Tool calls" value={s.tool_calls ?? 0} hint={`${s.scope_refusals ?? 0} refused in scope`} />
        <Stat label="Model spend" value={money(s.llm_cost_usd)} hint={`${(s.llm_tokens ?? 0).toLocaleString()} tokens`} />
      </div>

      {data.degradations.length > 0 && (
        <Card title="Coverage limitations" description="Read before trusting a low finding count.">
          <ul className="space-y-1.5 text-sm">
            {data.degradations.map((d, i) => (
              <li key={i} className="flex gap-2"><span className="font-mono text-xs text-[#B54708]">{d.code}</span><span className="text-ink-700">{d.detail}</span></li>
            ))}
          </ul>
        </Card>
      )}

      <Card title="Scope evaluated" padded={false}>
        <div className="flex flex-wrap gap-1.5 p-4">
          {(data.scope?.targets || []).map((t, i) => (
            <span key={i} className="rounded border border-line bg-canvas px-1.5 py-0.5 font-mono text-2xs text-ink-700">{t.kind} · {t.value}</span>
          ))}
          {(data.scope?.exclusions || []).map((t, i) => (
            <span key={`x${i}`} className="rounded border border-dashed border-line px-1.5 py-0.5 font-mono text-2xs text-ink-500">excluded {t.kind} · {t.value}</span>
          ))}
        </div>
      </Card>

      <Card title={`Findings (${data.findings.length})`} description="Click a row to open the full finding with evidence and verification." padded={false}>
        <Table
          rows={data.findings}
          getKey={(f) => f.id}
          onRowClick={(f) => navigate(`/findings/${f.id}`)}
          empty={<EmptyState icon={<FileText size={22} />} title="No findings in this report" description="Look at coverage limitations above before reading this as secure." />}
          columns={[
            { key: "severity", label: "Severity", render: (f) => <Badge tone={severityTone(f.severity)}>{f.severity}</Badge> },
            { key: "title", label: "Title", render: (f) => <span className="font-medium text-ink-900">{f.title}</span> },
            { key: "cwe", label: "CWE", render: (f) => <span className="font-mono text-xs text-ink-500">{f.cwe || "—"}</span> },
            { key: "state", label: "State", render: (f) => <Badge tone={stateTone(f.state)}>{title(f.state)}</Badge> },
            {
              key: "verification", label: "Verification",
              render: (f) => f.verifications?.length
                ? <span className="text-xs text-ink-700">{f.verifications[f.verifications.length - 1].verdict}</span>
                : <span className="text-xs text-ink-300">none</span>,
            },
          ]}
        />
      </Card>

      <p className="text-2xs text-ink-500">
        Downloads are fetched with the bearer header; the live stream alone uses a single-use,
        one-minute ticket because EventSource cannot set headers. Engagement profile: {eng.profile}.
      </p>
    </div>
  );
}