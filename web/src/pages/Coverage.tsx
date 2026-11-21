import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ClipboardCheck } from "lucide-react";
import { put } from "../api";
import type { Engagement } from "../types";
import { useApi } from "../lib/hooks";
import { Badge, Button, Card, EmptyState, ErrorNote, Field, Input, Modal, Select, Skeleton, Table, Textarea } from "../components/ui";

/** Automatic status: what the engagement actually executed. Never a claim of security. */
type AutoStatus =
  | "not_applicable" | "not_supported" | "requires_manual" | "skipped_policy"
  | "skipped_dependency" | "attempted" | "inconclusive" | "failed"
  | "completed_no_issue" | "finding_unverified" | "finding_verified";
const AUTO: AutoStatus[] = [
  "not_applicable", "not_supported", "requires_manual", "skipped_policy", "skipped_dependency",
  "attempted", "inconclusive", "failed", "completed_no_issue", "finding_unverified",
  "finding_verified",
];
/** Manual review vocabulary, exactly as the server stores it. */
type Review = "covered" | "manual" | "unsupported" | "unknown";
const REVIEWS: Review[] = ["covered", "manual", "unsupported", "unknown"];

const AUTO_TONE: Record<AutoStatus, "success" | "info" | "warning" | "danger" | "neutral"> = {
  not_applicable: "neutral", not_supported: "warning", requires_manual: "warning",
  skipped_policy: "warning", skipped_dependency: "warning", attempted: "info",
  inconclusive: "warning", failed: "danger", completed_no_issue: "success",
  finding_unverified: "info", finding_verified: "danger",
};
const AUTO_HELP: Record<AutoStatus, string> = {
  not_applicable: "The engagement scope has no web category, so the web framework does not apply.",
  not_supported: "No Libella check reaches this surface and the evidence sits outside the engagement model.",
  requires_manual: "No automated check exists; a tester has to perform this test by hand.",
  skipped_policy: "The engagement profile refused the mapped check. Untested, not failed.",
  skipped_dependency: "A mapped tool or dependency was missing, so the check could not run.",
  attempted: "Scheduled or running without a completion record.",
  inconclusive: "Ran partially (timeout/cancel) or never ran; nothing can be concluded.",
  failed: "The mapped check ran and failed. No result.",
  completed_no_issue: "The mapped check executed and recorded no finding. Only as good as the check.",
  finding_unverified: "A finding from the mapped check is recorded but not independently validated.",
  finding_verified: "A finding from the mapped check was independently replayed.",
};
const REVIEW_TONE: Record<Review, "success" | "info" | "warning" | "neutral"> = {
  covered: "success", manual: "info", unsupported: "warning", unknown: "neutral",
};
const REVIEW_HELP: Record<Review, string> = {
  covered: "Reviewed by hand, with evidence from this engagement attached.",
  manual: "Reviewed by hand; the note says what was checked.",
  unsupported: "Not testable here; the note says why.",
  unknown: "Clears the manual record and shows the automatic status only.",
};

interface Evidence { tool_calls: string[]; exchanges: string[]; intents: string[]; events: number[]; findings: string[] }
interface Item {
  id: string; title: string; status: AutoStatus | Review;
  automatic: { status: AutoStatus; reason: string; units: string[] };
  manual: { status: Review; note?: string | null; evidence_id?: string | null; updated_at?: number | null } | null;
  evidence: Evidence;
}
interface Category { id: string; name: string; counts: Record<AutoStatus, number>; tests: Item[] }
interface Workspace {
  framework: { id: string; version: string; title: string; source: string; tests: number };
  engagement_id: string;
  summary: Record<"total" | "applicable" | "supported" | "attempted" | "completed" | "with_findings"
    | "skipped" | "manual_required" | "not_tested", number>
    & { statuses: Record<AutoStatus, number>; manual: Record<"covered" | "manual" | "unsupported", number> };
  categories: Category[];
}

export default function Coverage() {
  const [params, setParams] = useSearchParams();
  const engagements = useApi<Engagement[]>("/api/engagements");
  const eid = params.get("engagement") || "";
  const ws = useApi<Workspace>(eid ? `/api/engagements/${encodeURIComponent(eid)}/coverage/wstg` : null);
  const [editing, setEditing] = useState<Item | null>(null);
  const [status, setStatus] = useState<Review>("manual");
  const [note, setNote] = useState("");
  const [evidence, setEvidence] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [filter, setFilter] = useState<"all" | AutoStatus | Review>("all");

  const open = (item: Item) => {
    setEditing(item); setStatus(item.manual?.status || "manual");
    setNote(item.manual?.note || ""); setEvidence(item.manual?.evidence_id || ""); setError(null);
  };

  const save = async () => {
    if (!editing) return;
    setSaving(true); setError(null);
    try {
      // The server owns the rules: covered needs this engagement's evidence, manual/unsupported need a note.
      await put(`/api/engagements/${encodeURIComponent(eid)}/coverage/wstg/${encodeURIComponent(editing.id)}`,
        { status, note: note.trim(), evidence_id: evidence.trim() || undefined });
      setEditing(null);
      ws.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const list = engagements.data || [];
  const d = ws.data;
  const rows = (tests: Item[]) => (filter === "all" ? tests : tests.filter((t) => t.status === filter));

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-900">WSTG 4.2 coverage</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-500">
          Two records per test, both always shown. <span className="font-medium text-ink-700">Executed</span> is
          derived from what this engagement actually ran — intents, tool calls, captured exchanges and findings.
          <span className="font-medium text-ink-700"> Review</span> is what an operator recorded by hand and
          overrides the displayed status when set. A test that was not tested is not a pass, and nothing here
          runs a tool.
        </p>
      </div>

      <Card title="Engagement" description="Coverage is recorded per engagement and never shared across them.">
        <div className="flex flex-wrap items-end gap-3">
          <label className="block w-full max-w-md">
            <span className="label">Engagement</span>
            <Select aria-label="Engagement" value={eid}
              onChange={(e) => {
                const next = new URLSearchParams(params);
                if (e.target.value) next.set("engagement", e.target.value); else next.delete("engagement");
                setParams(next, { replace: true });
              }}>
              <option value="">Select engagement…</option>
              {list.map((e) => <option key={e.id} value={e.id}>{e.name} · {e.status} · {e.profile}</option>)}
            </Select>
          </label>
          <label className="block w-full max-w-xs">
            <span className="label">Filter by status</span>
            <Select aria-label="Filter by status" value={filter}
              onChange={(e) => setFilter(e.target.value as typeof filter)}>
              <option value="all">All statuses ({d ? d.summary.total : 96})</option>
              {AUTO.map((s) => <option key={s} value={s}>{s}{d ? ` (${d.summary.statuses[s]})` : ""}</option>)}
              {REVIEWS.filter((r) => r !== "unknown").map((r) => (
                <option key={r} value={r}>review: {r}{d ? ` (${d.summary.manual[r]})` : ""}</option>
              ))}
            </Select>
          </label>
        </div>
        <p className="mt-3 text-xs text-ink-500">
          {AUTO.filter((s) => d?.summary.statuses[s]).map((s) => <span key={s} className="mr-3 inline-flex items-center gap-1">
            <Badge tone={AUTO_TONE[s]}>{s}</Badge>{AUTO_HELP[s]}</span>)}
        </p>
      </Card>

      <ErrorNote error={ws.error} />

      {!eid ? (
        <Card><EmptyState icon={<ClipboardCheck size={22} />} title="Choose an engagement"
          description={`The catalog lists all ${d?.framework.tests || 96} WSTG 4.2 tests grouped by category.`} /></Card>
      ) : ws.loading && !d ? <Skeleton className="h-64 w-full" /> : !d ? null : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Mini label="Applicable" value={d.summary.applicable} hint="tests the scope can reach" />
            <Mini label="Supported" value={d.summary.supported} hint="a Libella check can exercise them" />
            <Mini label="Attempted" value={d.summary.attempted} hint="a check started" />
            <Mini label="Completed" value={d.summary.completed} tone="success" hint="executed to a result" />
            <Mini label="With findings" value={d.summary.with_findings} tone="danger" hint="verified or unverified" />
            <Mini label="Skipped" value={d.summary.skipped} hint="profile or dependency" />
            <Mini label="Manual required" value={d.summary.manual_required} hint="no automated check exists" />
            <Mini label="Not tested" value={d.summary.not_tested} tone="danger" hint="never completed — not a pass" />
          </div>
          <p className="text-xs text-ink-500">
            {d.framework.title} v{d.framework.version} · {d.framework.tests} tests ·{" "}
            <a className="link" href={d.framework.source} target="_blank" rel="noreferrer">catalog source</a>
          </p>

          {d.categories.map((c) => {
            const tests = rows(c.tests);
            return (
              <Card key={c.id} title={<span className="inline-flex items-center gap-2">
                <span className="font-mono text-xs text-ink-700">{c.id}</span>{c.name}</span>}
                description={`${tests.length} of ${c.tests.length} tests shown`} padded={false}
                actions={<span className="flex flex-wrap gap-1">
                  {AUTO.filter((s) => c.counts[s]).map((s) => <Badge key={s} tone={AUTO_TONE[s]}>{c.counts[s]} {s}</Badge>)}
                </span>}>
                {tests.length === 0 ? (
                  <div className="px-4 py-6 text-center text-xs text-ink-500">No test in this category has that status.</div>
                ) : (
                  <Table<Item>
                    rows={tests} getKey={(t) => t.id} dense onRowClick={open}
                    columns={[
                      { key: "id", label: "ID", render: (t) => <span className="font-mono text-2xs text-ink-700">{t.id}</span> },
                      { key: "title", label: "Test", render: (t) => <span className="text-xs text-ink-900">{t.title}</span> },
                      { key: "auto", label: "Executed", sortValue: (t) => t.automatic.status, render: (t) => (
                        <div className="space-y-0.5">
                          <Badge tone={AUTO_TONE[t.automatic.status]}>{t.automatic.status}</Badge>
                          <div className="max-w-[260px] truncate text-2xs text-ink-500" title={t.automatic.reason}>
                            {t.automatic.reason}
                          </div>
                        </div>
                      ) },
                      { key: "review", label: "Review", sortValue: (t) => t.manual?.status || "", render: (t) => (
                        t.manual?.status
                          ? <Badge tone={REVIEW_TONE[t.manual.status]}>{t.manual.status}</Badge>
                          : <span className="text-2xs text-ink-300">—</span>
                      ) },
                      { key: "evidence", label: "Evidence", render: (t) => (
                        <span className="font-mono text-2xs text-ink-500">{evidenceSummary(t)}</span>
                      ) },
                    ]}
                  />
                )}
              </Card>
            );
          })}
        </>
      )}

      <Modal open={!!editing} onClose={() => setEditing(null)} width="max-w-2xl"
        title={editing ? `${editing.id} · ${editing.title}` : ""}
        footer={<><Button variant="ghost" onClick={() => setEditing(null)}>Cancel</Button>
          <Button onClick={save} disabled={saving}>{saving ? "Saving…" : "Save review"}</Button></>}>
        {editing && (
          <div className="space-y-4">
            <div className="rounded border border-line bg-ink-100 px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="text-2xs uppercase tracking-wide text-ink-500">Automatically derived</span>
                <Badge tone={AUTO_TONE[editing.automatic.status]}>{editing.automatic.status}</Badge>
              </div>
              <p className="mt-1 text-xs text-ink-700">{editing.automatic.reason}</p>
              <p className="mt-1 text-2xs text-ink-500">{AUTO_HELP[editing.automatic.status]}</p>
              <p className="mt-2 break-words font-mono text-2xs text-ink-500">
                {[
                  editing.evidence.findings.length && `findings: ${editing.evidence.findings.join(", ")}`,
                  editing.evidence.tool_calls.length && `tool_calls: ${editing.evidence.tool_calls.join(", ")}`,
                  editing.evidence.exchanges.length && `exchanges: ${editing.evidence.exchanges.length}`,
                  editing.evidence.intents.length && `intents: ${editing.evidence.intents.join(", ")}`,
                  editing.evidence.events.length && `degradations: #${editing.evidence.events.join(", #")}`,
                ].filter(Boolean).join(" · ") || "no evidence recorded"}
              </p>
            </div>
            <Field label="Review status" hint={REVIEW_HELP[status]}>
              <Select aria-label="Review status" value={status}
                onChange={(e) => setStatus(e.target.value as Review)}>
                {REVIEWS.map((s) => <option key={s} value={s}>{s}</option>)}
              </Select>
            </Field>
            <Field label="Note" hint={status === "manual" || status === "unsupported"
              ? "Required: what you checked, or why it cannot be tested here." : "Optional context for the reviewer."}>
              <Textarea aria-label="Review note" rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
            </Field>
            <Field label="Evidence ID" hint="Only for covered: an ev_ id from this engagement. A foreign or missing id is rejected.">
              <Input aria-label="Evidence ID" value={evidence} onChange={(e) => setEvidence(e.target.value)}
                placeholder="ev_…" disabled={status !== "covered"} />
            </Field>
            <ErrorNote error={error} />
          </div>
        )}
      </Modal>
    </div>
  );
}

function evidenceSummary(t: Item) {
  const calls = t.evidence.tool_calls.length + t.evidence.exchanges.length;
  const findings = t.evidence.findings.length;
  return `${findings ? `${findings} finding${findings > 1 ? "s" : ""} · ` : ""}${calls} call${calls === 1 ? "" : "s"}`;
}

function Mini({ label, value, tone, hint }: {
  label: string; value: number; tone?: "success" | "danger"; hint?: string;
}) {
  const color = tone === "success" ? "text-[#027A48]" : tone === "danger" ? "text-sev-high" : "text-ink-900";
  return (
    <div className="rounded border border-line bg-white px-3 py-2" title={hint}>
      <div className="text-2xs text-ink-500">{label}</div>
      <div className={`mt-0.5 text-base font-semibold tabular-nums ${color}`}>{value}</div>
      {hint && <div className="text-2xs text-ink-300">{hint}</div>}
    </div>
  );
}