import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ClipboardCheck } from "lucide-react";
import { put } from "../api";
import type { Engagement } from "../types";
import { useApi } from "../lib/hooks";
import { Badge, Button, Card, EmptyState, ErrorNote, Field, Input, Modal, Select, Skeleton, Table, Textarea } from "../components/ui";

type Status = "covered" | "manual" | "unsupported" | "unknown";
const STATUSES: Status[] = ["covered", "manual", "unsupported", "unknown"];
const TONE: Record<Status, "success" | "info" | "warning" | "neutral"> = {
  covered: "success", manual: "info", unsupported: "warning", unknown: "neutral",
};
const HELP: Record<Status, string> = {
  covered: "Performed, with evidence from this engagement attached.",
  manual: "Reviewed by hand; the note says what was checked.",
  unsupported: "Not testable here; the note says why.",
  unknown: "Not reviewed. This is the default and is never a pass.",
};

interface Item { id: string; title: string; status: Status; note?: string | null; evidence_id?: string | null; updated_at?: number | null }
interface Category { id: string; name: string; counts: Record<Status, number>; tests: Item[] }
interface Workspace {
  framework: { id: string; version: string; title: string; source: string; tests: number };
  engagement_id: string;
  summary: Record<Status, number> & { total: number };
  categories: Category[];
}

export default function Coverage() {
  const [params, setParams] = useSearchParams();
  const engagements = useApi<Engagement[]>("/api/engagements");
  const eid = params.get("engagement") || "";
  const ws = useApi<Workspace>(eid ? `/api/engagements/${encodeURIComponent(eid)}/coverage/wstg` : null);
  const [editing, setEditing] = useState<Item | null>(null);
  const [status, setStatus] = useState<Status>("manual");
  const [note, setNote] = useState("");
  const [evidence, setEvidence] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const open = (item: Item) => {
    setEditing(item); setStatus(item.status);
    setNote(item.note || ""); setEvidence(item.evidence_id || ""); setError(null);
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

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-900">WSTG 4.2 coverage</h1>
        <p className="mt-1 text-sm text-ink-500">
          The {d?.framework.version || "4.2"} test catalog with what this engagement actually reviewed.
          Everything not recorded stays <span className="font-medium text-ink-700">unknown</span> — it is not a pass,
          and nothing here runs a tool.
        </p>
      </div>

      <Card title="Engagement" description="Coverage is recorded per engagement and never shared across them.">
        <label className="block max-w-md">
          <span className="label">Engagement</span>
          <Select aria-label="Engagement" value={eid}
            onChange={(e) => {
              const next = new URLSearchParams(params);
              if (e.target.value) next.set("engagement", e.target.value); else next.delete("engagement");
              setParams(next, { replace: true });
            }}>
            <option value="">Select engagement…</option>
            {list.map((e) => <option key={e.id} value={e.id}>{e.name} · {e.status}</option>)}
          </Select>
        </label>
        <p className="mt-3 text-xs text-ink-500">
          {STATUSES.map((s) => <span key={s} className="mr-3 inline-flex items-center gap-1">
            <Badge tone={TONE[s]}>{s}</Badge>{HELP[s]}</span>)}
        </p>
      </Card>

      <ErrorNote error={ws.error} />

      {!eid ? (
        <Card><EmptyState icon={<ClipboardCheck size={22} />} title="Choose an engagement"
          description={`The catalog lists all ${d?.framework.tests || 96} WSTG 4.2 tests grouped by category.`} /></Card>
      ) : ws.loading && !d ? <Skeleton className="h-64 w-full" /> : !d ? null : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            <Mini label="Catalog" value={d.summary.total} />
            <Mini label="Covered" value={d.summary.covered} tone="success" />
            <Mini label="Manual" value={d.summary.manual} />
            <Mini label="Unsupported" value={d.summary.unsupported} />
            <Mini label="Unknown" value={d.summary.unknown} />
          </div>
          <p className="text-xs text-ink-500">
            Coverage: {d.framework.title} v{d.framework.version} · {d.framework.tests} tests ·{" "}
            <a className="link" href={d.framework.source} target="_blank" rel="noreferrer">catalog source</a>
          </p>

          {d.categories.map((c) => (
            <Card key={c.id} title={<span className="inline-flex items-center gap-2">
              <span className="font-mono text-xs text-ink-700">{c.id}</span>{c.name}</span>}
              description={`${c.tests.length} tests`} padded={false}
              actions={<span className="flex gap-1">
                {STATUSES.filter((s) => c.counts[s]).map((s) => <Badge key={s} tone={TONE[s]}>{c.counts[s]} {s}</Badge>)}
              </span>}>
              <Table<Item>
                rows={c.tests} getKey={(t) => t.id} dense
                onRowClick={open}
                columns={[
                  { key: "id", label: "ID", render: (t) => <span className="font-mono text-2xs text-ink-700">{t.id}</span> },
                  { key: "title", label: "Test", render: (t) => <span className="text-xs text-ink-900">{t.title}</span> },
                  { key: "status", label: "Status", sortValue: (t) => t.status, render: (t) => <Badge tone={TONE[t.status]}>{t.status}</Badge> },
                  { key: "note", label: "Note", render: (t) => <span className="block max-w-[380px] truncate text-2xs text-ink-500">{t.note || "—"}</span> },
                  { key: "evidence", label: "Evidence", render: (t) => <span className="font-mono text-2xs text-ink-500">{t.evidence_id || "—"}</span> },
                ]}
              />
            </Card>
          ))}
        </>
      )}

      <Modal open={!!editing} onClose={() => setEditing(null)}
        title={editing ? `${editing.id} · ${editing.title}` : ""}
        footer={<><Button variant="ghost" onClick={() => setEditing(null)}>Cancel</Button>
          <Button onClick={save} disabled={saving}>{saving ? "Saving…" : "Save review"}</Button></>}>
        <div className="space-y-3">
          <Field label="Status" hint={HELP[status]}>
            <Select aria-label="Review status" value={status} onChange={(e) => setStatus(e.target.value as Status)}>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
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
      </Modal>
    </div>
  );
}

function Mini({ label, value, tone }: { label: string; value: number; tone?: "success" }) {
  return (
    <div className="rounded border border-line bg-white px-3 py-2">
      <div className="text-2xs text-ink-500">{label}</div>
      <div className={tone === "success" ? "mt-0.5 text-base font-semibold tabular-nums text-[#027A48]" : "mt-0.5 text-base font-semibold tabular-nums text-ink-900"}>{value}</div>
    </div>
  );
}