/** One requirement, end to end: what it requires, what executed, what is left.
 *
 * A right-hand drawer, not a modal: the operator keeps the ledger in view while
 * reading a single row. It writes nothing except through the existing review PUT.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, X } from "lucide-react";
import { put, post } from "../../api";
import type { Finding } from "../../types";
import { fmtTime, severityTone, stateTone } from "../../lib/format";
import { Badge, Button, ErrorNote, Field, Input, Select, Textarea } from "../../components/ui";
import { HELP, REVIEWS, REVIEW_TONE, TONE, UNTESTED, type Item, type Mapping, type Review } from "./model";

import ReviewActivity from "./ReviewActivity";

const REVIEW_HELP: Record<Review, string> = {
  covered: "Reviewed by hand, with evidence from this engagement attached.",
  manual: "Reviewed by hand; the note says what was checked.",
  unsupported: "Not testable here; the note says why.",
  unknown: "Clears the manual record and shows the automatic status only.",
};

export default function RequirementDrawer({ eid, fw, item, mapping, findings, onClose, onSaved }: {
  eid: string; fw: string; item: Item; mapping: Mapping; findings: Finding[];
  onClose: () => void; onSaved: () => void;
}) {
  const [status, setStatus] = useState<Review>(item.manual?.status || "manual");
  const [note, setNote] = useState(item.manual?.note || "");
  const [evidenceId, setEvidenceId] = useState(item.manual?.evidence_id || "");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  // The saved record, so the drawer tells the truth the instant the PUT lands.
  const saved = item.manual;
  const [revision, setRevision] = useState(0);
  const path = `/api/engagements/${encodeURIComponent(eid)}/coverage/${encodeURIComponent(fw)}/${encodeURIComponent(item.id)}`;
  const refresh = () => { setRevision((n) => n + 1); onSaved(); };
  const [linkFinding, setLinkFinding] = useState("");
  const [linkAction, setLinkAction] = useState<"add" | "remove">("add");
  const [linkNote, setLinkNote] = useState("");
  const [linkError, setLinkError] = useState<string | null>(null);
  const [linkSaving, setLinkSaving] = useState(false);
  const [linkResult, setLinkResult] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const save = async () => {
    setSaving(true); setError(null);
    try {
      // The server owns the rules: covered needs this engagement's evidence, manual/unsupported a note.
      await put(`/api/engagements/${encodeURIComponent(eid)}/coverage/${encodeURIComponent(fw)}/${encodeURIComponent(item.id)}`,
        { status, note: note.trim(), evidence_id: status === "covered" ? evidenceId.trim() : undefined });
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const saveLink = async () => {
    if (!linkFinding) { setLinkError("Choose the finding this decision is about."); return; }
    setLinkSaving(true); setLinkError(null); setLinkResult(null);
    try {
      const r = await post<{ history: { action: string; finding_id: string }[] }>(
        `/api/engagements/${encodeURIComponent(eid)}/coverage/${encodeURIComponent(fw)}/${encodeURIComponent(item.id)}/links`,
        { finding_id: linkFinding, action: linkAction, note: linkNote.trim() });
      const last = r.history[r.history.length - 1];
      setLinkResult(`Recorded: ${last?.action} ${last?.finding_id} (${r.history.length} decision${r.history.length === 1 ? "" : "s"} on this requirement).`);
      setLinkNote("");
      refresh();
    } catch (e) {
      setLinkError(e instanceof Error ? e.message : String(e));
    } finally {
      setLinkSaving(false);
    }
  };

  const auto = item.automatic;
  const ev = item.evidence;
  const hits = ev.findings.map((id) => findings.find((f) => f.id === id) || { id } as Finding);
  const traffic = `/engagements/${eid}?tab=traffic`;
  const operations = `/engagements/${eid}?tab=operations`;
  const ledger = `/engagements/${eid}?tab=evidence`;
  const executed = [
    { label: "exchanges captured", n: ev.exchanges.length, to: traffic },
    { label: "tool calls", n: ev.tool_calls.length, to: operations },
    { label: "intents", n: ev.intents.length, to: operations },
    { label: "degradation events", n: ev.events.length, to: operations },
  ].filter((r) => r.n > 0);
  const untested = UNTESTED.includes(auto.status) || auto.status === "partial_evidence"
    || auto.status === "finding_unverified";

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-ink-900/30" onMouseDown={onClose}>
      <aside role="dialog" aria-modal="true" aria-label={`Requirement ${item.id}`}
        onMouseDown={(e) => e.stopPropagation()}
        className="flex h-full w-full flex-col overflow-y-auto bg-white shadow-lg sm:max-w-2xl">
        <header className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-line bg-white px-4 py-3">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm text-ink-900">{item.id}</span>
              {item.level ? <Badge tone="neutral">Level {item.level}</Badge> : null}
              <Badge tone={TONE[auto.status]}>{auto.status}</Badge>
              {saved && <Badge tone={REVIEW_TONE[saved.status]}>review: {saved.status}</Badge>}
            </div>
            <p className="mt-1 text-2xs text-ink-500">
              {item.section_title || item.section || "—"}
            </p>
          </div>
          <button onClick={onClose} aria-label="Close requirement" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900">
            <X size={16} />
          </button>
        </header>

        <div className="space-y-5 px-4 py-4">
          <section aria-label="What is required">
            <h3 className="text-2xs uppercase tracking-wide text-ink-500">What is required</h3>
            <p className="mt-1 text-sm leading-relaxed text-ink-900">{item.title}</p>
          </section>

          <section aria-label="Applicability">
            <h3 className="text-2xs uppercase tracking-wide text-ink-500">Applicability</h3>
            <p className="text-xs text-ink-700">{auto.status === "not_applicable" ? auto.reason
              : "In the selected catalog. Confirm that this control applies to the target before drawing a verdict."}</p>
          </section>
          <section aria-label="How Libella tested it" className="rounded border border-line bg-canvas px-3 py-3">
            <h3 className="text-2xs uppercase tracking-wide text-ink-500">How Libella tested it</h3>
            <p className="mt-1 text-sm text-ink-900">{auto.reason}</p>
            <p className="mt-1 text-2xs text-ink-500">{HELP[auto.status]}</p>
            {auto.units.length === 0 ? (
              <p className="mt-2 text-xs text-ink-500">No Libella check is mapped to this requirement.</p>
            ) : (
              <ul className="mt-2 space-y-2">
                {auto.units.map((u) => {
                  const row = mapping[u];
                  const strength = row?.strength?.[item.id] || "direct";
                  return (
                    <li key={u} className="rounded border border-line bg-white px-2.5 py-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-2xs text-ink-700">{u}</span>
                        <Badge tone={strength === "direct" ? "success" : "warning"}>{strength} coverage</Badge>
                      </div>
                      <p className="mt-1 text-xs text-ink-700">{row?.why || "no recorded rationale"}</p>
                    </li>
                  );
                })}
              </ul>
            )}
            {auto.strength && auto.units.length > 0 && (
              <p className="mt-2 text-2xs text-ink-500">
                Closest mapped check covers this requirement <span className="font-medium text-ink-700">{auto.strength}</span>ly.
              </p>
            )}
          </section>

          <section aria-label="What executed">
            <h3 className="text-2xs uppercase tracking-wide text-ink-500">What executed</h3>
            {executed.length === 0 ? (
              <p className="mt-1 text-sm text-ink-500">Nothing in this engagement executed for this requirement.</p>
            ) : (
              <ul className="mt-1 space-y-1 text-sm">
                {executed.map((r) => (
                  <li key={r.label} className="flex items-baseline justify-between gap-3">
                    <span className="text-ink-700">
                      <span className="font-semibold tabular-nums text-ink-900">{r.n}</span> {r.label}
                    </span>
                    <Link className="link inline-flex items-center gap-0.5 text-xs" to={r.to}>
                      open <ArrowUpRight size={11} />
                    </Link>
                  </li>
                ))}
                <li className="flex items-baseline justify-between gap-3">
                  <Link className="link text-xs" to={ledger}>Evidence ledger for this engagement</Link>
                </li>
              </ul>
            )}
            {hits.length > 0 && (
              <ul className="mt-3 space-y-2">
                {hits.map((f) => (
                  <li key={f.id} className="rounded border border-line px-2.5 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      {f.severity && <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>}
                      {f.state && <Badge tone={stateTone(f.state)}>{f.state}</Badge>}
                      <span className="font-mono text-2xs text-ink-500">{f.id}</span>
                    </div>
                    <Link to={`/findings/${f.id}`} className="link mt-1 inline-block text-sm">
                      {f.title || `Finding ${f.id}`}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {untested && (
            <section aria-label="What remains untested" className="rounded border border-[#FEDF89] bg-[#FFFAEB] px-3 py-3">
              <h3 className="text-2xs uppercase tracking-wide text-[#B54708]">What remains untested</h3>
              <p className="mt-1 text-sm text-ink-700">
                {auto.status === "partial_evidence"
                  ? "Only part of this requirement was covered. A partial check is not a pass: the rest is untested."
                  : auto.status === "finding_unverified"
                    ? "A finding exists but was not independently replayed. The requirement is not verified."
                    : auto.status === "requires_manual"
                      ? `No automated check exists, so this must be performed by hand: ${auto.reason}`
                      : auto.reason}
              </p>
            </section>
          )}

          <ReviewActivity path={path} item={item} revision={revision} onSaved={refresh} />

          <section aria-label="Analyst review">
            <h3 className="text-2xs uppercase tracking-wide text-ink-500">Analyst review</h3>
            {saved ? (
              <p className="mt-1 text-xs text-ink-500">
                Recorded {fmtTime(saved.updated_at)}{saved.evidence_id ? ` · evidence ${saved.evidence_id}` : ""}.
                The review overrides the displayed status; the automatic record stays visible above.
              </p>
            ) : (
              <p className="mt-1 text-xs text-ink-500">No review recorded. The status above is entirely what the run did.</p>
            )}
            <div className="mt-2 space-y-3">
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
                <Input aria-label="Evidence ID" value={evidenceId} onChange={(e) => setEvidenceId(e.target.value)}
                  placeholder="ev_…" disabled={status !== "covered"} />
              </Field>
              <ErrorNote error={error} />
              <Button onClick={save} disabled={saving}>{saving ? "Saving…" : "Save review"}</Button>
            </div>
          </section>

          <section aria-label="Attribution correction">
            <h3 className="text-2xs uppercase tracking-wide text-ink-500">Finding attribution</h3>
            <p className="mt-1 text-xs text-ink-500">
              The automatic attribution comes from the evidence a finding cites. Correct it when the
              run got it wrong: every add or remove is kept as history with its reason.
            </p>
            <div className="mt-2 space-y-3">
              <Field label="Finding" hint="Any finding from this engagement, attributed or not.">
                <Select aria-label="Link finding" value={linkFinding} onChange={(e) => setLinkFinding(e.target.value)}>
                  <option value="">Select finding…</option>
                  {findings.map((f) => (
                    <option key={f.id} value={f.id}>{f.id} · {f.cwe || "no CWE"} · {f.title}</option>
                  ))}
                </Select>
              </Field>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Action">
                  <Select aria-label="Link action" value={linkAction}
                    onChange={(e) => setLinkAction(e.target.value as "add" | "remove")}>
                    <option value="add">add — this finding is evidence here</option>
                    <option value="remove">remove — it is not</option>
                  </Select>
                </Field>
              </div>
              <Field label="Why" hint="Required: the record keeps the reason, not just the change.">
                <Textarea aria-label="Link note" rows={2} value={linkNote} onChange={(e) => setLinkNote(e.target.value)} />
              </Field>
              <ErrorNote error={linkError} />
              {linkResult && <p className="text-xs text-ink-700">{linkResult}</p>}
              <Button disabled={linkSaving} onClick={saveLink}>
                {linkSaving ? "Recording…" : "Record attribution"}
              </Button>
            </div>
          </section>

          <details className="rounded border border-line px-3 py-2">
            <summary className="cursor-pointer text-2xs uppercase tracking-wide text-ink-500">Technical detail</summary>
            <dl className="mt-2 space-y-1 break-words font-mono text-2xs text-ink-500">
              <div><dt className="inline text-ink-700">automatic: </dt><dd className="inline">{auto.status} · {auto.strength || "—"}</dd></div>
              <div><dt className="inline text-ink-700">units: </dt><dd className="inline">{auto.units.join(", ") || "—"}</dd></div>
              <div><dt className="inline text-ink-700">tool_calls: </dt><dd className="inline">{ev.tool_calls.join(", ") || "—"}</dd></div>
              <div><dt className="inline text-ink-700">exchanges: </dt><dd className="inline">{ev.exchanges.join(", ") || "—"}</dd></div>
              <div><dt className="inline text-ink-700">intents: </dt><dd className="inline">{ev.intents.join(", ") || "—"}</dd></div>
              <div><dt className="inline text-ink-700">events: </dt><dd className="inline">{ev.events.join(", ") || "—"}</dd></div>
            </dl>
          </details>

        </div>
      </aside>
    </div>
  );
}