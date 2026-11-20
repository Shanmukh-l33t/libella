import { useState } from "react";
import { Link } from "react-router-dom";
import { GitCompare, RotateCcw, X } from "lucide-react";
import { post } from "../../api";
import type { Finding, RemediationBoard } from "../../types";
import { useApi } from "../../lib/hooks";
import { fmtTime, remediationTone, severityTone, title } from "../../lib/format";
import { Badge, Button, Card, EmptyState, ErrorNote, Field, Input, Select, Skeleton, Textarea, cx, useToast } from "../../components/ui";

export default function Remediation({ eid, live }: { eid: string; live: number }) {
  const board = useApi<RemediationBoard>(`/api/engagements/${eid}/remediation-board?live=${live}`);
  const findings = useApi<Finding[]>(`/api/engagements/${eid}/findings?live=${live}`);
  const [selected, setSelected] = useState<string | null>(null);
  const [sev, setSev] = useState("all");

  const missing = board.error?.startsWith("404");
  const columns = (board.data?.columns || []).map((c) => ({
    ...c, findings: c.findings.filter((f) => sev === "all" || f.severity === sev),
  }));
  const all = (board.data?.columns || []).flatMap((c) => c.findings);
  const current = [...all, ...(findings.data || [])].find((f) => f.id === selected) || null;
  const shown = columns.reduce((n, c) => n + c.findings.length, 0);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-ink-900">Remediation board</h2>
          <p className="mt-0.5 text-xs text-ink-500">
            Status comes from the persisted remediation state; a retest decides fixed vs regressed — never a note.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select aria-label="Filter by severity" value={sev} onChange={(e) => setSev(e.target.value)} className="h-7 w-[140px] text-xs">
            <option value="all">All severities</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Link to={`/compare?a=${eid}`} className="inline-flex h-7 items-center gap-1 rounded border border-line bg-white px-2.5 text-xs text-ink-700 transition-colors hover:border-ink-300 hover:text-ink-900">
            <GitCompare size={13} /> Compare
          </Link>
        </div>
      </div>

      {missing ? (
        <div className="rounded border border-dashed border-line bg-canvas px-4 py-3 text-sm text-ink-500">
          <span className="font-medium text-ink-700">Remediation board</span> is unavailable on this backend build — it becomes available after the backend update.
        </div>
      ) : (
        <>
          <ErrorNote error={board.error} />
          {board.loading && !board.data ? <Skeleton className="h-72 w-full" /> : !shown ? (
            <Card><EmptyState title={all.length ? "No findings match this severity" : "No findings to remediate"}
              description={all.length ? "Pick another severity." : "Findings appear here once evidence supports them."} /></Card>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {columns.map((c) => (
                <div key={c.status} className="rounded border border-line bg-white">
                  <header className="flex items-center justify-between border-b border-line px-3 py-2">
                    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-ink-900">
                      <span className={cx("h-1.5 w-1.5 rounded-full", dot(c.status))} /> {c.label || title(c.status)}
                    </span>
                    <span className="text-2xs tabular-nums text-ink-500">{c.findings.length}</span>
                  </header>
                  <div className="min-h-[60px] space-y-1.5 p-2">
                    {!c.findings.length && <p className="px-1 py-3 text-2xs text-ink-300">nothing here</p>}
                    {c.findings.map((f) => (
                      <button key={f.id} onClick={() => setSelected(f.id)}
                        className="block w-full rounded border border-line px-2.5 py-2 text-left transition-colors hover:border-ink-300 hover:bg-canvas">
                        <div className="flex items-center gap-1.5">
                          <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                          <span className="ml-auto text-2xs text-ink-300">{f.state === "validated" ? "validated" : f.state ? title(f.state) : ""}</span>
                        </div>
                        <div className="mt-1 line-clamp-2 text-xs font-medium leading-snug text-ink-900">{f.title}</div>
                        <div className="mt-1 flex items-center justify-between gap-2 text-2xs text-ink-500">
                          <span className="truncate">{f.owner || "unassigned"}</span>
                          <span className={cx("shrink-0", f.due_at && "tabular-nums")}>
                            {f.due_at ? `due ${f.due_at}` : f.fix_commit ? <span className="font-mono">{f.fix_commit.slice(0, 8)}</span> : null}
                          </span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {current && <RemediationPanel key={current.id} finding={current} onClose={() => setSelected(null)}
        onSaved={() => { board.reload(); findings.reload(); }} />}
    </div>
  );
}

function dot(status: string) {
  return {
    open: "bg-ink-300", in_progress: "bg-accent", remediated: "bg-[#039855]",
    fixed: "bg-[#027A48]", regressed: "bg-sev-critical", closed: "bg-ink-300",
  }[status] || "bg-ink-300";
}

function RemediationPanel({ finding, onClose, onSaved }: { finding: Finding; onClose: () => void; onSaved: () => void }) {
  const toast = useToast();
  const [owner, setOwner] = useState(finding.owner || "");
  const [due, setDue] = useState(finding.due_at || "");
  const [rmState, setRmState] = useState(finding.remediation_state || "open");
  const [notes, setNotes] = useState(finding.remediation_notes || "");
  const [commit, setCommit] = useState(finding.fix_commit || "");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const save = async (nextState?: string) => {
    setBusy(nextState || "save");
    setError(null);
    try {
      await post(`/api/findings/${finding.id}/remediation`, {
        owner, notes, fix_commit: commit, due_at: due, remediation_state: nextState || rmState,
      });
      toast(nextState === "resolved" ? "Marked resolved — retest to confirm." : "Remediation saved.", "success");
      onSaved();
      if (nextState) onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const retest = async () => {
    setBusy("retest");
    setError(null);
    try {
      const res = await post<{ verdict?: string; detail?: string }>(`/api/findings/${finding.id}/retest`);
      toast(`Retest: ${res.verdict || "completed"}${res.detail ? ` — ${res.detail}` : ""}`, res.verdict === "fixed" ? "success" : "warning");
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <aside className="rounded border border-line bg-white shadow-card">
      <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge>
            <Badge tone={remediationTone(rmState)}>{title(rmState)}</Badge>
            {finding.owner && <Badge tone="accent">{finding.owner}</Badge>}
          </div>
          <h3 className="mt-1 break-words text-sm font-medium text-ink-900">{finding.title}</h3>
          <div className="mt-0.5 break-all font-mono text-2xs text-ink-500">{finding.endpoint || finding.id}</div>
        </div>
        <button onClick={onClose} aria-label="Close remediation panel" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900"><X size={14} /></button>
      </header>

      <div className="grid gap-4 p-4 lg:grid-cols-2">
        <div className="space-y-3">
          <Field label="Owner" htmlFor="rm-owner" hint="Who is fixing it.">
            <Input id="rm-owner" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="team or person" maxLength={120} />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Remediation status" htmlFor="rm-state" hint="Owner's workflow; verification is separate.">
              <Select id="rm-state" value={rmState} onChange={(e) => setRmState(e.target.value)}>
                {["open", "in_progress", "resolved"].map((s) => <option key={s} value={s}>{title(s)}</option>)}
              </Select>
            </Field>
            <Field label="Due date" htmlFor="rm-due" hint="YYYY-MM-DD">
              <Input id="rm-due" type="date" value={due} onChange={(e) => setDue(e.target.value)} />
            </Field>
          </div>
          <Field label="Fix commit" htmlFor="rm-commit" hint="Commit or change reference; not verified by the engine.">
            <Input id="rm-commit" value={commit} onChange={(e) => setCommit(e.target.value)} placeholder="abc1234" className="font-mono text-xs" maxLength={200} />
          </Field>
          <Field label="Remediation notes" htmlFor="rm-notes">
            <Textarea id="rm-notes" rows={5} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="what changed and why it removes the root cause" maxLength={4000} />
          </Field>
          <ErrorNote error={error} />
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" size="sm" loading={busy === "save"} onClick={() => save()}>Save</Button>
            <Button size="sm" loading={busy === "resolved"} onClick={() => save("resolved")}>Mark resolved</Button>
            <Button size="sm" icon={<RotateCcw size={13} />} loading={busy === "retest"} onClick={retest} title="Re-run the check and record a retest verdict">Trigger retest</Button>
            <Link to={`/findings/${finding.id}`} className="link self-center text-xs">Open finding</Link>
          </div>
        </div>

        <div className="space-y-3 text-xs">
          <dl className="grid grid-cols-2 gap-3">
            <div><dt className="text-ink-500">State</dt><dd className="text-ink-900">{title(finding.state)}</dd></div>
            <div><dt className="text-ink-500">Updated</dt><dd className="text-ink-900">{fmtTime(finding.updated_at)}</dd></div>
            <div><dt className="text-ink-500">Due</dt><dd className="text-ink-900">{finding.due_at || "—"}</dd></div>
            <div><dt className="text-ink-500">Remediated</dt><dd className="text-ink-900">{fmtTime(finding.remediated_at)}</dd></div>
            <div><dt className="text-ink-500">Evidence</dt><dd className="text-ink-900">{finding.evidence_ids?.length || 0} artifacts</dd></div>
          </dl>
          <div>
            <div className="text-ink-500">Lifecycle</div>
            <p className="mt-0.5 leading-relaxed text-ink-700">
              Suspect → observed → validated is evidence-gated. Remediation status (open / in progress / resolved) is the owner's
              workflow and needs no verification; a retest alone moves the finding to fixed (check no longer reproduces) or
              regressed (still reproduces).
            </p>
          </div>
          {finding.remediation && (
            <div>
              <div className="text-ink-500">Suggested remediation</div>
              <p className="mt-0.5 leading-relaxed text-ink-700">{finding.remediation}</p>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}