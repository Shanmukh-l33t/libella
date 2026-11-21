import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowRight, ChevronRight, Info } from "lucide-react";
import { get } from "../api";
import type { Engagement, Finding } from "../types";
import { useApi } from "../lib/hooks";
import { fmtTime, severityTone } from "../lib/format";
import { explainOf, latestRetest, statusOf, type Group } from "../lib/validation";
import { Badge, Button, EmptyState, ErrorNote, Select, Skeleton, Stat, Tabs, cx } from "../components/ui";
import { EvidenceRefs, FindingCase, StatusBadge } from "../components/validation";

type Filter = "all" | Group;

const LABELS: [string, string][] = [
  ["Suspected", "a check raised it; no captured request is attached yet."],
  ["Validation pending", "seen in a captured request and response, not replayed yet."],
  ["Verified", "an independent replay reproduced the recorded signal. Impact is still a prediction."],
  ["Still present", "a retest after the fix reproduced it again."],
  ["Retested fixed", "it reproduced earlier; the last retest could not."],
  ["Not reproduced", "an operator ruled it out; the reason is in the audit trail."],
  ["Inconclusive / Did not reproduce", "the last replay could not decide, or ran and saw nothing."],
  ["Blocked by policy", "the replay was refused by scope or profile before it ran."],
];

/** Read-only review of what an engagement recorded. Nothing here starts a check or a replay. */
export default function Validation() {
  const [params, setParams] = useSearchParams();
  const engagements = useApi<Engagement[]>("/api/engagements");
  const eid = params.get("engagement") || engagements.data?.[0]?.id || "";
  const list = useApi<Finding[]>(eid ? `/api/engagements/${encodeURIComponent(eid)}/findings` : null);

  const [details, setDetails] = useState<Record<string, Finding>>({});
  const [detailError, setDetailError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [open, setOpen] = useState<Record<string, boolean>>({});

  // Verification decisions live on the detail route only, so each candidate is read once.
  // shortcut: one detail request per finding, upgrade to a batch route if engagements grow past ~50.
  useEffect(() => {
    const rows = list.data || [];
    if (!rows.length) { setDetails({}); setDetailError(null); return; }
    let alive = true;
    Promise.all(rows.map((r) => get<Finding>(`/api/findings/${r.id}`).catch(() => null)))
      .then((ds) => {
        if (!alive) return;
        const next: Record<string, Finding> = {};
        for (const d of ds) if (d) next[d.id] = d;
        setDetails(next);
        const missing = ds.filter((d) => !d).length;
        setDetailError(missing ? `${missing} finding detail${missing > 1 ? "s" : ""} could not be loaded; those cards show list data only.` : null);
      });
    return () => { alive = false; };
  }, [list.data]);

  const rows = useMemo(
    () => (list.data || []).map((f) => (details[f.id] ? { ...f, ...details[f.id] } : f)),
    [list.data, details],
  );
  const buckets = useMemo(() => {
    const b: Record<Filter, number> = { all: rows.length, unverified: 0, verified: 0, closed: 0 };
    for (const f of rows) b[statusOf(f).group] += 1;
    return b;
  }, [rows]);
  const noEvidence = useMemo(() => rows.filter((f) => !(f.evidence_ids || []).length).length, [rows]);
  const visible = useMemo(() => (filter === "all" ? rows : rows.filter((f) => statusOf(f).group === filter)), [rows, filter]);

  const pick = (id: string) => {
    const next = new URLSearchParams(params);
    if (id) next.set("engagement", id); else next.delete("engagement");
    setParams(next, { replace: true });
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold tracking-tight text-ink-900">Validation workspace</h1>
          <p className="mt-1 max-w-2xl text-sm leading-relaxed text-ink-500">
            Read-only review of what this engagement captured. A finding is verified only when an
            independent replay reproduced it — which proves the signal repeats, not what an attacker would gain.
          </p>
        </div>
        <label className="w-full sm:w-[280px]">
          <span className="label">Engagement</span>
          <Select aria-label="Engagement" value={eid} onChange={(e) => pick(e.target.value)}>
            {!eid && <option value="">Select engagement…</option>}
            {(engagements.data || []).map((e) => <option key={e.id} value={e.id}>{e.name} · {e.status}</option>)}
          </Select>
        </label>
      </div>

      <ErrorNote error={engagements.error} />

      {!eid ? (
        <div className="rounded border border-line bg-white">
          <EmptyState
            title="Choose an engagement"
            description="Validation is recorded per engagement: each candidate is judged against what that engagement captured."
          />
        </div>
      ) : (
        <>
          {rows.length > 0 && (
            <div className="grid grid-cols-3 gap-3">
              <Stat label="Not verified" value={buckets.unverified} hint="Detected, not replayed, or no verdict" />
              <Stat label="Verified" value={buckets.verified} hint="A replay reproduced it" />
              <Stat label="Closed" value={buckets.closed} hint="Ruled out or fixed" />
            </div>
          )}

          <Tabs
            value={filter}
            onChange={(v) => setFilter(v as Filter)}
            tabs={[
              { id: "all", label: "All", count: buckets.all },
              { id: "unverified", label: "Not verified", count: buckets.unverified },
              { id: "verified", label: "Verified", count: buckets.verified },
              { id: "closed", label: "Closed", count: buckets.closed },
            ]}
          />

          {noEvidence > 0 && (
            <p className="text-xs text-ink-500">
              {noEvidence === 1
                ? "1 finding has no captured request bound, so it cannot be verified yet."
                : `${noEvidence} findings have no captured request bound, so they cannot be verified yet.`}
            </p>
          )}

          <ErrorNote error={list.error} />
          <ErrorNote error={detailError} />

          {list.loading && !list.data ? (
            <div className="space-y-3">
              {[0, 1, 2].map((i) => <Skeleton key={i} className="h-64 w-full" />)}
            </div>
          ) : list.error ? (
            <div className="rounded border border-line bg-white px-4 py-6 text-center">
              <p className="text-sm text-ink-700">The candidate list did not load.</p>
              <Button size="sm" className="mt-3" onClick={list.reload}>Try again</Button>
            </div>
          ) : !rows.length ? (
            <div className="rounded border border-line bg-white">
              <EmptyState
                title="No findings to validate yet"
                description="Candidates appear here when a check produces a claim. Before that there is nothing to review, and nothing is marked verified."
                action={<Link className="link text-sm" to={`/engagements/${eid}?tab=findings`}>Open the engagement</Link>}
              />
            </div>
          ) : !visible.length ? (
            <div className="rounded border border-line bg-white">
              <EmptyState title="Nothing in this view" description="No finding is in this state right now. Switch back to All." />
            </div>
          ) : (
            <div className="space-y-3">
              {visible.map((f) => (
                <FindingCard
                  key={f.id}
                  f={f}
                  open={!!open[f.id]}
                  onToggle={() => setOpen((m) => ({ ...m, [f.id]: !m[f.id] }))}
                />
              ))}
            </div>
          )}
        </>
      )}

      <details className="rounded border border-line bg-white px-4 py-3">
        <summary className="cursor-pointer text-xs font-medium text-ink-700">What the labels mean</summary>
        <dl className="mt-3 grid gap-x-8 gap-y-1.5 sm:grid-cols-2">
          {LABELS.map(([label, text]) => (
            <div key={label} className="text-xs leading-relaxed">
              <dt className="inline font-medium text-ink-900">{label}</dt>
              <dd className="inline text-ink-500"> — {text}</dd>
            </div>
          ))}
        </dl>
      </details>
    </div>
  );
}

function FindingCard({ f, open, onToggle }: { f: Finding; open: boolean; onToggle: () => void }) {
  const status = statusOf(f);
  const retest = latestRetest(f);
  const detailLoaded = Array.isArray(f.verifications);

  return (
    <article className="rounded border border-line bg-white shadow-card">
      <div className="flex flex-wrap items-start justify-between gap-3 px-4 pt-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
            <StatusBadge finding={f} />
            <span className="text-2xs text-ink-500">
              {f.cwe || "CWE n/a"} · OWASP {f.owasp || "n/a"}
            </span>
          </div>
          <h3 className="mt-2 text-[15px] font-medium leading-snug text-ink-900">
            <Link to={`/findings/${f.id}`} className="transition-colors hover:text-accent">{f.title}</Link>
          </h3>
          <p className="mt-1 break-all font-mono text-2xs text-ink-500">{f.endpoint || "No endpoint recorded"}</p>
        </div>
        <Link to={`/findings/${f.id}`}
          className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap text-xs text-accent transition-colors hover:text-accent-hover">
          Open finding <ArrowRight size={12} aria-hidden />
        </Link>
      </div>

      <div className="space-y-3 px-4 pb-4 pt-3">
        <div className="flex gap-2">
          <Info size={14} className="mt-0.5 shrink-0 text-ink-300" aria-hidden />
          <p className="max-w-[70ch] text-sm leading-relaxed text-ink-700">{explainOf(f)}</p>
        </div>

        <FindingCase finding={f} />

        <div>
          <h4 className="text-2xs font-medium uppercase tracking-wide text-ink-500">Why it was flagged</h4>
          <p className="mt-1 max-w-[70ch] whitespace-pre-wrap text-sm leading-relaxed text-ink-700">
            {f.description || "No description was recorded with this finding."}
          </p>
        </div>
      </div>

      <div className="border-t border-line px-4 py-2.5">
        {(f.evidence_ids || []).length === 0 ? (
          <span className="text-xs text-ink-500">No evidence objects bound, so there is nothing captured to inspect.</span>
        ) : (
          <button type="button" aria-expanded={open} aria-controls={`tech-${f.id}`} onClick={onToggle}
            className="inline-flex items-center gap-1.5 rounded text-xs font-medium text-ink-700 transition-colors hover:text-ink-900">
            <ChevronRight size={13} className={cx("transition-transform", open && "rotate-90")} aria-hidden />
            {open ? "Hide technical evidence" : "Technical evidence"}
            <span className="text-2xs font-normal text-ink-500">
              ({(f.evidence_ids || []).length} object{(f.evidence_ids || []).length === 1 ? "" : "s"})
            </span>
          </button>
        )}
      </div>

      {open && (
        <div id={`tech-${f.id}`} className="space-y-4 border-t border-line bg-canvas px-4 py-4">
          <div>
            <h4 className="text-2xs font-medium uppercase tracking-wide text-ink-500">Evidence objects</h4>
            <div className="mt-1.5">
              {detailLoaded ? <EvidenceRefs finding={f} /> : <Skeleton className="h-12 w-full" />}
            </div>
          </div>

          {retest && (
            <div>
              <h4 className="text-2xs font-medium uppercase tracking-wide text-ink-500">Retest</h4>
              <p className="mt-1 text-xs leading-relaxed text-ink-700">
                <span className="font-medium">{retest.verdict}</span>
                {retest.detail ? ` — ${retest.detail}` : ""}
                {retest.created_at ? ` (${fmtTime(retest.created_at)})` : ""}
              </p>
            </div>
          )}

          <p className="border-t border-line pt-3 font-mono text-2xs text-ink-500">
            {f.id} · {f.confidence} confidence · {status.verified ? "counts as verified" : "not verified"}
          </p>
        </div>
      )}
    </article>
  );
}