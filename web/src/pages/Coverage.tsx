import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ClipboardCheck, Download, Search } from "lucide-react";
import { downloadReport, put } from "../api";
import type { Engagement, Finding } from "../types";
import { useApi } from "../lib/hooks";
import { stateTone } from "../lib/format";
import { Badge, Button, Card, EmptyState, ErrorNote, Input, Select, Skeleton, Table } from "../components/ui";
import RequirementDrawer from "./coverage/RequirementDrawer";
import {
  AUTO_STATUSES, REVIEWS, REVIEW_TONE, SUMMARY_KEYS, TONE,
  type AutoStatus, type Item, type Review, type Workspace,
} from "./coverage/model";

type Filter = "all" | AutoStatus | Review;

export default function Coverage() {
  const [params, setParams] = useSearchParams();
  const engagements = useApi<Engagement[]>("/api/engagements");
  const eid = params.get("engagement") || "";
  const fw = params.get("framework") || "asvs";
  const ws = useApi<Workspace>(eid
    ? `/api/engagements/${encodeURIComponent(eid)}/coverage/${encodeURIComponent(fw)}`
    : null);
  const standards = useApi<{ standards: { id: string; framework: { title: string; version: string };
    levels: number[]; requirements: number }[] }>("/api/standards");
  const findings = useApi<Finding[]>(eid ? `/api/engagements/${encodeURIComponent(eid)}/findings` : null);

  const [open, setOpen] = useState<Item | null>(null);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [level, setLevel] = useState("all");
  const [manualOnly, setManualOnly] = useState(false);
  const [withEvidence, setWithEvidence] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const d = ws.data?.engagement_id === eid && ws.data.framework.id.toLowerCase().replace(/^owasp-/, "") === fw
    ? ws.data : null;
  const opened = d?.categories.flatMap((c) => c.tests).find((t) => t.id === open?.id);
  const needle = search.trim().toLowerCase();
  const filtering = needle !== "" || filter !== "all" || level !== "all" || manualOnly || withEvidence;

  const keep = (t: Item) =>
    (filter === "all" || t.automatic.status === filter || t.manual?.status === filter)
    && (level === "all" || String(t.level ?? "") === level)
    && (!manualOnly || t.automatic.status === "requires_manual")
    && (!withEvidence || hasEvidence(t))
    && (!needle || [t.id, t.title, t.section_title || "", t.section || ""]
      .some((s) => s.toLowerCase().includes(needle)));

  const chapters = useMemo(() => (d?.categories || []).map((c) => ({
    ...c, shown: c.tests.filter(keep),
  })), [d, needle, filter, level, manualOnly, withEvidence]);  // eslint-disable-line react-hooks/exhaustive-deps

  const shown = chapters.reduce((n, c) => n + c.shown.length, 0);
  const inScope = chapters.reduce((n, c) => n + c.tests.length, 0);

  const setParam = (key: string, value: string) => {
    setOpen(null);
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    setParams(next, { replace: true });
  };

  const applyLevel = async (value: number) => {
    setError(null); setBusy("level");
    try {
      await put(`/api/engagements/${encodeURIComponent(eid)}/standards`, { [fw]: { level: value } });
      ws.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setBusy(null); }
  };

  const download = (format: "md" | "pdf") => {
    setError(null); setBusy(format);
    downloadReport(eid, format, "coverage")
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setBusy(null));
  };

  const reset = () => {
    setSearch(""); setFilter("all"); setLevel("all"); setManualOnly(false); setWithEvidence(false);
  };

  const list = engagements.data || [];
  const unattributed = d?.unattributed_findings || [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-900">Security standards &amp; coverage</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-500">
          Every requirement of the selected standard, accounted for against what this engagement actually
          executed — intents, tool calls, captured exchanges, degradations and findings. Two records per
          requirement, both always shown: <span className="font-medium text-ink-700">Executed</span> is derived
          from the run, <span className="font-medium text-ink-700">Review</span> is what an operator recorded by
          hand. Captured-response checks use existing evidence and do not send target traffic.
        </p>
      </div>

      <Card title="Standard" description="Coverage is recorded per engagement and never shared across them."
        actions={d ? <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" icon={<Download size={13} />} onClick={() => download("md")} disabled={busy !== null}>
            {busy === "md" ? "Preparing…" : "Coverage report (MD)"}
          </Button>
          <Button size="sm" icon={<Download size={13} />} onClick={() => download("pdf")} disabled={busy !== null}>
            {busy === "pdf" ? "Preparing…" : "PDF"}
          </Button>
        </div> : undefined}>
        <div className="flex flex-wrap items-end gap-3">
          <label className="block w-full max-w-md">
            <span className="label">Engagement</span>
            <Select aria-label="Engagement" value={eid} onChange={(e) => setParam("engagement", e.target.value)}>
              <option value="">Select engagement…</option>
              {list.map((e) => <option key={e.id} value={e.id}>{e.name} · {e.status} · {e.profile}</option>)}
            </Select>
          </label>
          <label className="block w-full max-w-sm">
            <span className="label">Standard</span>
            <Select aria-label="Standard" value={fw} onChange={(e) => setParam("framework", e.target.value)}>
              {(standards.data?.standards || []).map((st) => (
                <option key={st.id} value={st.id}>{st.framework.title} · {st.requirements} requirements</option>
              ))}
            </Select>
          </label>
          {d && d.framework.levels.length > 0 && (
            <label className="block w-full max-w-[11rem]">
              <span className="label">Verification level</span>
              <Select aria-label="Verification level" value={String(d.summary.level ?? d.framework.levels[0])}
                disabled={busy === "level"} onChange={(e) => applyLevel(Number(e.target.value))}>
                {d.framework.levels.map((lv) => <option key={lv} value={lv}>Level {lv}</option>)}
              </Select>
            </label>
          )}
        </div>
        {d && (
          <p className="mt-3 text-xs text-ink-500">
            <span data-testid="framework-title" className="font-medium text-ink-700">
              {d.framework.title} v{d.framework.version}
            </span>
            {" · "}{d.summary.total} of {d.summary.catalog} requirements
            {typeof d.summary.level === "number" ? ` at Level ${d.summary.level}` : ""}
            {d.summary.excluded_by_level > 0 ? ` · ${d.summary.excluded_by_level} excluded by that level` : ""}
            {d.framework.license ? ` · ${d.framework.license}` : ""}{" · "}
            <a className="link" href={d.framework.source} target="_blank" rel="noreferrer">catalog source</a>
          </p>
        )}
        <ErrorNote error={error || ws.error} />
      </Card>

      {!eid ? (
        <Card><EmptyState icon={<ClipboardCheck size={22} />} title="Choose an engagement"
          description="The ledger lists every requirement of the selected standard, grouped by chapter, with the reason each one is or is not accounted for." /></Card>
      ) : ws.loading && !d ? <Skeleton className="h-64 w-full" /> : !d ? null : (
        <>
          <Card title="How to read a status"
            description="A row is never greener than the evidence allows.">
            <ul className="space-y-1.5 text-xs text-ink-700">
              <li><Badge tone="neutral">completed_no_issue</Badge> means a mapped check recorded no issue.
                It is not a requirement pass.</li>
              <li><Badge tone="info">partial_evidence</Badge> means a mapped check ran but covers only part of the
                requirement. <span className="font-medium">It is not a pass</span>, and neither is a
                completed_no_issue from a partial check — the server never records one.</li>
              <li><Badge tone="warning">requires_manual</Badge> and <Badge tone="warning">inconclusive</Badge> are{" "}
                <span className="font-medium">untested</span>: no automated check exists, or the one that ran
                produced no conclusion. Both count in <span className="font-medium">Not tested</span>.</li>
              <li><Badge tone="warning">skipped_policy</Badge> / <Badge tone="warning">skipped_dependency</Badge> are
                untested too — refused by the engagement profile or missing a tool, never failed.</li>
              <li><Badge tone="danger">finding_verified</Badge> and <Badge tone="info">finding_unverified</Badge>{" "}
                are evidence <span className="font-medium">against</span> the requirement, not coverage of it.</li>
            </ul>
          </Card>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {SUMMARY_KEYS.map(([key, label, hint, tone]) => (
              <div key={key} className="rounded border border-line bg-white px-3 py-2" title={hint}>
                <div className="text-2xs text-ink-500">{label}</div>
                <div data-testid={`summary-${key}`}
                  className={`mt-0.5 text-base font-semibold tabular-nums ${tone === "success" ? "text-[#027A48]" : tone === "danger" ? "text-sev-high" : "text-ink-900"}`}>
                  {(d.summary as unknown as Record<string, number>)[key]}
                </div>
                <div className="text-2xs text-ink-300">{hint}</div>
              </div>
            ))}
          </div>

          {unattributed.length > 0 && (
            <Card title={`Findings with no requirement (${unattributed.length})`}
              description="These exist in the engagement but no mapped check accounts for them. Open a requirement and record an attribution decision to attach one.">
              <ul className="space-y-2">
                {unattributed.map((f) => (
                  <li key={f.id} className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge tone={stateTone(f.state)}>{f.state}</Badge>
                    <span className="font-mono text-2xs text-ink-500">{f.id}</span>
                    <span className="font-mono text-2xs text-ink-500">{f.cwe || "no CWE"}</span>
                    <Link to={`/findings/${f.id}`} className="link">{f.title}</Link>
                    <span className="text-ink-500">— {f.reason}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <Card title="Filters" description={`${shown} of ${inScope} requirements shown in scope.`}>
            <div className="flex flex-wrap items-end gap-3">
              <label className="block w-full max-w-sm">
                <span className="label">Search</span>
                <div className="relative">
                  <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-300" />
                  <Input aria-label="Search requirements" className="pl-7" value={search}
                    onChange={(e) => setSearch(e.target.value)} placeholder="V3.4, section or requirement text" />
                </div>
              </label>
              <label className="block w-full max-w-xs">
                <span className="label">Status</span>
                <Select aria-label="Status filter" value={filter} onChange={(e) => setFilter(e.target.value as Filter)}>
                  <option value="all">All statuses ({d.summary.total})</option>
                  {AUTO_STATUSES.map((s) => <option key={s} value={s}>{s} ({d.summary.statuses[s]})</option>)}
                  {REVIEWS.filter((r) => r !== "unknown").map((r) => (
                    <option key={r} value={r}>review: {r} ({d.summary.manual[r]})</option>
                  ))}
                </Select>
              </label>
              {d.framework.levels.length > 0 && (
                <label className="block w-full max-w-[9.5rem]">
                  <span className="label">Requirement level</span>
                  <Select aria-label="Requirement level" value={level} onChange={(e) => setLevel(e.target.value)}>
                    <option value="all">All levels</option>
                    {d.framework.levels.map((lv) => <option key={lv} value={String(lv)}>Level {lv}</option>)}
                  </Select>
                </label>
              )}
              <label className="inline-flex items-center gap-2 pb-2 text-sm text-ink-700">
                <input type="checkbox" aria-label="Manual required only" checked={manualOnly}
                  onChange={(e) => setManualOnly(e.target.checked)} />
                Manual required only
              </label>
              <label className="inline-flex items-center gap-2 pb-2 text-sm text-ink-700">
                <input type="checkbox" aria-label="With evidence only" checked={withEvidence}
                  onChange={(e) => setWithEvidence(e.target.checked)} />
                With evidence only
              </label>
              {filtering && <Button size="sm" variant="ghost" className="mb-1" onClick={reset}>Reset filters</Button>}
            </div>
          </Card>

          {chapters.every((c) => filtering && c.shown.length === 0) && (
            <Card><EmptyState title="No requirement matches"
              description="Clear the search or filters to see the whole catalog." /></Card>
          )}

          {chapters.map((c) => {
            if (filtering && c.shown.length === 0) return null;
            const isOpen = filtering || !!expanded[c.id];
            const counts = AUTO_STATUSES.filter((s) => c.counts[s]);
            return (
              <div key={c.id} data-testid="chapter">
                <Card padded={false}
                  title={<button className="inline-flex items-center gap-2 text-left" aria-expanded={isOpen}
                    onClick={() => setExpanded((x) => ({ ...x, [c.id]: !x[c.id] }))}>
                    <span className="font-mono text-xs text-ink-700">{c.id}</span>
                    <span className="text-sm font-semibold text-ink-900">{c.name}</span>
                    <span aria-hidden className="text-2xs text-ink-500">{isOpen ? "▾" : "▸"}</span>
                  </button>}
                  description={`${c.shown.length} of ${c.tests.length} requirements${isOpen ? "" : " — open the chapter"}`}
                  actions={<span className="flex flex-wrap justify-end gap-1">
                    {counts.map((s) => <Badge key={s} tone={TONE[s]}>{c.counts[s]} {s}</Badge>)}
                  </span>}>
                  {isOpen && c.shown.length === 0 ? (
                    <div className="px-4 py-6 text-center text-xs text-ink-500">No requirement in this chapter has that status.</div>
                  ) : isOpen ? (
                    <Table<Item> rows={c.shown} getKey={(t) => t.id} dense onRowClick={(t) => setOpen(t)}
                      columns={[
                        { key: "id", label: "ID", width: "6.5rem", render: (t) => (
                          <span className="font-mono text-2xs text-ink-700">{t.id}</span>) },
                        ...(d.framework.levels.length > 0 ? [{ key: "level", label: "Level", width: "4rem",
                          className: "hidden sm:table-cell",
                          render: (t: Item) => <span className="text-2xs text-ink-500">L{t.level ?? "—"}</span> }] : []),
                        { key: "title", label: "Requirement", render: (t) => (
                          <div className="space-y-0.5">
                            {t.section_title && <div className="text-2xs text-ink-500">{t.section_title}</div>}
                            <span className="text-xs text-ink-900">{t.title}</span>
                          </div>) },
                        { key: "auto", label: "Executed", sortValue: (t) => t.automatic.status, render: (t) => (
                          <div className="space-y-0.5">
                            <Badge tone={TONE[t.automatic.status]}>{t.automatic.status}</Badge>
                            <div className="hidden max-w-[220px] truncate text-2xs text-ink-500 sm:block" title={t.automatic.reason}>
                              {t.automatic.reason}
                            </div>
                          </div>) },
                        { key: "review", label: "Review", className: "hidden sm:table-cell",
                          sortValue: (t) => t.manual?.status || "", render: (t) => (
                          t.manual?.status
                            ? <Badge tone={REVIEW_TONE[t.manual.status]}>{t.manual.status}</Badge>
                            : <span className="text-2xs text-ink-300">—</span>) },
                        { key: "evidence", label: "Evidence", className: "hidden sm:table-cell", render: (t) => (
                          <span className="font-mono text-2xs text-ink-500">{evidenceSummary(t)}</span>) },
                      ]} />
                  ) : null}
                </Card>
              </div>
            );
          })}
        </>
      )}

      {opened && eid && (
        <RequirementDrawer key={`${eid}/${fw}/${opened.id}`} eid={eid} fw={fw} item={opened}
          mapping={d?.mapping || {}} findings={findings.data || []}
          onClose={() => setOpen(null)} onSaved={() => ws.reload()} />
      )}
    </div>
  );
}

function hasEvidence(t: Item) {
  const e = t.evidence;
  return !!(e.tool_calls.length || e.exchanges.length || e.intents.length || e.events.length || e.findings.length);
}

function evidenceSummary(t: Item) {
  const calls = t.evidence.tool_calls.length + t.evidence.exchanges.length;
  const findings = t.evidence.findings.length;
  return `${findings ? `${findings} finding${findings > 1 ? "s" : ""} · ` : ""}${calls} call${calls === 1 ? "" : "s"}`;
}