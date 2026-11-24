import { useMemo } from "react";
import {
  Activity, AlertTriangle, Ban, Boxes, CheckCircle2, CircleAlert, FileText, Flag,
  GitBranch, Globe, ListChecks, Pause, Play, Terminal, XCircle, ChevronRight,
} from "lucide-react";
import type { Asset, Engagement, Event, Finding, Intent, ToolCall } from "../../types";
import { useApi } from "../../lib/hooks";
import { SEV_COLOR, SEV_ORDER, fmtTime, isScopeRefusal, title } from "../../lib/format";
import { Badge, Card, EmptyState, ErrorNote, Skeleton, Stat, cx } from "../../components/ui";
import TargetCredentials from "../../components/TargetCredentials";

const DEGRADATION_TITLE: Record<string, string> = {
  target_mitigated: "The target answered with a bot/WAF challenge",
  scan_partial: "The scanner stopped before finishing",
  policy_restriction: "Not permitted by this assessment profile",
  intent_blocked: "A step could not be completed",
  post_run_error: "Post-run work reported an error",
  verify_failed: "Verification could not run",
  tls_unreachable: "TLS endpoint unreachable",
};

const STATE_ORDER = ["suspected", "observed", "validated", "reported", "remediated", "retested_fixed", "retested_persists", "ruled_out"];

const EVENT_META: Record<string, { icon: typeof Activity; label: string }> = {
  engagement_created: { icon: Flag, label: "Engagement created" },
  engagement_started: { icon: Play, label: "Engagement started" },
  intent_created: { icon: ListChecks, label: "Intent created" },
  intent_running: { icon: Play, label: "Intent running" },
  intent_done: { icon: CheckCircle2, label: "Intent done" },
  asset_discovered: { icon: Globe, label: "Asset discovered" },
  finding_new: { icon: CircleAlert, label: "Finding raised" },
  finding_state: { icon: GitBranch, label: "Finding state changed" },
  finding_dedup: { icon: Boxes, label: "Finding deduplicated" },
  verification: { icon: CheckCircle2, label: "Verification" },
  retest: { icon: GitBranch, label: "Retest" },
  tool_call: { icon: Terminal, label: "Tool call" },
  scope_refusal: { icon: Ban, label: "Scope refusal" },
  degradation: { icon: AlertTriangle, label: "Degradation" },
  checks_complete: { icon: CheckCircle2, label: "Checks complete" },
  report_rendered: { icon: FileText, label: "Report rendered" },
  engagement_finished: { icon: Flag, label: "Engagement finished" },
  engagement_paused: { icon: Pause, label: "Engagement paused" },
  engagement_resumed: { icon: Play, label: "Engagement resumed" },
  engagement_cancelled: { icon: XCircle, label: "Engagement cancelled" },
  engagement_failed: { icon: XCircle, label: "Engagement failed" },
  compile_reject: { icon: AlertTriangle, label: "Instruction rejected" },
};

function detail(kind: string, p: Record<string, any>) {
  if (kind === "asset_discovered") return `${p.kind}: ${p.key}`;
  if (kind === "finding_new") return p.title;
  if (kind === "finding_state") return `${p.state}${p.reason ? ` — ${p.reason}` : ""}`;
  if (kind === "intent_created" || kind === "intent_running") return p.objective ? `${p.role}: ${p.objective}` : p.role;
  if (kind === "degradation") return `${p.code}: ${p.detail}`;
  if (kind === "compile_reject") return p.reason;
  if (kind === "engagement_finished") return `${p.status}${p.detail ? ` — ${p.detail}` : ""}`;
  if (kind === "scope_refusal") return `${p.tool || p.target || ""} ${p.reason || ""}`.trim();
  if (kind === "tool_call") return `${p.tool}${p.target ? ` → ${p.target}` : ""}`;
  if (kind === "verification") return `${p.verdict || ""} ${p.detail || ""}`.trim();
  if (kind === "engagement_started") return `mode: ${p.mode}`;
  if (kind === "finding_dedup") return p.dedup_key;
  return p.name || p.status || "";
}

export default function Overview({ eid, eng, live, events }: { eid: string; eng: Engagement; live: number; events: Event[] }) {
  const assets = useApi<Asset[]>(`/api/engagements/${eid}/assets?live=${live}`);
  const findings = useApi<Finding[]>(`/api/engagements/${eid}/findings?live=${live}`);
  const intents = useApi<Intent[]>(`/api/engagements/${eid}/intents?live=${live}`);
  const calls = useApi<ToolCall[]>(`/api/engagements/${eid}/tool-calls?live=${live}`);

  const bySeverity = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings.data || []) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }, [findings.data]);
  const byState = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings.data || []) c[f.state] = (c[f.state] || 0) + 1;
    return c;
  }, [findings.data]);
  const confirmed = (findings.data || []).filter((f) => ["validated", "reported", "retested_persists"].includes(f.state)).length;
  const refusals = (calls.data || []).filter((t) => isScopeRefusal(t.scope_decision)).length;
  const degradations = useMemo(
    () => events.filter((ev) => ev.kind === "degradation" || ev.kind === "engagement_failed").slice(0, 5),
    [events],
  );
  // Real progress, straight from the scanner's own stats line (nuclei -stats JSON).
  const scan = useMemo(() => {
    const ev = events.find((e) => e.kind === "scan_progress");
    return (ev?.payload || null) as { tool?: string; percent?: number; requests?: number;
      matched?: number; rps?: number; templates?: number; url?: string } | null;
  }, [events]);
  const loading = assets.loading || findings.loading || intents.loading || calls.loading;
  const errors = [assets.error, findings.error, intents.error, calls.error].filter(Boolean) as string[];

  return (
    <div className="space-y-4">
      {eng.status !== "done" && eng.status !== "draft" && (
        <div className={cx("rounded border px-4 py-2.5 text-xs",
          ["failed", "budget_exhausted", "cancelled", "window_closed"].includes(eng.status)
            ? "border-[#FEDF89] bg-[#FFFAEB] text-[#B54708]"
            : "border-line bg-canvas text-ink-500")}>
          Status is <span className="font-medium">{title(eng.status)}</span>
          {eng.status_detail && !["running", "paused"].includes(eng.status) ? ` — ${eng.status_detail}` : ""}. Results below are partial; the report records coverage limits.
          {eng.status === "window_closed" && " Create a new engagement with an authorized window to continue."}
        </div>
      )}
      {scan && (
        <div className="rounded border border-line bg-canvas px-4 py-3">
          <div className="flex flex-wrap items-baseline justify-between gap-2 text-xs">
            <span className="font-medium text-ink-900">
              {eng.status === "running" ? "Scanning" : "Last scan"} ·{" "}
              {scan.tool === "nuclei" ? "template scan" : title(scan.tool || "scan")}: {scan.percent}% of {scan.templates} templates
              {eng.status !== "running" && scan.percent !== undefined && scan.percent < 100 ? " (stopped early)" : ""}
            </span>
            <span className="tabular-nums text-ink-500">
              {scan.requests} requests · {scan.matched} matched · {scan.rps} req/s{scan.url ? ` · ${scan.url}` : ""}
            </span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink-100" title="Reported by the scanner itself">
            <div className="h-full rounded-full bg-ink-900 transition-all duration-500" style={{ width: `${Math.min(100, scan.percent || 0)}%` }} />
          </div>
        </div>
      )}
      {degradations.map((d) => (
        <div key={d.seq} className="flex gap-2 rounded border border-[#FEDF89] bg-[#FFFAEB] px-4 py-3 text-sm">
          <AlertTriangle size={15} className="mt-0.5 shrink-0 text-[#B54708]" />
          <div>
            <div className="font-medium text-ink-900">{DEGRADATION_TITLE[d.payload?.code] || title(d.payload?.code || d.kind)}
              {d.payload?.code && <span className="ml-1.5 font-mono text-2xs text-ink-500">{d.payload.code}</span>}
            </div>
            <div className="text-ink-700">{d.payload?.detail || d.payload?.error || "Coverage reduced."}</div>
          </div>
        </div>
      ))}
      {errors.map((e) => <ErrorNote key={e} error={e} />)}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Assets" value={loading && !assets.data ? <Skeleton className="h-6 w-10" /> : assets.data?.length ?? 0} hint="inside scope" />
        <Stat label="Findings" value={loading && !findings.data ? <Skeleton className="h-6 w-10" /> : findings.data?.length ?? 0}
          hint={confirmed ? `${confirmed} independently validated` : "none validated yet"} />
        <Stat label="Intents" value={loading && !intents.data ? <Skeleton className="h-6 w-10" /> : `${(intents.data || []).filter((i) => i.status === "done").length}/${intents.data?.length ?? 0}`} hint="done / total" />
        <Stat label="Tool calls" value={loading && !calls.data ? <Skeleton className="h-6 w-10" /> : calls.data?.length ?? 0} hint="scope-checked" />
        <Stat label="Scope refusals" value={loading && !calls.data ? <Skeleton className="h-6 w-10" /> : refusals} hint="blocked before egress" />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_400px]">
        <div className="space-y-4">
          <Card title="Findings by severity" description="Severity is assigned by the check that raised the finding, not by a model.">
            {Object.keys(bySeverity).length === 0 ? (
              <p className="text-sm text-ink-500">{loading ? "Loading…" : "No findings recorded yet."}</p>
            ) : (
              <div className="space-y-2">
                {SEV_ORDER.map((s) => {
                  const n = bySeverity[s] || 0;
                  const total = Object.values(bySeverity).reduce((a, b) => a + b, 0);
                  return (
                    <div key={s} className="flex items-center gap-3 text-sm">
                      <span className="flex w-20 items-center gap-1.5 capitalize text-ink-700">
                        <span className="h-2 w-2 rounded-sm" style={{ background: SEV_COLOR[s] }} />{s}
                      </span>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-ink-100">
                        <div className="h-full rounded-full transition-all duration-300" style={{ width: `${total ? (n / total) * 100 : 0}%`, background: SEV_COLOR[s] }} />
                      </div>
                      <span className="w-6 text-right tabular-nums text-ink-700">{n}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>

          <Card title="Findings by state" description="A finding is only validated after an independent replay reproduces it.">
            {Object.keys(byState).length === 0 ? (
              <p className="text-sm text-ink-500">{loading ? "Loading…" : "No findings recorded yet."}</p>
            ) : (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {STATE_ORDER.filter((s) => byState[s]).map((s) => (
                  <div key={s} className="rounded border border-line px-3 py-2">
                    <div className="text-lg font-semibold tabular-nums">{byState[s]}</div>
                    <div className="text-xs capitalize text-ink-500">{title(s)}</div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Scope" description="Authorization boundary for this engagement.">
            <dl className="grid gap-3 sm:grid-cols-2">
              <div>
                <dt className="text-xs text-ink-500">Targets</dt>
                <dd className="mt-1 flex flex-wrap gap-1">
                  {(eng.scope?.targets || []).map((t, i) => (
                    <span key={i} className="rounded border border-line bg-canvas px-1.5 py-0.5 font-mono text-2xs">{t.kind} · {t.value}</span>
                  ))}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-ink-500">Exclusions</dt>
                <dd className="mt-1 flex flex-wrap gap-1">
                  {(eng.scope?.exclusions || []).length
                    ? eng.scope.exclusions.map((t, i) => <span key={i} className="rounded border border-line bg-canvas px-1.5 py-0.5 font-mono text-2xs text-ink-500">{t.kind} · {t.value}</span>)
                    : <span className="text-sm text-ink-500">none</span>}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-ink-500">Categories</dt>
                <dd className="mt-1 text-sm">{(eng.scope?.categories || []).join(", ") || "—"}</dd>
              </div>
              <div>
                <dt className="text-xs text-ink-500">Limits</dt>
                <dd className="mt-1 text-sm tabular-nums">
                  {eng.scope?.rate_limit_rps ?? "—"} req/s · {eng.scope?.max_concurrency ?? "—"} concurrent
                  {eng.budgets?.max_duration_s ? ` · ${eng.budgets.max_duration_s}s cap` : ""}
                  {eng.budgets?.max_usd !== undefined ? ` · $${eng.budgets.max_usd} cap` : ""}
                </dd>
              </div>
            </dl>
            {(eng.auth?.identities || []).length > 0 && (
              <div className="mt-3 border-t border-line pt-2 text-xs text-ink-500">
                Test identities: {(eng.auth.identities || []).map((i) => i.username).filter(Boolean).join(", ")} (passwords never returned)
              </div>
            )}
          </Card>

          <TargetCredentials eid={eid} eng={eng} />
        </div>

        <Card title="Activity" description="Live event stream, newest first." padded={false}
          actions={<span className="text-2xs tabular-nums text-ink-500">{events.length} events</span>}>
          <ActivityFeed events={events} />
        </Card>
      </div>
    </div>
  );
}

function ActivityFeed({ events }: { events: Event[] }) {
  if (!events.length) {
    return <EmptyState icon={<Activity size={22} />} title="No activity yet"
      description="Start the engagement to see intents, assets, tool calls and findings arrive here in real time." />;
  }
  return (
    <ol className="max-h-[560px] divide-y divide-line/70 overflow-y-auto">
      {events.map((ev) => {
        const meta = EVENT_META[ev.kind] || { icon: ChevronRight, label: title(ev.kind) };
        const Icon = meta.icon;
        const isAlert = ev.kind === "degradation" || ev.kind === "engagement_failed" || ev.kind === "scope_refusal";
        return (
          <li key={ev.seq} className="flex gap-2.5 px-4 py-2.5">
            <Icon size={14} className={cx("mt-0.5 shrink-0", isAlert ? "text-[#B54708]" : ev.kind === "finding_new" ? "text-ink-500" : "text-ink-300")} />
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-xs font-medium text-ink-900">{meta.label}</span>
                <span className="shrink-0 text-2xs tabular-nums text-ink-300" title={`seq ${ev.seq}`}>{fmtTime(ev.created_at)}</span>
              </div>
              {detail(ev.kind, ev.payload || {}) && (
                <p className="mt-0.5 break-words font-mono text-2xs leading-relaxed text-ink-500">{String(detail(ev.kind, ev.payload || {})).slice(0, 220)}</p>
              )}
              {ev.kind === "finding_new" && ev.payload?.severity && (
                <Badge tone={ev.payload.severity === "critical" ? "critical" : ev.payload.severity === "high" ? "danger" : ev.payload.severity === "medium" ? "warning" : ev.payload.severity === "low" ? "success" : "info"}>
                  {ev.payload.severity}
                </Badge>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}