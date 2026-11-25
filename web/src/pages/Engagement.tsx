import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft, Pause, Play, Square, RefreshCw, Copy } from "lucide-react";
import { get, post } from "../api";
import type { Engagement as Eng, Event } from "../types";
import { useApi, useStream } from "../lib/hooks";
import { elapsed, fmtTime, money, statusTone, title } from "../lib/format";
import { Badge, Button, ErrorNote, Modal, Select, Skeleton, Tabs, cx, useToast } from "../components/ui";
import Overview from "./engagement/Overview";
import { feedView } from "../lib/feed";
import Operations from "./engagement/Operations";
import ApplicationTab from "./engagement/ApplicationTab";
import AssetsTab from "./engagement/Assets";
import GraphTab from "./engagement/Graph";
import FindingsTab from "./engagement/FindingsTab";
import TrafficTab from "./engagement/Traffic";
import EvidenceTab from "./engagement/Evidence";
import RemediationTab from "./engagement/Remediation";
import ReportTab from "./engagement/Report";

const TABS = ["overview", "operations", "application", "assets", "traffic", "evidence", "graph", "findings", "remediation", "report"];
const MODES = ["deterministic", "llm", "agent"];
const STARTABLE = ["draft", "done", "failed", "cancelled", "budget_exhausted"];

export default function Engagement() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = TABS.includes(params.get("tab") || "") ? params.get("tab")! : "overview";
  const eng = useApi<Eng>(`/api/engagements/${id}`);
  const toast = useToast();

  const [events, setEvents] = useState<Event[]>([]);
  const [degradations, setDegradations] = useState<Event[]>([]);
  const [since, setSince] = useState<number | null>(null);
  const [live, setLive] = useState(0);
  const [mode, setMode] = useState(() => {
    const m = params.get("mode") || "";
    return MODES.includes(m) ? m : "deterministic";
  });
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const feed = useRef(new Map<number, Event>());
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // The feed is always read from the persisted event log (cursor = last seq held), never built from
  // stream frames: the stream names events by kind and a client list of kinds is never complete, so
  // a stream-built feed silently dropped kinds that a reload then showed.
  const fill = useCallback((alive: () => boolean = () => true): Promise<void> => {
    const last = Math.max(0, ...feed.current.keys());
    return get<Event[]>(`/api/engagements/${id}/events?since=${last}`).then((rows) => {
      if (!alive()) return;
      for (const r of rows) feed.current.set(r.seq, r);
      const view = feedView(feed.current.values());
      setEvents(view.events);
      setDegradations(view.degradations);
      setSince((v) => v ?? Math.max(0, ...feed.current.keys()));
      if (rows.length >= 500) return fill(alive); // the endpoint pages at 500
      return undefined;
    });
  }, [id]);

  useEffect(() => {
    let alive = true;
    feed.current = new Map();
    setSince(null);
    fill(() => alive).catch(() => setSince((v) => v ?? 0));
    return () => { alive = false; };
  }, [id, fill]);

  const pushEvent = useCallback((kind: string) => {
    fill().catch(() => {});
    // A preview emits this event itself; refetching it grows the evidence store forever.
    if (kind === "report_rendered") return;
    // Lifecycle changes refresh at once: a debounce timer can be throttled to once a
    // minute in a background tab, which left a finished run reading "Running".
    if (kind.startsWith("engagement_")) {
      if (timer.current) { clearTimeout(timer.current); timer.current = null; }
      setLive((v) => v + 1);
      eng.reload();
      return;
    }
    if (timer.current) return;
    timer.current = setTimeout(() => {
      timer.current = null;
      setLive((v) => v + 1);
      eng.reload();
    }, 600);
  }, [eng, fill]);

  // Coming back to the tab must show current state, not whatever the throttled timers last fetched.
  useEffect(() => {
    const onVisible = () => { if (document.visibilityState === "visible") { fill().catch(() => {}); setLive((v) => v + 1); eng.reload(); } };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [eng, fill]);

  const connected = useStream(id, since, pushEvent);
  // A reconnect (offline, sleep) must catch up on what the dropped stream missed.
  useEffect(() => { if (connected) { fill().catch(() => {}); setLive((v) => v + 1); eng.reload(); } }, [connected]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  const act = async (name: "start" | "pause" | "resume" | "cancel") => {
    setBusy(name);
    setActionError(null);
    try {
      const body = name === "start" || name === "resume" ? { mode } : undefined;
      await post(`/api/engagements/${id}/${name}`, body);
      toast(`Engagement ${{ start: "started", pause: "paused", resume: "resumed", cancel: "cancelled" }[name]}.`, "success");
      setConfirmCancel(false);
      setTimeout(() => { eng.reload(); setLive((v) => v + 1); }, 350);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setActionError(msg);
      toast(msg, "danger");
    } finally {
      setBusy(null);
    }
  };

  const setTab = (t: string) => setParams({ tab: t }, { replace: true });

  if (eng.error) return <div className="space-y-4"><BackLink /><ErrorNote error={eng.error} /></div>;
  if (!eng.data) return (
    <div className="space-y-4">
      <Skeleton className="h-7 w-72" />
      <Skeleton className="h-16 w-full" />
      <Skeleton className="h-64 w-full" />
    </div>
  );

  const e = eng.data;
  const canStart = STARTABLE.includes(e.status);

  return (
    <div className="space-y-5">
      <div>
        <BackLink />
        <div className="mt-2 flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-xl font-semibold tracking-tight text-ink-900">{e.name}</h1>
              <Badge tone={statusTone(e.status)} dot>{title(e.status)}</Badge>
              {(e.status === "running" || e.status === "paused") && (
                <span className="hidden items-center gap-1 text-2xs text-ink-500 sm:inline-flex" title="Live event stream">
                  <span className={cx("h-1.5 w-1.5 rounded-full", connected ? "bg-sev-low" : "bg-ink-300", connected && "animate-pulse")} />
                  {connected ? "live" : "offline"}
                </span>
              )}
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-500">
              <button className="inline-flex items-center gap-1 font-mono hover:text-ink-900" title="Copy engagement id"
                onClick={() => { navigator.clipboard.writeText(e.id).then(() => toast("Engagement id copied.")).catch(() => {}); }}>
                {e.id} <Copy size={11} />
              </button>
              <span>·</span><span>profile <span className="text-ink-700">{title(e.profile)}</span></span>
              <span>·</span><span>created {fmtTime(e.created_at)}</span>
              <span>·</span><span>duration <span className="text-ink-700">{e.started_at ? elapsed(e.started_at, e.finished_at) : "—"}</span></span>
              <span>·</span><span>spend <span className="text-ink-700 tabular-nums">{money(e.spend?.cost_usd)}</span></span>
            </div>
            {e.scope?.targets?.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {e.scope.targets.slice(0, 4).map((t, i) => (
                  <span key={i} className="rounded border border-line bg-canvas px-1.5 py-0.5 font-mono text-2xs text-ink-700">{t.kind} · {t.value}</span>
                ))}
                {e.scope.targets.length > 4 && <span className="px-1 text-2xs text-ink-500">+{e.scope.targets.length - 4} more</span>}
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="ghost" icon={<RefreshCw size={13} />} aria-label="Refresh engagement" onClick={() => { eng.reload(); setLive((v) => v + 1); }} />
            {(canStart || e.status === "paused") && (
              <Select aria-label="Execution mode" value={mode} onChange={(ev) => setMode(ev.target.value)} className="h-8 w-[150px] text-xs"
                title="Deterministic runs the fixed check pipeline. LLM planner adds model-proposed intents. Agent runs specialist reasoning loops (requires a configured LLM).">
                <option value="deterministic">Deterministic</option>
                <option value="llm">LLM planner</option>
                <option value="agent">Agent</option>
              </Select>
            )}
            {canStart && <Button size="sm" variant="primary" icon={<Play size={13} />} loading={busy === "start"} onClick={() => act("start")}>{e.status === "draft" ? "Start" : "Run again"}</Button>}
            {e.status === "running" && <Button size="sm" icon={<Pause size={13} />} loading={busy === "pause"} onClick={() => act("pause")}>Pause</Button>}
            {e.status === "paused" && <Button size="sm" variant="primary" icon={<Play size={13} />} loading={busy === "resume"} onClick={() => act("resume")}>Resume</Button>}
            {(e.status === "running" || e.status === "paused") && (
              <Button size="sm" variant="danger" icon={<Square size={12} />} loading={busy === "cancel"} onClick={() => setConfirmCancel(true)}>Cancel</Button>
            )}
          </div>
        </div>
        <div className="mt-3"><ErrorNote error={actionError} /></div>
      </div>

      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "overview", label: "Overview" },
        { id: "operations", label: "Operations" },
        { id: "application", label: "Application" },
        { id: "assets", label: "Assets" },
        { id: "traffic", label: "Traffic" },
        { id: "evidence", label: "Evidence" },
        { id: "graph", label: "Graph" },
        { id: "findings", label: "Findings" },
        { id: "remediation", label: "Remediation" },
        { id: "report", label: "Report" },
      ]} />

      {tab === "overview" && <Overview eid={id} eng={e} live={live} events={events} degradations={degradations} />}
      {tab === "operations" && <Operations eid={id} live={live} />}
      {tab === "application" && <ApplicationTab eid={id} live={live} />}
      {tab === "assets" && <AssetsTab eid={id} live={live} />}
      {tab === "traffic" && <TrafficTab eid={id} live={live} />}
      {tab === "evidence" && <EvidenceTab eid={id} live={live} />}
      {tab === "graph" && <GraphTab eid={id} live={live} />}
      {tab === "findings" && <FindingsTab eid={id} live={live} />}
      {tab === "remediation" && <RemediationTab eid={id} live={live} />}
      {tab === "report" && <ReportTab eid={id} eng={e} live={live} />}

      <Modal open={confirmCancel} onClose={() => setConfirmCancel(false)} title="Cancel this engagement?"
        footer={<>
          <Button variant="ghost" onClick={() => setConfirmCancel(false)}>Keep running</Button>
          <Button variant="danger" loading={busy === "cancel"} onClick={() => act("cancel")}>Cancel engagement</Button>
        </>}>
        Open and running intents are stopped. Captured evidence and findings are kept, and the engagement can be started again later.
      </Modal>
    </div>
  );
}

function BackLink() {
  return <Link to="/" className="inline-flex items-center gap-1 text-xs text-ink-500 hover:text-ink-900"><ArrowLeft size={13} /> All engagements</Link>;
}