import { useEffect, useRef, useState } from "react";
import { get, getToken } from "../api";

export function useApi<T>(path: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(!!path);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!path) return;
    let alive = true;
    setLoading(true);
    get<T>(path)
      .then((d) => { if (alive) { setData(d); setError(null); } })
      .catch((e) => { if (alive) setError(e instanceof Error ? e.message : String(e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [path, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}

export const EVENT_KINDS = [
  "engagement_created", "engagement_started", "intent_created", "intent_running", "intent_done",
  "asset_discovered", "finding_new", "finding_state", "finding_dedup", "verification", "retest",
  "tool_call", "scope_refusal", "degradation", "checks_complete", "report_rendered",
  "engagement_finished", "engagement_paused", "engagement_resumed", "engagement_cancelled",
  "engagement_failed", "compile_reject",
];

/** SSE with cursor + reconnect. Mount only once the caller knows the last seen seq. */
export function useStream(eid: string | null, since: number | null, onEvent: (kind: string, data: any, seq: number) => void) {
  const cb = useRef(onEvent);
  cb.current = onEvent;
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    if (!eid || since === null) return;
    let es: EventSource | null = null;
    let closed = false;
    let retry = 0;
    let cursor = since;
    const connect = () => {
      if (closed) return;
      es = new EventSource(`/api/engagements/${eid}/stream?since=${cursor}&token=${encodeURIComponent(getToken())}`);
      es.onopen = () => { retry = 0; setConnected(true); };
      for (const kind of EVENT_KINDS) {
        es.addEventListener(kind, (ev) => {
          const me = ev as MessageEvent;
          if (me.lastEventId) cursor = Math.max(cursor, Number(me.lastEventId));
          try { cb.current(kind, JSON.parse(me.data), Number(me.lastEventId) || 0); } catch { /* malformed event payload */ }
        });
      }
      es.onerror = () => {
        es?.close();
        setConnected(false);
        if (closed) return;
        retry = Math.min(retry + 1, 8);
        setTimeout(connect, retry * 1000);
      };
    };
    connect();
    return () => { closed = true; es?.close(); setConnected(false); };
  }, [eid, since]);
  return connected;
}
