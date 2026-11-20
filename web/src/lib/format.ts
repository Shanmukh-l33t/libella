import type { Tone } from "../types";

export function fmtTime(ts?: number | null) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
export function fmtDate(ts?: number | null) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}
export function fmtDuration(ms?: number | null) {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60_000);
  return `${m}m ${Math.round((ms % 60_000) / 1000)}s`;
}
export function elapsed(from?: number | null, to?: number | null) {
  if (!from) return "—";
  const end = to && to > from ? to : Date.now() / 1000;
  return fmtDuration(Math.max(0, end - from) * 1000);
}
export function money(n?: number | null) {
  return `$${(n || 0).toFixed(n ? 2 : 2)}`;
}

const SEV: Record<string, Tone> = { critical: "critical", high: "danger", medium: "warning", low: "success", info: "info" };
export const severityTone = (s: string): Tone => SEV[s] || "neutral";

const STATE: Record<string, Tone> = {
  validated: "success", retested_fixed: "success", reported: "accent",
  observed: "accent", suspected: "neutral", remediated: "neutral",
  retested_persists: "critical", ruled_out: "info",
};
export const stateTone = (s: string): Tone => STATE[s] || "neutral";

const STATUS: Record<string, Tone> = {
  running: "accent", done: "success", paused: "warning", cancelled: "info",
  failed: "critical", budget_exhausted: "warning", draft: "neutral",
};
export const statusTone = (s: string): Tone => STATUS[s] || "neutral";

const INTENT: Record<string, Tone> = { running: "accent", done: "success", blocked: "critical", open: "neutral", exhausted: "warning", stopped: "info" };
export const intentTone = (s: string): Tone => INTENT[s] || "neutral";

export const title = (s: string) => s.replace(/_/g, " ");

export const SEV_COLOR: Record<string, string> = {
  critical: "#B42318", high: "#D92D20", medium: "#DC6803", low: "#039855", info: "#667085",
};
export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
