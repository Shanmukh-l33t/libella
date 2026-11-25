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
  // sub-cent spend must not read as $0.00
  return `$${(n || 0).toFixed(n && n < 0.01 ? 4 : 2)}`;
}

/** A refusal for scope reasons. A missing binary or a bad argv never reached the scope check's verdict. */
export const isScopeRefusal = (d?: string | null) =>
  !!d && d.startsWith("refused") && !/^refused: (missing binary|argv build error|bad argv)/.test(d);

/** Badge for a tool call's recorded decision. */
export function callVerdict(d?: string | null): { tone: Tone; label: string } {
  if (isScopeRefusal(d)) return { tone: "critical", label: "refused" };
  if (d?.startsWith("refused")) return { tone: "warning", label: "not run" };
  return { tone: "success", label: "allowed" };
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

const RUN: Record<string, Tone> = {
  running: "accent", completed: "success", failed: "critical", cancelled: "info",
  budget_exhausted: "warning", queued: "neutral", stopped: "info",
};
export const runTone = (s: string): Tone => RUN[s] || "neutral";

const HYP: Record<string, Tone> = { open: "neutral", supported: "success", refuted: "danger", inconclusive: "warning" };
export const hypothesisTone = (s: string): Tone => HYP[s] || "neutral";

const REM: Record<string, Tone> = {
  open: "neutral", in_progress: "accent", remediated: "success", fixed: "success",
  regressed: "critical", closed: "info",
};
export const remediationTone = (s: string): Tone => REM[s] || "neutral";

const AUTH: Record<string, Tone> = { active: "success", expired: "warning", failed: "critical" };
export const authTone = (s: string): Tone => AUTH[s] || "neutral";

export const ACTION_KIND: Record<string, string> = {
  reason: "Reasoning", tool_call: "Tool call", observation: "Observation",
  hypothesis: "Hypothesis", conclusion: "Conclusion", delegation: "Delegation",
};

export const title = (s: string) => s.replace(/_/g, " ");

export const SEV_COLOR: Record<string, string> = {
  critical: "#B42318", high: "#D92D20", medium: "#DC6803", low: "#039855", info: "#667085",
};
export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
