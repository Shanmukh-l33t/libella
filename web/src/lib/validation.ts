import type { Finding, Retest, Tone, Verification } from "../types";
import { title } from "./format";

/** Grouping used by the workspace filters. */
export type Group = "unverified" | "verified" | "closed";

export interface Status {
  key: string;
  label: string;
  tone: Tone;
  group: Group;
  /** True only when the pipeline reached a reproduced state. It says nothing about impact. */
  verified: boolean;
  hint: string;
}

const BY_STATE: Record<string, Status> = {
  suspected: {
    key: "suspected", label: "Suspected", tone: "neutral", group: "unverified", verified: false,
    hint: "A check raised this. Nothing has confirmed it.",
  },
  observed: {
    key: "observed", label: "Validation pending", tone: "accent", group: "unverified", verified: false,
    hint: "Seen in a captured request and response. No replay has confirmed it.",
  },
  validated: {
    key: "validated", label: "Verified", tone: "success", group: "verified", verified: true,
    hint: "An independent replay reproduced the recorded signal.",
  },
  reported: {
    key: "reported", label: "Verified", tone: "success", group: "verified", verified: true,
    hint: "Reproduced by replay and handed to the remediation workflow.",
  },
  remediated: {
    key: "remediated", label: "Remediation claimed", tone: "warning", group: "unverified", verified: false,
    hint: "A fix is claimed, but no retest has confirmed it.",
  },
  retested_fixed: {
    key: "retested_fixed", label: "Retested fixed", tone: "success", group: "closed", verified: false,
    hint: "It reproduced before the fix; the last retest could not reproduce it.",
  },
  retested_persists: {
    key: "retested_persists", label: "Still present", tone: "critical", group: "verified", verified: true,
    hint: "The fix did not hold: the retest reproduced the signal again.",
  },
  ruled_out: {
    key: "ruled_out", label: "Not reproduced", tone: "info", group: "closed", verified: false,
    hint: "An operator ruled it out. The reason is in the audit trail.",
  },
};

/** What the detection itself rests on, without repeating the verification outcome. */
export const stateHint = (f: Finding): string =>
  BY_STATE[f.state]?.hint ?? "State recorded by the pipeline.";

export const GROUP_LABEL: Record<Group, string> = {
  unverified: "Not verified",
  verified: "Verified",
  closed: "Closed",
};

export const latestVerification = (f: Finding): Verification | null =>
  (f.verifications || []).reduce<Verification | null>(
    (best, v) => (!best || (v.attempt || 0) >= (best.attempt || 0) ? v : best), null);

export const latestRetest = (f: Finding): Retest | null =>
  (f.retests || []).reduce<Retest | null>(
    (best, r) => (!best || (r.created_at || 0) >= (best.created_at || 0) ? r : best), null);

const isPolicyRefusal = (detail: string) => /^refused:|policy|out of scope|not permitted/i.test(detail);

/**
 * State label, refined by the last recorded verdict. A recorded replay that came back
 * inconclusive, refused or negative is more honest than the bare state.
 */
export function statusOf(f: Finding): Status {
  const base = BY_STATE[f.state] || {
    key: f.state, label: title(f.state), tone: "neutral" as Tone, group: "unverified" as Group,
    verified: false, hint: "State recorded by the pipeline.",
  };
  if (base.verified || f.state === "ruled_out" || f.state === "retested_fixed" || f.state === "remediated") return base;

  const v = latestVerification(f);
  if (!v) return base;
  const detail = (v.detail || "").trim();
  if (v.verdict === "error") {
    return { key: "failed", label: "Verification failed", tone: "danger", group: "unverified", verified: false,
      hint: "The verification run did not complete. Its reason is in the decision below." };
  }
  if (isPolicyRefusal(detail)) {
    return { key: "blocked", label: "Blocked by policy", tone: "warning", group: "unverified", verified: false,
      hint: "The replay was refused by scope or profile before it ran." };
  }
  if (v.verdict === "inconclusive") {
    return { key: "inconclusive", label: "Inconclusive", tone: "warning", group: "unverified", verified: false,
      hint: "The last replay could not decide either way, so the finding stays unverified." };
  }
  if (v.verdict === "not_reproduced") {
    return { key: "not_reproduced", label: "Did not reproduce", tone: "danger", group: "unverified", verified: false,
      hint: "The replay ran and the recorded signal did not come back." };
  }
  return base;
}

export interface Impact {
  label: string;
  note: string;
}

export const EXPLOITABILITY = "Not assessed";

/**
 * Impact is never read off a state. A reproduced replay proves the signal repeats; a
 * retest proves it stopped (or did not). Neither shows what an attacker would gain,
 * and no field records a demonstrated consequence, so impact stays unproven.
 */
export function impactOf(f: Finding): Impact {
  const reproduced = (f.verifications || []).some((v) => v.verdict === "reproduced");
  if (reproduced || f.state === "retested_fixed") {
    return {
      label: "Predicted, not demonstrated",
      note: "Reproduced means the signal repeats. What an attacker would gain is still unproven.",
    };
  }
  return {
    label: "Not demonstrated",
    note: (f.evidence_ids || []).length
      ? "Detection only: nothing here shows what an attacker could do with it."
      : "No evidence is bound, so nothing has been replayed.",
  };
}

export interface Decision {
  verdict: string;
  label: string;
  tone: Tone;
  method?: string;
  detail?: string;
  when?: number;
  attempts: number;
}

const VERDICT: Record<string, { label: string; tone: Tone }> = {
  reproduced: { label: "Reproduced", tone: "success" },
  not_reproduced: { label: "Not reproduced", tone: "danger" },
  inconclusive: { label: "Inconclusive", tone: "warning" },
  error: { label: "Failed", tone: "danger" },
  fixed: { label: "Fixed", tone: "success" },
  persists: { label: "Still present", tone: "critical" },
};

export function decisionOf(f: Finding): Decision | null {
  const vs = f.verifications || [];
  if (!vs.length) return null;
  const v = latestVerification(f)!;
  const meta = VERDICT[v.verdict] || { label: title(v.verdict || "unknown"), tone: "neutral" as Tone };
  return {
    verdict: v.verdict, label: meta.label, tone: meta.tone,
    method: v.method, detail: v.detail, when: v.created_at, attempts: vs.length,
  };
}

/** Known limits of this finding's case, read from what is recorded — nothing invented. */
export function limitationsOf(f: Finding): string[] {
  const out: string[] = [];
  const evidence = (f.evidence_ids || []).length;
  if (!evidence) out.push("No captured request is bound, so verification cannot run.");
  if (!(f.verifications || []).length) out.push("Never independently verified: nothing has reproduced this yet.");
  const r = latestRetest(f);
  if (r && r.verdict === "inconclusive") out.push(`Last retest was inconclusive: ${r.detail || "no reason recorded"}`);
  if (f.state === "remediated") out.push("Remediation is claimed, but no retest has confirmed the signal is gone.");
  if (statusOf(f).verified) out.push("The replay re-sent the recorded proof request only; no other input or endpoint was explored.");
  if (evidence && evidence < 2) out.push("There is no second observation to compare this one against.");
  if (!out.length) out.push("No further limitations are recorded for this finding.");
  return out;
}

/** The beginner-facing sentence: what the record shows, in plain English. */
export function explainOf(f: Finding): string {
  const s = statusOf(f);
  const where = f.endpoint || "this asset";
  const head: Record<string, string> = {
    suspected: `A check raised this on ${where} but attached no captured request, so nothing here confirms it.`,
    observed: `A check saw this in a real request and response on ${where}. No independent replay has confirmed it, so treat it as unreviewed.`,
    validated: "An independent replay sent the recorded request again and got the same signal back, so this reproduces. The impact line above is what the check predicted, not measured damage.",
    reported: "An independent replay reproduced this and it went to the remediation workflow, so the signal is reproducible. Its impact is still the check's prediction.",
    remediated: "A fix is claimed for this finding, but no retest has run, so there is no evidence the signal is gone.",
    retested_fixed: "This reproduced earlier and the last retest could not reproduce it, so the signal looks gone. One clean retest is not proof by itself.",
    retested_persists: "This reproduced earlier, and a retest after the fix reproduced it again: the signal is still there.",
    ruled_out: "An operator ruled this out. The reason sits in the audit trail on the finding page.",
    inconclusive: `${s.hint} Its reason is in the decision above.`,
    blocked: `${s.hint} That is a limit, not a result.`,
    failed: s.hint,
    not_reproduced: `${s.hint} That counts against the finding, not for it.`,
  };
  return head[s.key] || head.observed;
}