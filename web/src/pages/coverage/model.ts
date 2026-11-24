/** Shared vocabulary for the standards coverage screen.
 *
 * The server owns the rules; this file only names them so the list and the
 * detail drawer cannot drift apart. Nothing here derives a status.
 */
import type { Tone } from "../../types";

export type AutoStatus =
  | "not_applicable" | "not_supported" | "requires_manual" | "skipped_policy"
  | "skipped_dependency" | "attempted" | "inconclusive" | "failed"
  | "completed_no_issue" | "partial_evidence" | "finding_unverified" | "finding_verified";
export type Review = "covered" | "manual" | "unsupported" | "unknown";

export const AUTO_STATUSES: AutoStatus[] = [
  "not_applicable", "not_supported", "requires_manual", "skipped_policy", "skipped_dependency",
  "attempted", "inconclusive", "failed", "completed_no_issue", "partial_evidence",
  "finding_unverified", "finding_verified",
];
export const REVIEWS: Review[] = ["covered", "manual", "unsupported", "unknown"];

export const TONE: Record<AutoStatus, Tone> = {
  not_applicable: "neutral", not_supported: "warning", requires_manual: "warning",
  skipped_policy: "warning", skipped_dependency: "warning", attempted: "info",
  inconclusive: "warning", failed: "danger", completed_no_issue: "neutral",
  partial_evidence: "info", finding_unverified: "info", finding_verified: "danger",
};
export const REVIEW_TONE: Record<Review, Tone> = {
  covered: "success", manual: "info", unsupported: "warning", unknown: "neutral",
};

export const HELP: Record<AutoStatus, string> = {
  not_applicable: "The engagement scope has no web category, so this standard does not apply.",
  not_supported: "No Libella check reaches this surface; the evidence sits outside the engagement model.",
  requires_manual: "No automated check exists. A tester has to perform this test by hand.",
  skipped_policy: "The engagement profile refused the mapped check. Untested, not failed.",
  skipped_dependency: "A mapped tool or dependency was missing, so the check could not run.",
  attempted: "Scheduled or running without a completion record.",
  inconclusive: "Ran partially (timeout/cancel) or never ran. Nothing can be concluded.",
  failed: "The mapped check ran and failed. No result.",
  completed_no_issue: "The mapped check executed and recorded no finding. Only as good as the check.",
  partial_evidence: "A mapped check ran, but it covers only PART of this requirement. Not a pass.",
  finding_unverified: "A finding from the mapped check is recorded but not independently validated.",
  finding_verified: "A finding from the mapped check was independently replayed.",
};

/** Everything an operator must read as "no conclusion". */
export const UNTESTED: AutoStatus[] = [
  "not_applicable", "not_supported", "requires_manual", "skipped_policy",
  "skipped_dependency", "attempted", "inconclusive", "failed",
];

export interface Evidence {
  tool_calls: string[]; exchanges: string[]; intents: string[]; events: number[]; findings: string[];
}
export interface Item {
  id: string; title: string; status: AutoStatus | Review;
  level?: number | null; section?: string | null; section_title?: string | null;
  automatic: { status: AutoStatus; reason: string; units: string[]; strength?: string; test?: string; prerequisite?: string };
  manual: { status: Review; note?: string | null; evidence_id?: string | null; updated_at?: number | null } | null;
  evidence: Evidence;
}
export interface Category { id: string; name: string; counts: Record<AutoStatus, number>; tests: Item[] }
export type Mapping = Record<string, {
  requirements: string[]; why: string; strength: Record<string, "direct" | "partial" | "indirect">;
}>;
export interface Framework {
  id: string; version: string; title: string; source: string; license?: string;
  requirements: number; groups: number; levels: number[];
}
export interface UnattributedFinding { id: string; title: string; cwe?: string | null; state: string; reason: string }
export interface Workspace {
  framework: Framework;
  engagement_id: string;
  unattributed_findings?: UnattributedFinding[];
  summary: Record<"total" | "applicable" | "supported" | "attempted" | "completed" | "partial"
    | "with_findings" | "skipped" | "manual_required" | "not_tested" | "catalog"
    | "excluded_by_level", number> & { level: number | null }
    & { statuses: Record<AutoStatus, number>; manual: Record<"covered" | "manual" | "unsupported", number> };
  categories: Category[];
  mapping: Mapping;
}

/** The nine tiles, in reading order: how much of the scope was actually resolved. */
export const SUMMARY_KEYS: [key: string, label: string, hint: string, tone: "" | "success" | "danger"][] = [
  ["applicable", "Applicable", "tests the scope can reach", ""],
  ["supported", "Supported", "a Libella check can exercise them", ""],
  ["attempted", "Attempted", "a check started", ""],
  ["completed", "Completed", "executed to a result", "success"],
  ["partial", "Partial", "a check covered only part of the requirement", ""],
  ["with_findings", "With findings", "verified or unverified", "danger"],
  ["skipped", "Skipped", "profile or dependency", ""],
  ["manual_required", "Manual required", "no automated check exists", ""],
  ["not_tested", "Not tested", "never completed — not a pass", "danger"],
] as const;