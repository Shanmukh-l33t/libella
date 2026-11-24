import { Fingerprint } from "lucide-react";
import type { ReactNode } from "react";
import type { Finding } from "../types";
import { fmtTime } from "../lib/format";
import { Badge, cx } from "./ui";
import { decisionOf, EXPLOITABILITY, impactOf, limitationsOf, stateHint, statusOf } from "../lib/validation";

/** State label refined by the last recorded verdict. Never promoted from a tool's exit code. */
export function StatusBadge({ finding }: { finding: Finding }) {
  const s = statusOf(finding);
  return (
    <span title={s.hint} className="inline-flex">
      <Badge tone={s.tone} dot capitalize={false}>{s.label}</Badge>
    </span>
  );
}

function Cell({ label, icon, children, className }: {
  label: string; icon?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <div className={cx("px-4 py-3", className)}>
      <div className="flex items-center gap-1.5 text-2xs font-medium uppercase tracking-wide text-ink-500">
        {icon}
        {label}
      </div>
      <div className="mt-1.5">{children}</div>
    </div>
  );
}

/**
 * The whole case for a finding in one frame: what was detected, whether impact was
 * demonstrated, what the last replay decided, and what the case does not cover.
 */
export function FindingCase({ finding }: { finding: Finding }) {
  const impact = impactOf(finding);
  const d = decisionOf(finding);
  const evidence = (finding.evidence_ids || []).length;

  return (
    <div className="grid overflow-hidden rounded border border-line bg-canvas sm:grid-cols-2">
      <Cell label="Detection" className="border-b border-line sm:border-r">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="text-sm font-medium text-ink-900">{finding.state === "suspected" ? "Suspected" : "Observed"}</span>
          <span className="text-2xs text-ink-500">
            {finding.confidence} confidence · {evidence ? `${evidence} evidence object${evidence > 1 ? "s" : ""}` : "no evidence bound"}
          </span>
        </div>
        <p className="mt-1 text-xs leading-relaxed text-ink-700">{stateHint(finding)}</p>
      </Cell>

      <Cell label="Impact" className="border-b border-line">
        <Badge tone="neutral" capitalize={false}>{impact.label}</Badge>
        <p className="mt-1 text-xs leading-relaxed text-ink-700">
          {finding.impact
            ? <><span className="text-ink-500">Predicted: </span>{finding.impact}</>
            : <span className="text-ink-500">No impact statement recorded.</span>}
        </p>
        <p className="mt-1 text-2xs text-ink-500">
          Exploitability: <span className="font-medium text-ink-700">{EXPLOITABILITY}</span>
        </p>
        {finding.impact && <p className="mt-1 text-2xs leading-relaxed text-ink-500">{impact.note}</p>}
      </Cell>

      <Cell label="Verification decision" className="border-b border-line sm:border-b-0 sm:border-r">
        {d ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={d.tone} dot capitalize={false}>{d.label}</Badge>
              <span className="text-2xs tabular-nums text-ink-500">
                {d.attempts} attempt{d.attempts === 1 ? "" : "s"}
                {d.method ? ` · ${d.method}` : ""}
                {d.when ? ` · ${fmtTime(d.when)}` : ""}
              </span>
            </div>
            {d.detail && <p className="mt-1 text-xs leading-relaxed text-ink-700">{d.detail}</p>}
          </>
        ) : (
          <p className="text-xs leading-relaxed text-ink-500">No verification has run. Nothing here reproduces the claim yet.</p>
        )}
      </Cell>

      <Cell label="Limitations">
        <ul className="space-y-1.5">
          {limitationsOf(finding).map((line) => (
            <li key={line} className="flex gap-2 text-xs leading-relaxed text-ink-700">
              <span aria-hidden className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-ink-300" />
              <span>{line}</span>
            </li>
          ))}
        </ul>
      </Cell>
    </div>
  );
}

/** Evidence objects bound to the finding, each with the request that produced it. */
export function EvidenceRefs({ finding }: { finding: Finding }) {
  const ids = finding.evidence_ids || [];
  if (!ids.length) {
    return <p className="text-xs leading-relaxed text-ink-500">No evidence is bound. Without a captured request this finding cannot be verified.</p>;
  }
  const byEvidence = new Map((finding.exchanges || []).map((x) => [x.evidence_id || "", x]));
  return (
    <ul className="divide-y divide-line/70 overflow-hidden rounded border border-line bg-white">
      {ids.map((id) => {
        const x = byEvidence.get(id);
        return (
          <li key={id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
            <Fingerprint size={13} className="shrink-0 text-ink-300" aria-hidden />
            <span className="font-mono text-xs text-ink-900">{id}</span>
            {x ? (
              <>
                <span className="font-mono text-2xs font-medium text-ink-700">{x.method || "GET"}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-2xs text-ink-500" title={x.url}>{x.url}</span>
                <span className={cx("font-mono text-2xs tabular-nums", (x.status || 0) >= 400 ? "text-sev-high" : "text-ink-700")}>
                  {x.status ?? "—"}
                </span>
              </>
            ) : (
              <span className="text-2xs text-ink-500">exchange not recorded</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}