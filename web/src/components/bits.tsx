import type { ReactNode } from "react";
import { SEV_COLOR, SEV_ORDER } from "../lib/format";
import { EmptyState } from "./ui";

export function SeverityCounts({ counts }: { counts: Record<string, number> }) {
  const total = SEV_ORDER.reduce((n, k) => n + (counts[k] || 0), 0);
  if (!total) return <span className="text-xs text-ink-300">none</span>;
  return (
    <div className="flex flex-wrap gap-2.5">
      {SEV_ORDER.filter((k) => counts[k]).map((k) => (
        <span key={k} aria-label={`${counts[k]} ${k} findings`} className="inline-flex items-center gap-1 text-xs tabular-nums text-ink-700" title={`${counts[k]} ${k}`}>
          <span className="h-2 w-2 rounded-sm" style={{ background: SEV_COLOR[k] }} />
          {counts[k]}
        </span>
      ))}
    </div>
  );
}

export function NoRows({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return <EmptyState title={title} description={description} action={action} />;
}

export function KeyVal({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-ink-500">{label}</dt>
      <dd className="text-sm text-ink-900 break-words">{children}</dd>
    </div>
  );
}
