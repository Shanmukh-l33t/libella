import type { ReactNode } from "react";
import { Check, Minus } from "lucide-react";
import { cx } from "../../components/ui";

/** A selectable card. The real control is the radio inside, so keyboard and AT behave natively. */
export function Choice({ name, checked, onChange, title, hint, note, children, disabled }: {
  name: string; checked: boolean; onChange: () => void; title: ReactNode; hint?: ReactNode;
  note?: ReactNode; children?: ReactNode; disabled?: boolean;
}) {
  return (
    <label className={cx("flex cursor-pointer gap-2.5 rounded border p-3 transition-colors duration-150",
      checked ? "border-accent bg-accent-soft/60 ring-1 ring-accent/20" : "border-line hover:border-ink-300",
      disabled && "cursor-not-allowed opacity-60")}>
      <input type="radio" name={name} checked={checked} disabled={disabled} onChange={onChange} className="mt-0.5 shrink-0" />
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-medium text-ink-900">{title}</span>
        {hint && <span className="mt-0.5 block text-xs text-ink-500">{hint}</span>}
        {note && <span className="mt-1.5 block text-xs text-ink-700">{note}</span>}
        {children}
      </span>
    </label>
  );
}

export function YesNo({ runs, stops }: { runs: string[]; stops: string[] }) {
  return (
    <span className="mt-2 block space-y-2">
      <span className="block">
        <span className="text-2xs font-medium uppercase tracking-wide text-ink-500">Runs</span>
        <span className="mt-0.5 block space-y-0.5">
          {runs.map((r) => (
            <span key={r} className="flex gap-1.5 text-xs text-ink-700">
              <Check size={12} className="mt-0.5 shrink-0 text-sev-low" />{r}
            </span>
          ))}
        </span>
      </span>
      <span className="block">
        <span className="text-2xs font-medium uppercase tracking-wide text-ink-500">Does not run</span>
        <span className="mt-0.5 block space-y-0.5">
          {stops.map((r) => (
            <span key={r} className="flex gap-1.5 text-xs text-ink-500">
              <Minus size={12} className="mt-0.5 shrink-0 text-ink-300" />{r}
            </span>
          ))}
        </span>
      </span>
    </span>
  );
}

/** Read-back of one choice, for the readiness and start steps. */
export function Summary({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="divide-y divide-line/70">
      {rows.map(([k, v]) => (
        <div key={k} className="flex flex-col gap-0.5 py-2 sm:flex-row sm:gap-4">
          <dt className="w-40 shrink-0 text-xs text-ink-500">{k}</dt>
          <dd className="min-w-0 break-words text-sm text-ink-900">{v}</dd>
        </div>
      ))}
    </dl>
  );
}