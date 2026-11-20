import {
  createContext, useCallback, useContext, useEffect, useId, useMemo, useState,
  type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode,
  type SelectHTMLAttributes, type TextareaHTMLAttributes,
} from "react";
import { Check, ChevronDown, ChevronUp, Copy, X, AlertTriangle, Inbox } from "lucide-react";
import type { Tone } from "../types";

export const cx = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(" ");

/* ---------------------------------- Button --------------------------------- */

type Variant = "primary" | "secondary" | "ghost" | "danger";
const VARIANTS: Record<Variant, string> = {
  primary: "bg-accent text-white border border-accent hover:bg-accent-hover hover:border-accent-hover shadow-card",
  secondary: "bg-white text-ink-700 border border-line hover:border-ink-300 hover:text-ink-900 shadow-card",
  ghost: "bg-transparent text-ink-700 border border-transparent hover:bg-ink-100 hover:text-ink-900",
  danger: "bg-white text-sev-critical border border-line hover:border-sev-critical/40 hover:bg-sev-critical/5",
};

export function Button({
  variant = "secondary", size = "md", loading, className, children, disabled, icon, ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant; size?: "sm" | "md"; loading?: boolean; icon?: ReactNode;
}) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded font-medium transition-all duration-150",
        "disabled:opacity-50 disabled:pointer-events-none active:translate-y-px",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-8 px-3 text-sm",
        VARIANTS[variant], className,
      )}
    >
      {loading ? <span className="h-3.5 w-3.5 animate-spin rounded-full border-[1.5px] border-current border-t-transparent" /> : icon}
      {children}
    </button>
  );
}

/* ---------------------------------- Badge ---------------------------------- */

const TONES: Record<Tone, string> = {
  neutral: "bg-ink-100 text-ink-700 ring-line",
  accent: "bg-accent-soft text-accent ring-accent/20",
  success: "bg-[#ECFDF3] text-[#027A48] ring-[#ABEFC6]",
  warning: "bg-[#FFFAEB] text-[#B54708] ring-[#FEDF89]",
  danger: "bg-[#FEF3F2] text-[#B42318] ring-[#FECDCA]",
  critical: "bg-[#FEF3F2] text-[#912018] ring-[#FECDCA]",
  info: "bg-ink-100 text-ink-700 ring-line",
};

export function Badge({ tone = "neutral", children, dot, className }: { tone?: Tone; children: ReactNode; dot?: boolean; className?: string }) {
  return (
    <span className={cx("chip ring-1 ring-inset", TONES[tone], className)}>
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />}
      <span className="capitalize">{children}</span>
    </span>
  );
}

/* ---------------------------------- Card ----------------------------------- */

export function Card({ title, description, actions, children, className, padded = true }: {
  title?: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; padded?: boolean;
}) {
  return (
    <section className={cx("rounded border border-line bg-white shadow-card", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
          <div>
            {title && <h2 className="text-sm font-semibold text-ink-900">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-ink-500">{description}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={padded ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="rounded border border-line bg-white px-4 py-3">
      <div className="text-xs text-ink-500">{label}</div>
      <div className="mt-1 text-xl font-semibold tabular-nums text-ink-900">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-ink-500">{hint}</div>}
    </div>
  );
}

/* ---------------------------------- Table ---------------------------------- */

export interface Column<T> {
  key: string;
  label: ReactNode;
  render?: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number;
  align?: "left" | "right";
  width?: string;
  className?: string;
}

export function Table<T>({ columns, rows, getKey, empty, onRowClick, initialSort, dense }: {
  columns: Column<T>[]; rows: T[]; getKey: (row: T) => string; empty?: ReactNode;
  onRowClick?: (row: T) => void; initialSort?: { key: string; dir: "asc" | "desc" }; dense?: boolean;
}) {
  const [sort, setSort] = useState(initialSort || null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const sv = col.sortValue;
    return [...rows].sort((a, b) => {
      const va = sv(a), vb = sv(b);
      const r = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
      return sort.dir === "asc" ? r : -r;
    });
  }, [rows, sort, columns]);

  if (!rows.length) return <>{empty}</>;

  return (
    <div className="overflow-x-auto">
      <table className="table-base">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} style={{ ...(c.width ? { width: c.width } : {}), ...(c.align === "right" ? { textAlign: "right" } : {}) }}
                className={c.className}>
                {c.sortValue ? (
                  <button className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-ink-900 transition-colors"
                    onClick={() => setSort((s) => ({ key: c.key, dir: s?.key === c.key && s.dir === "asc" ? "desc" : "asc" }))}
                    aria-label={`Sort by ${String(c.label)}`}>
                    {c.label}
                    {sort?.key === c.key && (sort.dir === "asc" ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                  </button>
                ) : c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => (
            <tr key={getKey(row)} onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={cx(onRowClick && "cursor-pointer", dense && "[&>td]:py-2")}>
              {columns.map((c) => (
                <td key={c.key} className={cx(c.align === "right" && "text-right", c.className)}>
                  {c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? "—")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------------------------------- Tabs ----------------------------------- */

export function Tabs({ tabs, value, onChange }: {
  tabs: { id: string; label: string; count?: number }[]; value: string; onChange: (id: string) => void;
}) {
  return (
    <div role="tablist" className="no-scrollbar flex gap-1 overflow-x-auto border-b border-line">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
          className={cx("-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm transition-colors",
            value === t.id ? "border-accent font-medium text-ink-900" : "border-transparent text-ink-500 hover:text-ink-900")}>
          {t.label}
          {t.count !== undefined && <span className="rounded bg-ink-100 px-1.5 text-2xs tabular-nums text-ink-500">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

/* --------------------------------- Form bits -------------------------------- */

export function Field({ label, htmlFor, error, hint, required, children, className }: {
  label: ReactNode; htmlFor?: string; error?: string | null; hint?: ReactNode; required?: boolean; children: ReactNode; className?: string;
}) {
  return (
    <div className={className}>
      <label className="label" htmlFor={htmlFor}>
        {label} {required && <span className="text-sev-high">*</span>}
      </label>
      {children}
      {error ? <p className="mt-1 text-xs text-sev-high">{error}</p> : hint ? <p className="mt-1 text-xs text-ink-500">{hint}</p> : null}
    </div>
  );
}

export const Input = (p: InputHTMLAttributes<HTMLInputElement> & { error?: boolean }) => {
  const { error, className, ...rest } = p;
  return <input {...rest} className={cx("input", error && "input-error", className)} />;
};

export const Select = (p: SelectHTMLAttributes<HTMLSelectElement> & { error?: boolean }) => {
  const { error, className, children, ...rest } = p;
  return <select {...rest} className={cx("input pr-8", error && "input-error", className)}>{children}</select>;
};

export const Textarea = (p: TextareaHTMLAttributes<HTMLTextAreaElement> & { error?: boolean }) => {
  const { error, className, ...rest } = p;
  return <textarea {...rest} className={cx("input h-auto py-2 leading-relaxed", error && "input-error", className)} />;
};

/* ---------------------------------- Modal ---------------------------------- */

export function Modal({ open, onClose, title, children, footer, width = "max-w-lg" }: {
  open: boolean; onClose: () => void; title: string; children: ReactNode; footer?: ReactNode; width?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-ink-900/30 p-4 pt-[12vh]" onMouseDown={onClose}>
      <div role="dialog" aria-modal="true" aria-label={title} className={cx("w-full rounded border border-line bg-white shadow-lg", width)}
        onMouseDown={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold">{title}</h2>
          <button onClick={onClose} aria-label="Close dialog" className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-900">
            <X size={16} />
          </button>
        </header>
        <div className="px-4 py-4">{children}</div>
        {footer && <footer className="flex justify-end gap-2 border-t border-line px-4 py-3">{footer}</footer>}
      </div>
    </div>
  );
}

/* -------------------------------- Empty/loading ----------------------------- */

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("animate-pulse rounded bg-ink-100", className)} />;
}

export function TableSkeleton({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="divide-y divide-line/70">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-4 px-3 py-3">
          {Array.from({ length: cols }).map((__, c) => <Skeleton key={c} className={cx("h-3.5", c === 0 ? "w-1/3" : "flex-1")} />)}
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ title, description, action, icon }: { title: string; description?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-3 text-ink-300">{icon || <Inbox size={22} />}</div>
      <h3 className="text-sm font-medium text-ink-900">{title}</h3>
      {description && <p className="mt-1 max-w-sm text-sm text-ink-500">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Banner({ tone = "warning", title, children }: { tone?: Tone; title: string; children?: ReactNode }) {
  return (
    <div className={cx("flex gap-3 rounded border px-4 py-3 text-sm",
      tone === "critical" || tone === "danger" ? "border-sev-high/30 bg-[#FEF3F2]" : "border-[#FEDF89] bg-[#FFFAEB]")}>
      <AlertTriangle size={16} className={cx("mt-0.5 shrink-0", tone === "critical" || tone === "danger" ? "text-sev-high" : "text-[#B54708]")} />
      <div>
        <div className="font-medium text-ink-900">{title}</div>
        {children && <div className="mt-0.5 text-ink-700">{children}</div>}
      </div>
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="rounded border border-sev-high/30 bg-[#FEF3F2] px-3 py-2 text-sm text-[#912018]">{error}</div>;
}

/* ---------------------------------- Code ----------------------------------- */

export function CodeBlock({ content, maxHeight = 320, label }: { content: string; maxHeight?: number; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(content); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard unavailable */ }
  };
  return (
    <div className="overflow-hidden rounded border border-line bg-canvas">
      <div className="flex items-center justify-between border-b border-line px-3 py-1.5">
        <span className="text-2xs font-medium uppercase tracking-wide text-ink-500">{label || "content"}</span>
        <button onClick={copy} aria-label="Copy to clipboard" className="inline-flex items-center gap-1 rounded px-1.5 py-1 text-2xs text-ink-500 hover:bg-white hover:text-ink-900 transition-colors">
          {copied ? <Check size={12} /> : <Copy size={12} />} {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-auto p-3 text-xs leading-relaxed text-ink-700 whitespace-pre-wrap break-words" style={{ maxHeight }}>
        {content}
      </pre>
    </div>
  );
}

export function JsonViewer({ value, maxHeight = 320 }: { value: unknown; maxHeight?: number }) {
  return <CodeBlock label="json" content={JSON.stringify(value, null, 2)} maxHeight={maxHeight} />;
}

/* ---------------------------------- Toast ---------------------------------- */

type ToastItem = { id: number; message: string; tone: Tone };
const ToastCtx = createContext<(message: string, tone?: Tone) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const push = useCallback((message: string, tone: Tone = "neutral") => {
    const id = Date.now() + Math.random();
    setItems((xs) => [...xs, { id, message, tone }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 4500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={cx("pointer-events-auto rounded border bg-white px-3 py-2.5 text-sm shadow-lg animate-[fadeIn_.15s_ease-out]",
            t.tone === "critical" || t.tone === "danger" ? "border-sev-high/40" : t.tone === "success" ? "border-[#ABEFC6]" : "border-line")}>
            <div className="flex items-start gap-2">
              <span className={cx("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full",
                t.tone === "critical" || t.tone === "danger" ? "bg-sev-high" : t.tone === "success" ? "bg-sev-low" : "bg-ink-300")} />
              <span className="text-ink-700">{t.message}</span>
            </div>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/* -------------------------------- Misc utils -------------------------------- */

export function useDomId(prefix: string) {
  const id = useId();
  return `${prefix}-${id}`;
}