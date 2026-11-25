import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import type { TargetKind } from "../../types";
import { Button, Card, Field, Input, Select, cx } from "../../components/ui";
import {
  EXCLUSION_KINDS, TARGET_TYPES, targetError, type ExRow, type Patch, type Row, type WizardState,
} from "../../lib/wizard";

const KINDS: TargetKind[] = ["url", "domain", "cidr", "ip", "repo", "image", "cloud"];

const PLACEHOLDER: Record<TargetKind, string> = {
  url: "https://app.example.com", domain: "example.com", cidr: "10.0.0.0/24", ip: "10.0.0.5",
  repo: "/srv/app", image: "app:latest", cloud: "123456789012",
};

export default function Scope({ s, patch, errors }: {
  s: WizardState; patch: Patch; errors: Record<string, string>;
}) {
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const mark = (k: string) => setTouched((t) => ({ ...t, [k]: true }));

  const setRow = (i: number, p: Partial<Row>) =>
    patch({ targets: s.targets.map((r, idx) => (idx === i ? { ...r, ...p } : r)) });
  const setEx = (i: number, p: Partial<ExRow>) =>
    patch({ exclusions: s.exclusions.map((r, idx) => (idx === i ? { ...r, ...p } : r)) });

  const preset = TARGET_TYPES.find((t) => t.id === s.targetType);

  return (
    <>
      <Card title="Scope" description="The authorization boundary. Every tool call is checked against it before anything leaves this machine.">
        <Field label="Engagement name" htmlFor="w-name" error={errors.name} required>
          <Input id="w-name" value={s.name} onChange={(e) => patch({ name: e.target.value })}
            onBlur={() => mark("name")} placeholder="e.g. ACME portal — external web"
            error={!!errors.name} />
        </Field>

        <div className="mt-5 space-y-2">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="text-sm font-medium text-ink-700">In-scope targets <span className="text-sev-high">*</span></h3>
            <span className="text-xs text-ink-500">{preset ? `${preset.label} preset` : "at least one required"}</span>
          </div>
          {s.targets.map((t, i) => {
            const err = t.value.trim() ? targetError(t.kind, t.value) : null;
            return (
              <div key={i} className="rounded border border-line/80 p-2 sm:border-0 sm:p-0">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                  <Select aria-label={`Target ${i + 1} kind`} value={t.kind} className="sm:w-32"
                    onChange={(e) => setRow(i, { kind: e.target.value as TargetKind })}>
                    {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
                  </Select>
                  <Input aria-label={`Target ${i + 1} value`} value={t.value} className="flex-1 font-mono text-xs"
                    placeholder={PLACEHOLDER[t.kind]} error={!!err && touched[`t${i}`]}
                    onChange={(e) => setRow(i, { value: e.target.value })} onBlur={() => mark(`t${i}`)} />
                  <div className="flex items-center justify-end gap-2 sm:justify-start">
                    {t.kind === "domain" && (
                      <label className="flex items-center gap-1.5 whitespace-nowrap text-xs text-ink-700">
                        <input type="checkbox" checked={t.include_subdomains}
                          onChange={(e) => setRow(i, { include_subdomains: e.target.checked })} />
                        subdomains
                      </label>
                    )}
                    <Button type="button" variant="ghost" aria-label={`Remove target ${i + 1}`} icon={<Trash2 size={14} />}
                      onClick={() => patch({
                        targets: s.targets.length === 1
                          ? [{ kind: t.kind, value: "", include_subdomains: false }]
                          : s.targets.filter((_, idx) => idx !== i),
                      })} />
                  </div>
                </div>
                {err && touched[`t${i}`] && <p className="mt-1 text-xs text-sev-high">{err}</p>}
              </div>
            );
          })}
          {errors.targets && <p className="text-xs text-sev-high">{errors.targets}</p>}
          <Button type="button" size="sm" icon={<Plus size={13} />}
            onClick={() => patch({ targets: [...s.targets, { kind: s.targets[0]?.kind || "url", value: "", include_subdomains: false }] })}>
            Add target
          </Button>
        </div>
      </Card>

      <Card title="Exclusions" description="Optional. Anything listed here is refused even when it falls inside a target.">
        {s.exclusions.map((x, i) => {
          const err = x.value.trim() ? targetError(x.kind, x.value) : null;
          return (
            <div key={i} className="mb-2">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <Select aria-label={`Exclusion ${i + 1} kind`} value={x.kind} className="sm:w-32"
                  onChange={(e) => setEx(i, { kind: e.target.value as ExRow["kind"] })}>
                  {EXCLUSION_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
                </Select>
                <Input aria-label={`Exclusion ${i + 1} value`} value={x.value} className="flex-1 font-mono text-xs"
                  placeholder={x.kind === "url_prefix" ? "https://app.example.com/billing" : "billing.example.com"}
                  error={!!err && touched[`x${i}`]}
                  onChange={(e) => setEx(i, { value: e.target.value })} onBlur={() => mark(`x${i}`)} />
                <Button type="button" variant="ghost" aria-label={`Remove exclusion ${i + 1}`} icon={<Trash2 size={14} />}
                  onClick={() => patch({ exclusions: s.exclusions.filter((_, idx) => idx !== i) })} />
              </div>
              {err && touched[`x${i}`] && <p className="mt-1 text-xs text-sev-high">{err}</p>}
            </div>
          );
        })}
        {errors.exclusions && <p className="mb-2 text-xs text-sev-high">{errors.exclusions}</p>}
        <Button type="button" size="sm" icon={<Plus size={13} />}
          onClick={() => patch({ exclusions: [...s.exclusions, { kind: "domain", value: "" }] })}>
          Add exclusion
        </Button>
      </Card>

      <Card title="Authorization and limits" description="Scope is fail-closed: without the confirmation below nothing is created.">
        <label className={cx("flex cursor-pointer items-start gap-2 rounded border p-3",
          errors.authorized ? "border-sev-high/60 bg-[#FEF3F2]" : "border-line")}>
          <input type="checkbox" className="mt-0.5" checked={s.authorized}
            onChange={(e) => patch({ authorized: e.target.checked })} />
          <span className="text-sm text-ink-900">
            I am authorized to test every target above.
            <span className="mt-0.5 block text-xs text-ink-500">
              The platform enforces this list in code: any host, port or path outside it is refused and the refusal is audited.
            </span>
          </span>
        </label>
        {errors.authorized && <p className="mt-1 text-xs text-sev-high">{errors.authorized}</p>}

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="Window starts" htmlFor="w-win-start" hint="Optional. Blank means it may run as soon as you start it.">
            <Input id="w-win-start" type="datetime-local" value={s.windowStart}
              onChange={(e) => patch({ windowStart: e.target.value })} error={!!errors.window} />
          </Field>
          <Field label="Window ends" htmlFor="w-win-end" hint="After this, every egress path is refused.">
            <Input id="w-win-end" type="datetime-local" value={s.windowEnd}
              onChange={(e) => patch({ windowEnd: e.target.value })} error={!!errors.window} />
          </Field>
        </div>
        {errors.window && <p className="mt-1 text-xs text-sev-high">{errors.window}</p>}

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="Requests per second" htmlFor="w-rps" hint="10 is polite on a shared host. Higher finishes sooner and stands out in logs.">
            <Input id="w-rps" type="number" min={0.1} step="0.1" value={s.rps} onChange={(e) => patch({ rps: e.target.value })} />
          </Field>
          <Field label="Requests in flight" htmlFor="w-conc" hint="How many run at the same moment. 4 is a safe default.">
            <Input id="w-conc" type="number" min={1} step={1} value={s.concurrency} onChange={(e) => patch({ concurrency: e.target.value })} />
          </Field>
          <Field label="Stop after (seconds)" htmlFor="w-dur" hint="Blank means no time cap.">
            <Input id="w-dur" type="number" min={1} value={s.duration} placeholder="1800" onChange={(e) => patch({ duration: e.target.value })} />
          </Field>
          <Field label="Spend cap (USD)" htmlFor="w-budget" hint="Only model calls cost money. Blank means no cap.">
            <Input id="w-budget" type="number" min={0.01} step="0.01" value={s.budget} placeholder="5.00" onChange={(e) => patch({ budget: e.target.value })} />
          </Field>
        </div>
      </Card>
    </>
  );
}