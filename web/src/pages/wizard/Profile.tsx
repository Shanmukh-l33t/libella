import { Card, Field, Select, cx } from "../../components/ui";
import { CATEGORIES, PROFILES, applyProfile, type Patch, type WizardState } from "../../lib/wizard";
import { Choice, YesNo } from "./parts";

const CEILINGS = [
  { id: "passive", label: "passive — read-only observation" },
  { id: "production_safe", label: "production_safe — passive, labelled for live systems" },
  { id: "safe_active", label: "safe_active — adds scanners and injection probes" },
  { id: "advanced_validation", label: "advanced_validation — same surface, disruptive validation authorised" },
];

export default function Profile({ s, patch }: { s: WizardState; patch: Patch }) {
  return (
    <>
      <Card title="How hard should it push?"
        description="The profile is an enforced ceiling, not a label: a check outside it is refused and the refusal is recorded.">
        <div role="radiogroup" aria-label="Profile" className="grid gap-2 lg:grid-cols-2">
          {PROFILES.map((p) => (
            <Choice key={p.id} name="profile" checked={s.profileId === p.id} onChange={() => patch(applyProfile(p.id))}
              title={p.label} hint={p.profile.replace(/_/g, " ")}>
              <YesNo runs={p.runs} stops={p.stops} />
            </Choice>
          ))}
        </div>

        {s.profileId === "custom" && (
          <div className="mt-4 border-t border-line pt-4">
            <Field label="Policy ceiling" htmlFor="w-ceiling" hint="Which units the engine may run at all.">
              <Select id="w-ceiling" value={s.profile} onChange={(e) => patch({ profile: e.target.value })}>
                {CEILINGS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
              </Select>
            </Field>
            {s.profile === "advanced_validation" && (
              <p className="mt-2 text-xs text-ink-500">advanced_validation marks the scope as authorising disruptive validation.</p>
            )}
          </div>
        )}
      </Card>

      <Card title="Check families" description="What to plan for. At least one keeps the run meaningful; unmatched ones are skipped with a reason.">
        <div className="grid gap-2 sm:grid-cols-2">
          {CATEGORIES.map((c) => {
            const on = s.categories.includes(c.id);
            return (
              <label key={c.id} className={cx("flex cursor-pointer items-start gap-2 rounded border px-3 py-2 transition-colors",
                on ? "border-accent/40 bg-accent-soft/40" : "border-line hover:border-ink-300")}>
                <input type="checkbox" className="mt-0.5" checked={on}
                  onChange={(e) => patch({
                    categories: e.target.checked ? [...s.categories, c.id] : s.categories.filter((x) => x !== c.id),
                  })} />
                <span>
                  <span className="block text-sm font-medium text-ink-900">{c.label}</span>
                  <span className="block text-xs text-ink-500">{c.hint}</span>
                </span>
              </label>
            );
          })}
        </div>
        <p className="mt-3 text-xs text-ink-500">
          Policy refuses some pairs: Quick cannot run API audits, Production-safe cannot run scanners. Readiness says which.
        </p>
      </Card>
    </>
  );
}
