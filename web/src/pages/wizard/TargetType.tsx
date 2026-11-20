import { Card } from "../../components/ui";
import { TARGET_TYPES, applyType, type Patch, type WizardState } from "../../lib/wizard";
import { Choice } from "./parts";

export default function TargetType({ s, patch, errors }: {
  s: WizardState; patch: Patch; errors: Record<string, string>;
}) {
  return (
    <Card title="What are you assessing?"
      description="This picks the target kind and the check families that make sense for it. Both stay editable.">
      <div role="radiogroup" aria-label="Target type" className="grid gap-2 sm:grid-cols-2">
        {TARGET_TYPES.map((t) => (
          <Choice key={t.id} name="target-type" checked={s.targetType === t.id}
            onChange={() => patch(applyType(s, t.id))} title={t.label} hint={t.hint} note={t.note} />
        ))}
      </div>
      {errors.targetType && <p className="mt-2 text-xs text-sev-high">{errors.targetType}</p>}
      <p className="mt-3 text-xs text-ink-500">
        Steps 2 to 4 are prefilled from this choice. Nothing is created or contacted until the last step.
      </p>
    </Card>
  );
}