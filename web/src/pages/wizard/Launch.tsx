import { Card, Field, Select } from "../../components/ui";
import { MODES, PROFILES, type Patch, type WizardState } from "../../lib/wizard";
import { Summary } from "./parts";

export default function Launch({ s, patch, provider, offline }: {
  s: WizardState; patch: Patch; provider: boolean; offline: boolean;
}) {
  const profile = PROFILES.find((p) => p.id === s.profileId);
  return (
    <>
      <Card title="Create and start" description="One call creates the engagement, then the run starts under the profile and limits you chose.">
        <Summary rows={[
          ["Name", s.name],
          ["Profile", `${profile?.label || "—"} — ${s.profile.replace(/_/g, " ")}`],
          ["Targets", s.targets.filter((t) => t.value.trim()).map((t) => `${t.kind} ${t.value}`).join(", ")],
          ["Limits", `${s.rps} req/s · ${s.concurrency} in flight${s.duration ? ` · stop after ${s.duration}s` : ""}${s.budget ? ` · $${s.budget} cap` : ""}`],
        ]} />

        <div className="mt-4 border-t border-line pt-4">
          <Field label="Execution mode" htmlFor="w-mode"
            hint={`${MODES.find((m) => m.id === s.mode)?.hint || ""} ${offline ? "No provider yet: only deterministic runs." : ""}`.trim()}>
            <Select id="w-mode" value={s.mode} onChange={(e) => patch({ mode: e.target.value })}>
              {MODES.map((m) => (
                <option key={m.id} value={m.id} disabled={!provider && m.id !== "deterministic"}>{m.label}</option>
              ))}
            </Select>
          </Field>
        </div>

        <p className="mt-4 text-xs text-ink-500">
          Saving as a draft does the same work minus the start: the engagement appears in the list, and you can start it when
          you are ready. Credentials are never kept in this browser.
        </p>
      </Card>
    </>
  );
}