import { AlertTriangle, CheckCircle2, CircleSlash } from "lucide-react";
import type { Settings, ToolInfo } from "../../types";
import { Badge, Card, Skeleton, cx } from "../../components/ui";
import {
  CATEGORIES, MODES, PROFILES, TARGET_TYPES, providerReady, toolTypes, warnings, type WizardState,
} from "../../lib/wizard";
import { Summary } from "./parts";

export default function Readiness({ s, tools, cfg, toolsError }: {
  s: WizardState; tools: ToolInfo[] | null; cfg: Settings | null; toolsError?: string | null;
}) {
  const provider = providerReady(cfg?.llm);
  const types = toolTypes(s.categories);
  const relevant = (tools || []).filter((t) => types.includes(t.category));
  const has = (k: string) => s.targets.some((t) => t.kind === k && t.value.trim());
  const warn = warnings(s, tools, provider, has);
  const profile = PROFILES.find((p) => p.id === s.profileId);
  const type = TARGET_TYPES.find((t) => t.id === s.targetType);
  const mode = MODES.find((m) => m.id === s.mode);

  return (
    <>
      <Card title="What you are about to create" description="Read back from the choices above. Nothing here has touched a target.">
        <Summary rows={[
          ["Name", s.name || <span className="text-sev-high">not set</span>],
          ["Target type", type?.label || "—"],
          ["Targets", s.targets.filter((t) => t.value.trim()).map((t) => `${t.kind} ${t.value}`).join(", ") || "—"],
          ["Exclusions", s.exclusions.filter((x) => x.value.trim()).map((x) => x.value).join(", ") || "none"],
          ["Check families", CATEGORIES.filter((c) => s.categories.includes(c.id)).map((c) => c.label).join(", ") || "none"],
          ["Profile", `${profile?.label || "—"} (${s.profile.replace(/_/g, " ")})`],
          ["Mode", mode ? `${mode.label} — ${mode.hint}` : s.mode],
          ["Access", s.access === "login" ? "recorded login flow" : s.access === "identities" ? `${s.identities.length} test account(s)` : "unauthenticated"],
          ["Specs", [s.openapi.trim() && "OpenAPI file", s.graphql.trim() && "GraphQL endpoint"].filter(Boolean).join(", ") || "none"],
          ["Window", s.windowStart || s.windowEnd
            ? `${s.windowStart ? new Date(s.windowStart).toLocaleString() : "now"} → ${s.windowEnd ? new Date(s.windowEnd).toLocaleString() : "manual stop"}`
            : "open (start and stop by hand)"],
          ["Limits", `${s.rps} req/s · ${s.concurrency} in flight${s.duration ? ` · ${s.duration}s cap` : ""}${s.budget ? ` · $${s.budget} cap` : ""}`],
        ]} />
      </Card>

      <Card title="Tools for these check families"
        description="Read from this machine's inventory. A missing tool is skipped and recorded as a degradation, never as a clean result.">
        {!tools && !toolsError && <Skeleton className="h-24 w-full" />}
        {toolsError && <p className="text-sm text-sev-high">Could not read the tool inventory: {toolsError}</p>}
        {tools && !relevant.length && (
          <p className="text-sm text-ink-500">No external scanner is needed for the selected families. The built-in checks run on their own.</p>
        )}
        {!!relevant.length && (
          <ul className="divide-y divide-line/70">
            {relevant.map((t) => (
              <li key={t.name} className="flex items-start gap-3 py-2">
                <span className={cx("mt-0.5 shrink-0", t.available ? "text-sev-low" : "text-ink-300")}>
                  {t.available ? <CheckCircle2 size={15} /> : <CircleSlash size={15} />}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-medium text-ink-900">{t.name}</span>
                    <Badge tone={t.available ? "success" : "neutral"}>{t.available ? "installed" : "missing"}</Badge>
                    <span className="text-2xs capitalize text-ink-500">{t.category}</span>
                  </div>
                  <p className="mt-0.5 text-xs text-ink-500">{t.description}</p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="AI provider" description="Only LLM planner and agent modes need one. The deterministic pipeline never does.">
        <div className="flex items-start gap-3">
          <span className={cx("mt-0.5 shrink-0", provider ? "text-sev-low" : "text-ink-300")}>
            {provider ? <CheckCircle2 size={15} /> : <CircleSlash size={15} />}
          </span>
          <div>
            <p className="text-sm font-medium text-ink-900">{provider ? "Configured" : "Not configured — offline"}</p>
            <p className="mt-0.5 text-xs text-ink-500">
              {provider
                ? "Agent and planner modes can run, and spend is capped by the budget above."
                : "Deterministic mode runs the full deterministic pipeline. LLM planner and agent modes are refused at start."}
            </p>
          </div>
        </div>
      </Card>

      <Card title="What will not work as chosen" description="Consequences you would otherwise discover in the report.">
        {warn.length ? (
          <ul className="space-y-2">
            {warn.map((w) => (
              <li key={w} className="flex gap-2 text-sm text-ink-700">
                <AlertTriangle size={15} className="mt-0.5 shrink-0 text-[#B54708]" />
                <span>{w}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-ink-500">Nothing to flag: the choices match the target, the profile and this machine.</p>
        )}
      </Card>
    </>
  );
}