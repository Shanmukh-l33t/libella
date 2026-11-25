import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, CheckCircle2, Circle, CircleSlash, PlugZap, Rocket, Wrench } from "lucide-react";
import { post, put } from "../api";
import type { Engagement, Settings as S, ToolInfo } from "../types";
import { useApi } from "../lib/hooks";
import { Badge, Button, Card, EmptyState, ErrorNote, Field, Input, Skeleton, cx, useToast } from "../components/ui";

type Health = { status: string; version: string };
type ProviderResult = { status: string; message: string; latency_ms: number | null };

const STEPS = ["Environment", "AI provider", "Tools", "Next steps"];
const effectiveUrl = (url?: string) => url?.trim().replace(/\/+$/, "") || "https://api.openai.com/v1";

export default function Setup() {
  const navigate = useNavigate();
  const toast = useToast();
  const health = useApi<Health>("/api/health");
  const cfg = useApi<S>("/api/settings");
  const tools = useApi<ToolInfo[]>("/api/tools");
  const engs = useApi<Engagement[]>("/api/engagements");

  const [step, setStep] = useState(0);
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [defaultModel, setDefaultModel] = useState("");
  const [keySet, setKeySet] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<ProviderResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Move focus to the step body so keyboard and screen-reader users land on the new content.
  const region = useRef<HTMLElement>(null);
  const moved = useRef(false);
  useEffect(() => {
    if (moved.current) region.current?.focus();
    else moved.current = true;
  }, [step]);

  useEffect(() => {
    if (!cfg.data) return;
    const llm = cfg.data.llm || {};
    setBaseUrl(llm.base_url || "");
    setDefaultModel(llm.default_model || "");
    setKeySet(llm.api_key === "[SET]");
  }, [cfg.data]);

  const usingSavedKey = keySet && effectiveUrl(baseUrl) === effectiveUrl(cfg.data?.llm?.base_url);

  const test = async () => {
    setTesting(true);
    setResult(null);
    try {
      setResult(await post<ProviderResult>("/api/settings/provider-test", {
        base_url: baseUrl.trim(), default_model: defaultModel.trim(), api_key: apiKey.trim(),
      }));
    } catch {
      setResult({ status: "error", message: "Libella could not complete this check. Check the server and your session, then retry.", latency_ms: null });
    } finally {
      setTesting(false);
    }
  };

  const save = async () => {
    setError(null);
    if (baseUrl && !/^https?:\/\//.test(baseUrl)) { setError("Base URL must start with http:// or https://"); return; }
    setSaving(true);
    try {
      const llm: Record<string, unknown> = { base_url: baseUrl.trim(), default_model: defaultModel.trim() };
      if (apiKey.trim()) llm.api_key = apiKey.trim();
      await put("/api/settings", { llm });
      toast("Provider saved.", "success");
      setApiKey("");
      setResult(null);
      cfg.reload();
      setStep(2);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  const installed = (tools.data || []).filter((t) => t.available).length;
  const registry = [...(tools.data || [])].sort((a, b) => Number(a.available) - Number(b.available) || a.name.localeCompare(b.name));

  return (
    <div className="mx-auto max-w-[860px] space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-900">Set up Libella</h1>
        <p className="mt-1 text-sm text-ink-500">
          Step {step + 1} of {STEPS.length} · nothing here starts an assessment or contacts a target.
        </p>
      </div>

      <nav aria-label="Setup steps" className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
        {STEPS.map((label, i) => (
          <button key={label} type="button" onClick={() => setStep(i)} aria-current={i === step ? "step" : undefined}
            className={cx("flex items-center gap-2 rounded border px-2.5 py-2.5 text-left text-xs transition-colors sm:py-2",
              i === step ? "border-accent/40 bg-accent-soft font-medium text-accent"
                : "border-line bg-white text-ink-500 hover:border-ink-300 hover:text-ink-900")}>
            <span className={cx("flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-2xs tabular-nums",
              i === step ? "bg-accent text-white" : "bg-ink-100 text-ink-500")}>{i + 1}</span>
            <span className="truncate">{label}</span>
          </button>
        ))}
      </nav>

      <section ref={region} tabIndex={-1} aria-label={STEPS[step]} className="space-y-5 outline-none">
        {step === 0 && (
          <>
            <Card title="Environment check" description="Read-only probes of the running backend."
              actions={<Button size="sm" disabled={health.loading} onClick={() => { health.reload(); engs.reload(); }}>Refresh</Button>}>
              <div className="divide-y divide-line/70">
                <CheckRow ok={health.data ? health.data.status === "ok" : health.error ? false : null} label="Backend"
                  value={health.loading && !health.data ? "checking…"
                    : health.data ? `reachable · version ${health.data.version}`
                    : health.error ? "unreachable" : "—"}
                  hint="GET /api/health, the same probe used for container liveness." />
                <CheckRow ok={engs.data ? true : engs.error ? false : null} label="Local data store"
                  value={engs.loading && !engs.data ? "checking…"
                    : engs.data ? `readable · ${engs.data.length} engagement${engs.data.length === 1 ? "" : "s"}`
                    : engs.error ? "not readable" : "—"}
                  hint="SQLite state read back through GET /api/engagements." />
                <CheckRow ok={null} label="Evidence ledger"
                  value="verified per engagement"
                  hint="This build's health probe reports status and version only, not chain integrity. Open an engagement's Evidence tab to verify its hash chain." />
              </div>
              <ErrorNote error={health.error || engs.error} />
            </Card>
            <p className="text-xs text-ink-500">
              A provider is optional — the deterministic pipeline runs the full assessment without one.
            </p>
          </>
        )}

        {step === 1 && (
          <Card title="AI provider" description="Optional. Leave it unconfigured to work offline in deterministic mode.">
            {cfg.loading && !cfg.data ? <Skeleton className="h-40 w-full" /> : (
              <>
                <ErrorNote error={error} />
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Base URL" htmlFor="setup-base-url" hint="Blank uses OpenAI. Custom endpoints need server approval for connection testing.">
                    <Input id="setup-base-url" value={baseUrl} disabled={testing || saving} placeholder="https://api.openai.com/v1"
                      onChange={(e) => { setBaseUrl(e.target.value); setApiKey(""); setResult(null); }} />
                  </Field>
                  <Field label={<span className="inline-flex items-center gap-2">API key <Badge tone="info">{usingSavedKey ? "saved" : "not saved"}</Badge></span>}
                    htmlFor="setup-api-key" hint={usingSavedKey ? "Leave blank to use the saved key." : "Enter a key if this endpoint requires one."}>
                    <Input id="setup-api-key" type="password" autoComplete="new-password" value={apiKey} disabled={testing || saving}
                      placeholder={usingSavedKey ? "•••••••• (saved)" : undefined}
                      onChange={(e) => { setApiKey(e.target.value); setResult(null); }} />
                  </Field>
                  <Field label="Default model" htmlFor="setup-model" className="sm:col-span-2" hint="Enter the exact model ID. Blank uses gpt-4o-mini.">
                    <Input id="setup-model" value={defaultModel} disabled={testing || saving} placeholder="gpt-4o-mini"
                      onChange={(e) => { setDefaultModel(e.target.value); setResult(null); }} />
                  </Field>
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <Button type="button" disabled={saving || !cfg.data} loading={testing} onClick={test} icon={<PlugZap size={14} />}>Test connection</Button>
                  <Button type="button" variant="primary" disabled={testing || !cfg.data} loading={saving} onClick={save}>Save provider</Button>
                  <Button type="button" variant="ghost" onClick={() => setStep(2)}>Skip — stay offline</Button>
                </div>
                <p className="mt-2 text-xs text-ink-500">
                  Testing sends one short prompt and may incur a small charge. It does not save settings.
                </p>
                <div role="status" aria-live="polite">
                  {result && <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-ink-700">
                    <Badge tone={result.status === "connected" ? "success" : result.status === "busy" ? "info" : "danger"}>
                      {result.status === "connected" ? "Connected" : result.status === "busy" ? "Busy" : "Not verified"}
                    </Badge>
                    <span>{result.message}{result.latency_ms !== null ? ` (${result.latency_ms} ms)` : ""}</span>
                  </div>}
                </div>
                {keySet && !usingSavedKey && <p className="mt-3 text-xs text-ink-600">Saving a different endpoint removes the old API key. Enter a replacement if needed.</p>}
              </>
            )}
          </Card>
        )}

        {step === 2 && (
          <Card title={<span className="inline-flex items-center gap-1.5"><Wrench size={14} className="text-ink-500" /> Tool inventory</span>}
            description={tools.data
              ? `${installed} of ${tools.data.length} installed. A check whose tool is missing is skipped and recorded as a degradation, never as a clean result.`
              : "Checks whose tool is missing are skipped and recorded as degradations."}
            actions={<Button size="sm" onClick={() => navigate("/tools")}>Check tool versions</Button>} padded={false}>
            <div className="px-4"><ErrorNote error={tools.error} /></div>
            {tools.loading && !tools.data ? <Skeleton className="m-4 h-32" />
              : !registry.length ? <EmptyState title="No scanners registered" description="This backend build exposes no tool adapters; deterministic checks that need one will be skipped." />
              : (
                <ul className="divide-y divide-line/70 px-4">
                  {registry.map((t) => (
                    <li key={t.name} className="flex items-start gap-3 py-2.5">
                      <span className={cx("mt-0.5 shrink-0", t.available ? "text-[#027A48]" : "text-ink-300")}>
                        {t.available ? <CheckCircle2 size={15} /> : <CircleSlash size={15} />}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs font-medium text-ink-900">{t.name}</span>
                          <Badge tone={t.available ? "success" : "neutral"}>{t.available ? "Installed" : "Missing"}</Badge>
                          <span className="text-2xs capitalize text-ink-500">{t.category}</span>
                        </div>
                        <p className="mt-0.5 text-xs text-ink-500">{t.description}</p>
                        {!t.available && <p className="mt-0.5 text-xs text-ink-500">Install <span className="font-mono">{t.name}</span> on PATH, then restart the backend.</p>}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
          </Card>
        )}

        {step === 3 && (
          <>
            <Card title={<span className="inline-flex items-center gap-1.5"><Rocket size={14} className="text-ink-500" /> Next steps</span>}
              description="Review previous results or create a draft engagement. Setup does not run an assessment.">
              <div className="mt-4 flex flex-wrap gap-2">
                <Button variant="primary" icon={<Rocket size={14} />} onClick={() => navigate("/engagements/new")}>Create an engagement</Button>
                <Button onClick={() => navigate("/engagements")}>View engagements</Button>
              </div>
              <p className="mt-3 text-xs text-ink-500">
                {engs.loading && !engs.data ? "Counting engagements…"
                  : engs.data ? `${engs.data.length} engagement${engs.data.length === 1 ? "" : "s"} so far.`
                  : "Could not read the engagement list."}
              </p>
            </Card>

          </>
        )}
      </section>

      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-4">
        {step > 0 && <Button variant="ghost" icon={<ArrowLeft size={14} />} onClick={() => setStep((s) => s - 1)}>Back</Button>}
        {step < 3
          ? <Button variant="primary" onClick={() => setStep((s) => s + 1)}>Next <ArrowRight size={14} /></Button>
          : <Button variant="ghost" onClick={() => navigate("/")}>Command center</Button>}
      </div>
    </div>
  );
}

/** One read-only probe. `ok: null` means this build does not report it. */
function CheckRow({ ok, label, value, hint }: { ok: boolean | null; label: string; value: string; hint: string }) {
  return (
    <div className="flex items-start gap-3 py-3">
      <span className={cx("mt-0.5 shrink-0", ok === true ? "text-[#027A48]" : ok === false ? "text-sev-high" : "text-ink-300")}>
        {ok === null ? <Circle size={14} /> : ok ? <CheckCircle2 size={15} /> : <CircleSlash size={15} />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="text-sm font-medium text-ink-900">{label}</span>
          <span className={cx("text-sm", ok === false ? "text-sev-high" : "text-ink-700")}>{value}</span>
        </div>
        <p className="mt-0.5 text-xs text-ink-500">{hint}</p>
      </div>
    </div>
  );
}