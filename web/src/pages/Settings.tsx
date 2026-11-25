import { useEffect, useState } from "react";
import { CheckCircle2, CircleSlash, Save, Wrench } from "lucide-react";
import { post, put } from "../api";
import type { Settings as S, ToolInfo } from "../types";
import { useApi } from "../lib/hooks";
import { Badge, Button, Card, ErrorNote, Field, Input, Skeleton, Table, Textarea, useToast } from "../components/ui";

const ROLES = [
  { id: "planner", label: "Planner", hint: "Decomposes objectives into intents." },
  { id: "worker", label: "Worker", hint: "Interprets tool output." },
  { id: "verifier", label: "Verifier", hint: "Cross-checks claims (deterministic replay stays authoritative)." },
  { id: "reporter", label: "Reporter", hint: "Drafts narrative — never evidence." },
];

type ProviderResult = { status: string; message: string; latency_ms: number | null };
const effectiveUrl = (url?: string) => url?.trim().replace(/\/+$/, "") || "https://api.openai.com/v1";

export default function Settings() {
  const cfg = useApi<S>("/api/settings");
  const tools = useApi<ToolInfo[]>("/api/tools");
  const toast = useToast();
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [defaultModel, setDefaultModel] = useState("");
  const [models, setModels] = useState<Record<string, string>>({});
  const [fallback, setFallback] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [keySet, setKeySet] = useState(false);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<ProviderResult | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [detected, setDetected] = useState<{ id: string; label: string }[]>([]);
  const [detectMsg, setDetectMsg] = useState<string | null>(null);
  const [apiStyle, setApiStyle] = useState<"auto" | "openai" | "anthropic">("auto");
  const usingSavedKey = keySet && effectiveUrl(baseUrl) === effectiveUrl(cfg.data?.llm?.base_url);

  useEffect(() => {
    if (!cfg.data) return;
    const llm = cfg.data.llm || {};
    setBaseUrl(llm.base_url || "");
    setDefaultModel(llm.default_model || "");
    setModels(llm.models || {});
    setFallback((llm.fallback || []).join("\n"));
    setKeySet(llm.api_key === "[SET]");
    const st = (llm.api_style || "auto").toLowerCase();
    setApiStyle(st === "anthropic" || st === "openai" ? st : "auto");
  }, [cfg.data]);

  /** Ask the endpoint which models it has, so nobody has to type an ID from memory. */
  const detect = async () => {
    setDetecting(true);
    setDetectMsg(null);
    setDetected([]);
    try {
      const r = await post<{ status: string; message: string; models: { id: string; label: string }[] }>(
        "/api/settings/provider-models",
        { base_url: baseUrl.trim(), api_key: apiKey.trim(), api_style: apiStyle === "auto" ? "" : apiStyle },
      );
      setDetected(r.models || []);
      setDetectMsg(r.models?.length ? `${r.models.length} model(s) found` : r.message);
    } catch {
      setDetectMsg("Could not reach the endpoint to list models.");
    } finally {
      setDetecting(false);
    }
  };

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

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (baseUrl && !/^https?:\/\//.test(baseUrl)) { setError("Base URL must start with http:// or https://"); return; }
    setBusy(true);
    try {
      const llm: Record<string, unknown> = {
        base_url: baseUrl.trim(),
        api_style: apiStyle === "auto" ? "" : apiStyle,
        default_model: defaultModel.trim(),
        models: Object.fromEntries(Object.entries(models).filter(([, v]) => v && v.trim()).map(([k, v]) => [k, v.trim()])),
        fallback: fallback.split("\n").map((s) => s.trim()).filter(Boolean),
      };
      if (apiKey.trim()) llm.api_key = apiKey.trim();
      await put("/api/settings", { llm });
      toast("Settings saved.", "success");
      setApiKey("");
      cfg.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const missing = (tools.data || []).filter((t) => !t.available);

  return (
    <div className="mx-auto max-w-[900px] space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-900">Settings</h1>
        <p className="mt-1 text-sm text-ink-500">Instance-wide configuration, stored by the backend. Deterministic checks run with or without a model.</p>
      </div>

      <form onSubmit={save} className="space-y-5">
        <ErrorNote error={error} />
        <Card title="AI provider" description="Optional. Leave this unconfigured to work without an AI provider.">
          {cfg.loading && !cfg.data ? <Skeleton className="h-40 w-full" /> : (
            <>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Base URL" htmlFor="base-url" hint="Blank uses OpenAI. Custom endpoints need server approval for connection testing.">
                  <Input id="base-url" value={baseUrl} disabled={testing || busy} onChange={(e) => { setBaseUrl(e.target.value); setApiKey(""); setResult(null); }} placeholder="https://api.openai.com/v1" />
                </Field>
                <Field label={<span className="inline-flex items-center gap-2">API key <Badge tone="info">{usingSavedKey ? "saved" : "not saved"}</Badge></span>} htmlFor="api-key" hint={usingSavedKey ? "Leave blank to use the saved key." : "Enter a key if this endpoint requires one."}>
                  <Input id="api-key" type="password" autoComplete="new-password" value={apiKey} disabled={testing || busy} onChange={(e) => { setApiKey(e.target.value); setResult(null); }} placeholder={usingSavedKey ? "•••••••• (saved)" : undefined} />
                </Field>
                <Field label="API style" htmlFor="api-style"
                  hint="Auto detects from the host. Anthropic speaks the Messages API, which is a different wire format.">
                  <select id="api-style" className="input h-8 w-full text-sm" value={apiStyle}
                    disabled={testing || busy}
                    onChange={(e) => { setApiStyle(e.target.value as "auto" | "openai" | "anthropic"); setDetected([]); setDetectMsg(null); }}>
                    <option value="auto">Auto detect</option>
                    <option value="openai">OpenAI compatible</option>
                    <option value="anthropic">Anthropic Messages</option>
                  </select>
                </Field>
                <Field label="Default model" htmlFor="default-model"
                  hint="Detect to list what the endpoint offers, then pick one. Typing an exact ID still works.">
                  <div className="flex gap-2">
                    <Input id="default-model" value={defaultModel} disabled={testing || busy}
                      onChange={(e) => { setDefaultModel(e.target.value); setResult(null); }}
                      placeholder={detected.length ? "pick a detected model" : "gpt-4o-mini"} />
                    <Button type="button" variant="secondary" disabled={busy || detecting}
                      loading={detecting} onClick={detect}>Detect</Button>
                  </div>
                  {detectMsg && <p className="mt-1 text-xs text-ink-500">{detectMsg}</p>}
                  {!!detected.length && (
                    <ul className="mt-2 max-h-40 overflow-auto rounded border border-ink-100">
                      {detected.map((m) => (
                        <li key={m.id}>
                          <button type="button" onClick={() => { setDefaultModel(m.id); setResult(null); }}
                            className={`w-full px-2 py-1 text-left text-xs hover:bg-ink-50 ${defaultModel === m.id ? "bg-ink-50 font-medium" : ""}`}>
                            {m.id}{m.label && m.label !== m.id ? <span className="text-ink-400"> — {m.label}</span> : null}
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </Field>
              </div>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                <Button type="button" disabled={busy || !cfg.data} loading={testing} onClick={test}>Test connection</Button>
                <span className="text-xs text-ink-500">Sends one short prompt. May incur a small charge. Does not save settings.</span>
              </div>
              <div role="status" aria-live="polite">
                {result && <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-ink-700">
                  <Badge tone={result.status === "connected" ? "success" : result.status === "busy" ? "info" : "danger"}>
                    {result.status === "connected" ? "Connected" : result.status === "busy" ? "Busy" : "Not verified"}
                  </Badge>
                  <span>{result.message}{result.latency_ms !== null ? ` (${result.latency_ms} ms)` : ""}</span>
                </div>}
              </div>
              <details className="mt-5 border-t border-line pt-4">
                <summary className="mb-3 cursor-pointer text-sm font-medium text-ink-700">Advanced model settings</summary>
                <Field label="Fallback models" htmlFor="fallback" hint="One per line, tried in order.">
                  <Textarea id="fallback" rows={yieldRows(fallback)} value={fallback} onChange={(e) => setFallback(e.target.value)} placeholder={"model-a\nmodel-b"} className="font-mono text-xs" />
                </Field>
                <div className="mb-2 mt-4 text-sm font-medium text-ink-700">Per-role overrides</div>
                <div className="grid gap-3 sm:grid-cols-2">
                  {ROLES.map((r) => (
                    <Field key={r.id} label={r.label} htmlFor={`role-${r.id}`} hint={r.hint}>
                      <Input id={`role-${r.id}`} value={models[r.id] || ""} placeholder={defaultModel || "inherit default"}
                        onChange={(e) => setModels({ ...models, [r.id]: e.target.value })} />
                    </Field>
                  ))}
                </div>
              </details>
              {keySet && !usingSavedKey && <p className="mt-3 text-xs text-ink-600">Saving a different endpoint removes the old API key. Enter a replacement if needed.</p>}
              <div className="mt-5 flex justify-end">
                <Button type="submit" variant="primary" icon={<Save size={14} />} disabled={testing || !cfg.data} loading={busy}>Save provider settings</Button>
              </div>
            </>
          )}
        </Card>
      </form>

      <Card title={<span className="inline-flex items-center gap-1.5"><Wrench size={14} className="text-ink-500" /> Tools</span>}
        description={missing.length ? `${missing.length} tool${missing.length === 1 ? "" : "s"} missing — checks that need them are skipped and surface as degradations, never as clean results.` : "All registered tools are installed."}
        padded={false}>
        <ErrorNote error={tools.error} />
        {tools.loading && !tools.data ? <Skeleton className="m-4 h-32" /> : (
          <Table<ToolInfo>
            rows={tools.data || []}
            getKey={(t) => t.name}
            columns={[
              { key: "name", label: "Tool", render: (t) => <span className="font-mono text-xs font-medium">{t.name}</span> },
              { key: "category", label: "Category", render: (t) => <span className="text-xs capitalize text-ink-700">{t.category}</span> },
              {
                key: "available", label: "Status",
                render: (t) => t.available
                  ? <span className="inline-flex items-center gap-1 text-xs text-[#027A48]"><CheckCircle2 size={12} /> installed</span>
                  : <span className="inline-flex items-center gap-1 text-xs text-ink-500"><CircleSlash size={12} /> missing</span>,
              },
              { key: "description", label: "Description", render: (t) => <span className="text-xs text-ink-500">{t.description}</span> },
              ...(missing.length ? [{
                key: "hint", label: "Install hint",
                render: (t: ToolInfo) => t.available ? <span className="text-ink-300">—</span>
                  : <span className="text-xs text-ink-500">Install <span className="font-mono">{t.name}</span> on PATH (or /usr/local/bin) and restart the backend.</span>,
              }] : []),
              {
                key: "flags", label: "Flags",
                render: (t) => <span className="flex gap-1">{t.read_only && <Badge tone="info">read-only</Badge>}{t.destructive && <Badge tone="danger">destructive</Badge>}</span>,
              },
            ]}
          />
        )}
      </Card>
    </div>
  );
}

function yieldRows(s: string) {
  return Math.min(6, Math.max(2, s.split("\n").length));
}
