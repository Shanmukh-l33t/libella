import { useEffect, useState } from "react";
import { CheckCircle2, CircleSlash, Save, Wrench } from "lucide-react";
import { put } from "../api";
import type { Settings as S, ToolInfo } from "../types";
import { useApi } from "../lib/hooks";
import { Badge, Button, Card, ErrorNote, Field, Input, Skeleton, Table, Textarea, useToast } from "../components/ui";

const ROLES = [
  { id: "planner", label: "Planner", hint: "Decomposes objectives into intents." },
  { id: "worker", label: "Worker", hint: "Interprets tool output." },
  { id: "verifier", label: "Verifier", hint: "Cross-checks claims (deterministic replay stays authoritative)." },
  { id: "reporter", label: "Reporter", hint: "Drafts narrative — never evidence." },
];

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

  useEffect(() => {
    if (!cfg.data) return;
    const llm = cfg.data.llm || {};
    setBaseUrl(llm.base_url || "");
    setDefaultModel(llm.default_model || "");
    setModels(llm.models || {});
    setFallback((llm.fallback || []).join("\n"));
    setKeySet(llm.api_key === "[SET]");
  }, [cfg.data]);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (baseUrl && !/^https?:\/\//.test(baseUrl)) { setError("Base URL must start with http:// or https://"); return; }
    setBusy(true);
    try {
      const llm: Record<string, unknown> = {
        base_url: baseUrl.trim(),
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
        <Card title="LLM provider" description="Optional. Without a provider the engine runs deterministic planning only.">
          {cfg.loading && !cfg.data ? <Skeleton className="h-40 w-full" /> : (
            <>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Base URL" htmlFor="base-url" hint="OpenAI-compatible endpoint, e.g. https://api.openai.com/v1">
                  <Input id="base-url" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://api.openai.com/v1" />
                </Field>
                <Field label={<span className="inline-flex items-center gap-2">API key <Badge tone={keySet ? "success" : "info"}>{keySet ? "configured" : "not set"}</Badge></span>} htmlFor="api-key" hint={keySet ? "A key is stored. Leave blank to keep it." : "Stored server-side; returned only as [SET]."}>
                  <Input id="api-key" type="password" autoComplete="off" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder={keySet ? "•••••••• (set)" : "sk-…"} />
                </Field>
                <Field label="Default model" htmlFor="default-model" hint="Used when a role has no override.">
                  <Input id="default-model" value={defaultModel} onChange={(e) => setDefaultModel(e.target.value)} placeholder="e.g. gpt-4.1-mini" />
                </Field>
                <Field label="Fallback models" htmlFor="fallback" hint="One per line, tried in order.">
                  <Textarea id="fallback" rows={yieldRows(fallback)} value={fallback} onChange={(e) => setFallback(e.target.value)} placeholder={"model-a\nmodel-b"} className="font-mono text-xs" />
                </Field>
              </div>

              <div className="mt-5 border-t border-line pt-4">
                <div className="mb-2 text-sm font-medium text-ink-700">Per-role overrides</div>
                <div className="grid gap-3 sm:grid-cols-2">
                  {ROLES.map((r) => (
                    <Field key={r.id} label={r.label} htmlFor={`role-${r.id}`} hint={r.hint}>
                      <Input id={`role-${r.id}`} value={models[r.id] || ""} placeholder={defaultModel || "inherit default"}
                        onChange={(e) => setModels({ ...models, [r.id]: e.target.value })} />
                    </Field>
                  ))}
                </div>
              </div>

              <div className="mt-5 flex justify-end">
                <Button type="submit" variant="primary" icon={<Save size={14} />} loading={busy}>Save LLM settings</Button>
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
