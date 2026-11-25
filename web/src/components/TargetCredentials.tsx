import { useId, useState, type ChangeEvent, type FormEvent } from "react";
import { KeyRound, Play, Trash2 } from "lucide-react";
import type { Engagement, Tone } from "../types";
import { api, post } from "../api";
import { useApi } from "../lib/hooks";
import { fmtTime } from "../lib/format";
import { Badge, Button, Card, ErrorNote, Field, Input, Select, cx } from "./ui";

type CredType = "bearer" | "header" | "basic" | "cookie" | "oauth_client_credentials";

interface TestResult {
  classification: string;
  status?: number | null;
  message: string;
  url?: string | null;
  location_host?: string | null;
}

interface Credential {
  id: string;
  type: CredType;
  name: string;
  header_name?: string | null;
  token_url?: string | null;
  created_at?: number;
  last_test?: TestResult | null;
}

const TYPES: { id: CredType; label: string }[] = [
  { id: "bearer", label: "Bearer token" },
  { id: "header", label: "Custom header" },
  { id: "basic", label: "Basic auth (username / password)" },
  { id: "cookie", label: "Cookie header" },
  { id: "oauth_client_credentials", label: "OAuth client credentials" },
];

const TONE: Record<string, Tone> = {
  accepted: "success",
  responded_success: "warning",
  rejected: "danger",
  redirect: "warning",
  server_error: "danger",
  refused: "neutral",
  error: "neutral",
};

const LABEL: Record<string, string> = {
  accepted: "Accepted",
  responded_success: "2xx, identity not proven",
  rejected: "Rejected",
  redirect: "Redirect",
  server_error: "Server error",
  refused: "Refused before sending",
  error: "No result",
};

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

export default function TargetCredentials({ eid, eng }: { eid: string; eng: Engagement }) {
  const list = useApi<Credential[]>(`/api/engagements/${eid}/credentials`);
  const [type, setType] = useState<CredType>("bearer");
  const [form, setForm] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, TestResult>>({});
  const [urls, setUrls] = useState<Record<string, string>>({});
  const [markers, setMarkers] = useState<Record<string, string>>({});
  const uid = useId();

  const scopeDefault = (eng.scope?.targets || []).find((t) => t.kind === "url")?.value || "";
  const field = (key: string) => ({
    id: `${uid}-${key}`,
    value: form[key] || "",
    onChange: (e: ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [key]: e.target.value })),
  });

  const payload = () => {
    const body: Record<string, string> = { type, name: (form.name || "").trim() || TYPES.find((t) => t.id === type)!.label };
    if (type === "oauth_client_credentials") {
      body.token_url = form.token_url || "";
      body.client_id = form.client_id || "";
      body.client_secret = form.client_secret || "";
      if (form.scope) body.scope = form.scope;
    } else {
      if (type === "header") body.header_name = form.header_name || "";
      if (type === "basic") {
        body.username = form.username || "";
        body.password = form.password || "";
      } else {
        body.value = form.value || "";
      }
    }
    return body;
  };

  async function save(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await post(`/api/engagements/${eid}/credentials`, payload());
      setForm({});  // the value is sealed server-side and never comes back
      list.reload();
    } catch (err) {
      setError(errText(err));
    } finally {
      setSaving(false);
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      await api(`/api/engagements/${eid}/credentials/${id}`, { method: "DELETE" });
      list.reload();
    } catch (err) {
      setError(errText(err));
    }
  }

  async function test(c: Credential) {
    setBusy(c.id);
    setError(null);
    try {
      const url = (urls[c.id] || c.token_url || scopeDefault).trim();
      const marker = (markers[c.id] || "").trim();
      const result = await post<TestResult>(`/api/engagements/${eid}/credentials/${c.id}/test`,
        { url, ...(marker ? { expect_substring: marker } : {}) });
      setResults((r) => ({ ...r, [c.id]: result }));
      list.reload();
    } catch (err) {
      setError(errText(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card title="Target credentials" description="Stored encrypted for this engagement. A test is one bounded request inside the authorized scope.">
      <form className="space-y-3" onSubmit={save}>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Type" htmlFor={`${uid}-type`}>
            <Select id={`${uid}-type`} value={type} onChange={(e) => setType(e.target.value as CredType)}>
              {TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
            </Select>
          </Field>
          <Field label="Name" htmlFor={`${uid}-name`} hint="Shown in the list; never the secret.">
            <Input {...field("name")} placeholder="Staging API key" autoComplete="off" />
          </Field>
          {type === "header" && (
            <>
              <Field label="Header name" htmlFor={`${uid}-header_name`} required>
                <Input {...field("header_name")} placeholder="X-Api-Key" autoComplete="off" />
              </Field>
              <Field label="Header value" htmlFor={`${uid}-value`} required>
                <Input {...field("value")} type="password" autoComplete="off" />
              </Field>
            </>
          )}
          {(type === "bearer" || type === "cookie") && (
            <Field label={type === "bearer" ? "Token" : "Cookie header value"} htmlFor={`${uid}-value`} required
              className="sm:col-span-2" hint="Sent as-is. It is sealed before it touches the database.">
              <Input {...field("value")} type="password" autoComplete="off"
                placeholder={type === "bearer" ? "eyJ…" : "session=abc123"} />
            </Field>
          )}
          {type === "basic" && (
            <>
              <Field label="Username" htmlFor={`${uid}-username`} required>
                <Input {...field("username")} autoComplete="off" />
              </Field>
              <Field label="Password" htmlFor={`${uid}-password`} required>
                <Input {...field("password")} type="password" autoComplete="off" />
              </Field>
            </>
          )}
          {type === "oauth_client_credentials" && (
            <>
              <Field label="Token URL" htmlFor={`${uid}-token_url`} required className="sm:col-span-2"
                hint="Must be inside this engagement's scope; the client secret only goes here.">
                <Input {...field("token_url")} placeholder="https://auth.example.test/oauth/token" autoComplete="off" />
              </Field>
              <Field label="Client ID" htmlFor={`${uid}-client_id`} required>
                <Input {...field("client_id")} autoComplete="off" />
              </Field>
              <Field label="Client secret" htmlFor={`${uid}-client_secret`} required>
                <Input {...field("client_secret")} type="password" autoComplete="off" />
              </Field>
              <Field label="Scope" htmlFor={`${uid}-scope`} hint="Optional. Sent as the token request scope.">
                <Input {...field("scope")} placeholder="read:api" autoComplete="off" />
              </Field>
            </>
          )}
        </div>
        {error && <ErrorNote error={error} />}
        <Button type="submit" variant="primary" loading={saving} icon={<KeyRound size={14} />}>Save credential</Button>
      </form>

      <div className="mt-4 border-t border-line pt-3">
        {list.error && <ErrorNote error={list.error} />}
        {(list.data || []).length === 0 ? (
          <p className="text-sm text-ink-500">{list.loading ? "Loading…" : "No credentials saved for this engagement."}</p>
        ) : (
          <ul className="divide-y divide-line/70">
            {(list.data || []).map((c) => {
              const result = results[c.id] || c.last_test || null;
              return (
                <li key={c.id} className="space-y-2 py-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone="neutral" capitalize={false}>{c.type.replace(/_/g, " ")}</Badge>
                    <span className="text-sm font-medium text-ink-900">{c.name}</span>
                    <span className="font-mono text-2xs text-ink-500">{c.header_name || "—"}</span>
                    <span className="text-2xs text-ink-300">value •••••• (sealed)</span>
                    <span className="text-2xs text-ink-300">added {fmtTime(c.created_at)}</span>
                    <span className="ml-auto flex items-center gap-1.5">
                      <Button size="sm" icon={<Play size={12} />} loading={busy === c.id} onClick={() => test(c)}>Test credentials</Button>
                      <Button size="sm" variant="danger" aria-label={`Delete ${c.name}`} onClick={() => remove(c.id)} icon={<Trash2 size={12} />} />
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Input aria-label={`Test URL for ${c.name}`} className="min-w-0 flex-1 font-mono text-xs"
                      placeholder={c.token_url || scopeDefault || "https://target.example/api/me"}
                      value={urls[c.id] ?? (c.type === "oauth_client_credentials" ? c.token_url || "" : scopeDefault)}
                      onChange={(e) => setUrls((u) => ({ ...u, [c.id]: e.target.value }))} />
                    <Input aria-label={`Expected marker for ${c.name}`} className="w-48 font-mono text-xs"
                      placeholder="expected identity text"
                      value={markers[c.id] || ""}
                      onChange={(e) => setMarkers((m) => ({ ...m, [c.id]: e.target.value }))} />
                  </div>
                  {result && (
                    <div className={cx("rounded border px-3 py-2 text-xs",
                      result.classification === "accepted" ? "border-[#ABEFC6] bg-[#ECFDF3]"
                        : result.classification === "responded_success" ? "border-[#FEDF89] bg-[#FFFAEB]"
                          : "border-line bg-canvas")}>
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={TONE[result.classification] || "neutral"} dot>
                          {LABEL[result.classification] || result.classification}
                        </Badge>
                        {result.status ? <span className="tabular-nums text-ink-500">HTTP {result.status}</span> : null}
                        {result.location_host ? <span className="font-mono text-ink-500">→ {result.location_host}</span> : null}
                      </div>
                      <p className="mt-1 text-ink-700">{result.message}</p>
                      {result.classification === "responded_success" && (
                        <p className="mt-1 text-ink-500">A 200 response alone is not proof of authorization.</p>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Card>
  );
}