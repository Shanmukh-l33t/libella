import { useState } from "react";
import { KeyRound, PlugZap } from "lucide-react";
import { post } from "../api";
import { Badge, Button, Field, Input, Select } from "./ui";

interface Result {
  reachable: boolean; tls: string; status: number | null;
  auth: string; identity_confirmed: boolean; detail: string;
}

const AUTH_TONE: Record<string, "success" | "danger" | "warning" | "info"> = {
  accepted: "success", responded_success: "info", rejected: "danger",
  redirect: "warning", server_error: "danger", refused: "danger", error: "danger", unknown: "info",
};
const AUTH_LABEL: Record<string, string> = {
  accepted: "Credential accepted", responded_success: "Responded 2xx (identity unconfirmed)",
  rejected: "Credential rejected", redirect: "Redirected (likely login)",
  server_error: "Server error", refused: "Refused by scope", error: "Invalid input", unknown: "Unknown",
};

/** Setup-time check that a target API credential works. Never assumes 200 = authorized. */
export default function CredentialTest({ defaultUrl = "" }: { defaultUrl?: string }) {
  const [url, setUrl] = useState(defaultUrl);
  const [type, setType] = useState("bearer");
  const [value, setValue] = useState("");
  const [name, setName] = useState("X-API-Key");
  const [username, setUsername] = useState("");
  const [expect, setExpect] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);

  const test = async () => {
    setBusy(true); setError(null); setResult(null);
    const credential: Record<string, string> = { type };
    if (type === "bearer") credential.token = value;
    else if (type === "header") { credential.name = name; credential.value = value; }
    else if (type === "basic") { credential.username = username; credential.password = value; }
    else if (type === "cookie") credential.value = value;
    try {
      setResult(await post<Result>("/api/target-credentials/test", {
        url: url.trim(), credential, expect_substring: expect.trim() || undefined,
      }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded border border-line bg-canvas p-4">
      <div className="mb-1 flex items-center gap-1.5 text-sm font-medium text-ink-900">
        <KeyRound size={14} className="text-ink-500" /> Test target API credentials
      </div>
      <p className="mb-3 text-xs text-ink-500">
        Optional. Confirm a key, token or cookie works against an authorized endpoint before you run.
        A 200 response alone is not treated as proof of authorization.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Endpoint URL" htmlFor="cred-url">
          <Input id="cred-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://api.example.com/me" />
        </Field>
        <Field label="Credential type" htmlFor="cred-type">
          <Select id="cred-type" value={type} onChange={(e) => setType(e.target.value)}>
            <option value="bearer">Bearer token</option>
            <option value="header">Custom header</option>
            <option value="basic">Basic (username / password)</option>
            <option value="cookie">Cookie</option>
            <option value="none">None (reachability only)</option>
          </Select>
        </Field>
        {type === "header" && (
          <Field label="Header name" htmlFor="cred-name">
            <Input id="cred-name" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
        )}
        {type === "basic" && (
          <Field label="Username" htmlFor="cred-user">
            <Input id="cred-user" value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
        )}
        {type !== "none" && (
          <Field label={type === "basic" ? "Password" : type === "cookie" ? "Cookie value" : "Value"} htmlFor="cred-value">
            <Input id="cred-value" type="password" autoComplete="new-password" value={value} onChange={(e) => setValue(e.target.value)} />
          </Field>
        )}
        <Field label="Expected identity marker (optional)" htmlFor="cred-expect" hint="A string that must appear in the response to confirm identity, e.g. a username.">
          <Input id="cred-expect" value={expect} onChange={(e) => setExpect(e.target.value)} placeholder="alice" />
        </Field>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <Button size="sm" icon={<PlugZap size={13} />} loading={busy} onClick={test} disabled={!url.trim()}>
          Test credentials
        </Button>
        {result && (
          <span className="flex flex-wrap items-center gap-2 text-xs text-ink-700" role="status" aria-live="polite">
            <Badge tone={AUTH_TONE[result.auth] || "info"}>{AUTH_LABEL[result.auth] || result.auth}</Badge>
            {result.status !== null && <span>HTTP {result.status}</span>}
            <span>{result.reachable ? "reachable" : "not reachable"}</span>
            {result.identity_confirmed && <Badge tone="success">identity confirmed</Badge>}
          </span>
        )}
      </div>
      {result?.detail && <p className="mt-2 text-xs text-ink-600">{result.detail}</p>}
      {error && <p className="mt-2 text-xs text-sev-high">{error}</p>}
    </div>
  );
}
