import { useEffect, useState } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { api, setToken, getToken } from "../api";
import { Button, Input } from "./ui";

export default function TokenScreen({ onAuthed }: { onAuthed: () => void }) {
  const [token, setTok] = useState(getToken());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState<{ version?: string; tools?: unknown[] } | null>(null);

  useEffect(() => {
    fetch("/api/health").then((r) => r.json()).then(setHealth).catch(() => setHealth(null));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token.trim()) { setError("Enter the API token printed by the Libella backend."); return; }
    setBusy(true);
    setError(null);
    setToken(token);
    try {
      await api("/api/tools");
      onAuthed();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8">
          <div className="text-lg font-semibold tracking-tight text-ink-900">Libella</div>
          <div className="text-xs text-ink-500">Autonomous penetration testing workbench</div>
        </div>
        <form onSubmit={submit} className="rounded border border-line bg-white p-6 shadow-card">
          <div className="mb-4 flex items-center gap-2 text-sm font-medium text-ink-900">
            <KeyRound size={16} className="text-ink-500" /> Connect to local instance
          </div>
          <label className="label" htmlFor="token">API token</label>
          <Input id="token" type="password" autoFocus autoComplete="off" value={token}
            onChange={(e) => setTok(e.target.value)} placeholder="Paste the token from the server log"
            error={!!error} />
          {error && <p className="mt-1.5 text-xs text-sev-high">{error}</p>}
          <p className="mt-2 text-xs text-ink-500">Stored in this browser only. Sent as a bearer token.</p>
          <Button type="submit" variant="primary" loading={busy} className="mt-4 w-full">Connect</Button>
        </form>
        <div className="mt-4 flex items-center justify-between px-1 text-xs text-ink-500">
          <span className="inline-flex items-center gap-1.5">
            <ShieldCheck size={13} className={health ? "text-sev-low" : "text-ink-300"} />
            {health ? `Backend ${health.version || ""} · ${health.tools?.length ?? 0} tools` : "Backend unreachable"}
          </span>
          <span>localhost only</span>
        </div>
      </div>
    </div>
  );
}