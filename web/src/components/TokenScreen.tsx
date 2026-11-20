import { useEffect, useState } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { api, setToken, getToken } from "../api";
import { Button, Input } from "./ui";

export default function TokenScreen({ onAuthed }: { onAuthed: () => void }) {
  const [token, setTok] = useState(getToken());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState<{ version?: string } | null>(null);

  useEffect(() => {
    fetch("/api/health").then((r) => r.json()).then(setHealth).catch(() => setHealth(null));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token.trim()) {
      setError("Enter the API token: the value of LIBELLA_TOKEN, or run `libella --show-token --data-dir <dir>` in a terminal.");
      return;
    }
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
            onChange={(e) => setTok(e.target.value)} placeholder="Paste the API token"
            error={!!error} />
          {error && <p className="mt-1.5 text-xs text-sev-high">{error}</p>}
          <p className="mt-2 text-xs text-ink-500">
            Held in memory for this tab only, so a reload asks again. Never written to browser storage or a URL.
            Get it from <span className="font-mono">LIBELLA_TOKEN</span> or
            <span className="font-mono"> libella --show-token --data-dir &lt;dir&gt;</span> in a terminal.
          </p>
          <Button type="submit" variant="primary" loading={busy} className="mt-4 w-full">Connect</Button>
        </form>
        <div className="mt-4 flex items-center justify-between px-1 text-xs text-ink-500">
          <span className="inline-flex items-center gap-1.5">
            <ShieldCheck size={13} className={health ? "text-sev-low" : "text-ink-300"} />
            {health ? `Backend ${health.version || ""}` : "Backend unreachable"}
          </span>
          <span>localhost only</span>
        </div>
      </div>
    </div>
  );
}