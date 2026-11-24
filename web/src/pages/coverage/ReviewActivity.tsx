import { useState } from "react";
import { post } from "../../api";
import { Badge, Button, ErrorNote, Input, CodeBlock } from "../../components/ui";
import { fmtTime } from "../../lib/format";
import { useApi } from "../../lib/hooks";
import type { ExchangeDetail } from "../../types";
import type { Item } from "./model";

interface History {
  reviews: { seq: number; created_at: number; status: string; note?: string }[];
  links: { id: number; created_at: number; action: string; finding_id: string; note: string }[];
  samples: { seq: number; created_at: number; exchange_id: string; outcome: string; reason: string }[];
}

export default function ReviewActivity({ path, item, revision, onSaved }: {
  path: string; item: Item; revision: number; onSaved: () => void;
}) {
  const history = useApi<History>(`${path}/history?revision=${revision}`);
  const [selected, select] = useState("");
  const sample = useApi<ExchangeDetail>(selected ? `/api/exchanges/${encodeURIComponent(selected)}` : null);
  const [capture, setCapture] = useState("");
  const [sensitive, setSensitive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const exchanges = item.evidence.exchanges;
  const check = async () => {
    setError(null); setBusy(true);
    try {
      await post(`${path}/sample`, { exchange_id: capture.trim(), sensitive });
      onSaved();
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  };

  return <div className="space-y-4">
    {item.automatic.test && <section className="space-y-2 rounded border border-line px-3 py-2">
      <h3 className="text-2xs uppercase tracking-wide text-ink-500">Check a captured response</h3>
      <p className="text-xs text-ink-700">{item.automatic.prerequisite} {item.automatic.test} No request is replayed.</p>
      <Input aria-label="Captured exchange ID" placeholder="Exchange ID from Traffic" value={capture}
        onChange={(e) => { setCapture(e.target.value); setSensitive(false); }} />
      <label className="flex items-center gap-2 text-xs text-ink-700">
        <input type="checkbox" checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} />
        The captured response contains sensitive data
      </label>
      <Button onClick={check} disabled={busy || !capture.trim() || !sensitive}>
        {busy ? "Checking…" : "Evaluate sample"}
      </Button>
      <ErrorNote error={error} />
    </section>}
    <section className="space-y-2" aria-label="Captured evidence">
      <h3 className="text-2xs uppercase tracking-wide text-ink-500">Captured evidence</h3>
      {exchanges.length ? <select className="w-full rounded border border-line p-2 text-xs" aria-label="Inspect exchange"
        value={selected} onChange={(e) => select(e.target.value)}>
        <option value="">Inspect an HTTP exchange…</option>
        {exchanges.map((id) => <option key={id}>{id}</option>)}
      </select> : <p className="text-xs text-ink-500">No HTTP capture is attributed to this requirement.</p>}
      {selected && <ErrorNote error={sample.error} />}
      {selected && sample.data?.id === selected && <div className="space-y-1 break-all text-xs text-ink-700">
        <p>{sample.data.method} {sample.data.url} · HTTP {sample.data.status}</p>
        {sample.data.evidence_id && <p className="font-mono">{sample.data.evidence_id}</p>}
        <CodeBlock content={JSON.stringify(sample.data.resp_headers || {}, null, 2)} />
      </div>}
    </section>
    <section aria-label="Review history" className="space-y-2">
      <h3 className="text-2xs uppercase tracking-wide text-ink-500">Review history</h3>
      <ErrorNote error={history.error} />
      {history.loading && !history.data && <p className="text-xs text-ink-500">Loading history…</p>}
      {history.data && <ul className="space-y-2 text-xs text-ink-700">
        {!history.data.samples.length && !history.data.reviews.length && !history.data.links.length && <li>No recorded history.</li>}
        {[...history.data.samples].reverse().map((s) => <li key={`sample-${s.seq}`} className="break-words">
          <Badge tone={s.outcome === "deviation" ? "warning" : "neutral"}>{s.outcome}</Badge>{" "}
          {fmtTime(s.created_at)} · <button className="link" onClick={() => select(s.exchange_id)}>{s.exchange_id}</button> · {s.reason}
        </li>)}
        {[...history.data.reviews].reverse().map((r) => <li key={`review-${r.seq}`} className="break-words">
          <time>{fmtTime(r.created_at)}</time> · {r.status === "unknown" ? "Review cleared" : r.status}{r.note && ` · ${r.note}`}
        </li>)}
        {[...history.data.links].reverse().map((r) => <li key={`link-${r.id}`} className="break-words">
          <time>{fmtTime(r.created_at)}</time> · {r.action} {r.finding_id} · {r.note}
        </li>)}
      </ul>}
    </section>
  </div>;
}
