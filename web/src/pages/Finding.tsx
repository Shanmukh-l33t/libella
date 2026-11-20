import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, CheckCircle2, ChevronRight, RotateCcw, ShieldQuestion, XCircle } from "lucide-react";
import { get, post } from "../api";
import type { ChainStatus, Exchange, Finding as F } from "../types";
import { useApi } from "../lib/hooks";
import { fmtDuration, fmtTime, severityTone, stateTone, title } from "../lib/format";
import {
  Badge, Button, Card, CodeBlock, EmptyState, ErrorNote, Field, Modal, Skeleton, Table, Textarea, cx, useToast,
} from "../components/ui";

export default function Finding() {
  const { id = "" } = useParams();
  const { data, error, loading, reload } = useApi<F>(`/api/findings/${id}`);
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [ruleOut, setRuleOut] = useState(false);
  const [reason, setReason] = useState("");
  const [outcome, setOutcome] = useState<{ kind: "verify" | "retest"; verdict: string; detail: string } | null>(null);
  const [chain, setChain] = useState<ChainStatus | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);

  useEffect(() => {
    const ev = data?.evidence_ids?.[0];
    if (!ev) return;
    let alive = true;
    get<ChainStatus>(`/api/evidence/${ev}/chain`)
      .then((c) => { if (alive) setChain(c); })
      .catch((e) => { if (alive) setChainError(e instanceof Error ? e.message : String(e)); });
    return () => { alive = false; };
  }, [data?.evidence_ids]);

  const run = async (kind: "verify" | "retest") => {
    setBusy(kind);
    setActionError(null);
    setOutcome(null);
    try {
      const res = await post<{ verdict: string; detail: string }>(`/api/findings/${id}/${kind}`);
      setOutcome({ kind, verdict: res.verdict, detail: res.detail });
      toast(`${kind === "verify" ? "Verification" : "Retest"}: ${res.verdict}`, res.verdict === "reproduced" || res.verdict === "fixed" ? "success" : res.verdict === "inconclusive" ? "warning" : "neutral");
      reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const transition = async (state: string, why: string) => {
    setBusy(state);
    setActionError(null);
    try {
      await post(`/api/findings/${id}/state`, { state, reason: why });
      toast(`State changed to ${title(state)}.`, "success");
      setRuleOut(false);
      setReason("");
      reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  if (error) return <div className="space-y-4"><Back id={null} /><ErrorNote error={error} /></div>;
  if (loading && !data) return <div className="space-y-4"><Skeleton className="h-7 w-2/3" /><Skeleton className="h-40 w-full" /></div>;
  if (!data) return <EmptyState title="Finding not found" description="It may have been removed with its engagement." />;

  const f = data;
  const canReport = f.state === "validated";
  const canRemediate = f.state === "reported";

  return (
    <div className="space-y-5">
      <Back id={f.engagement_id} />

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
            <Badge tone={stateTone(f.state)} dot>{title(f.state)}</Badge>
            <span className="text-xs capitalize text-ink-500" title="Confidence">{f.confidence} confidence</span>
            {f.cvss !== null && f.cvss !== undefined && <span className="text-xs text-ink-500">CVSS {f.cvss}</span>}
          </div>
          <h1 className="mt-2 text-xl font-semibold leading-snug tracking-tight text-ink-900">{f.title}</h1>
          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-ink-500">
            <span className="font-mono">{f.id}</span><span>·</span>
            <span>{f.cwe || "CWE n/a"}</span><span>·</span>
            <span>OWASP {f.owasp || "n/a"}</span><span>·</span>
            <span>raised {fmtTime(f.created_at)}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" icon={<ShieldQuestion size={14} />} loading={busy === "verify"} onClick={() => run("verify")}>Verify</Button>
          <Button icon={<RotateCcw size={14} />} loading={busy === "retest"} onClick={() => run("retest")}>Retest</Button>
          {canReport && <Button onClick={() => transition("reported", "operator: marked reported")} loading={busy === "reported"}>Mark reported</Button>}
          {canRemediate && <Button onClick={() => transition("remediated", "operator: remediation applied")} loading={busy === "remediated"}>Mark remediated</Button>}
          <Button variant="danger" icon={<XCircle size={14} />} onClick={() => setRuleOut(true)}>Rule out</Button>
        </div>
      </div>

      <ErrorNote error={actionError} />

      {outcome && (
        <div className={cx("flex items-start gap-2 rounded border px-4 py-3 text-sm",
          outcome.verdict === "reproduced" || outcome.verdict === "fixed" ? "border-[#ABEFC6] bg-[#ECFDF3]"
            : outcome.verdict === "inconclusive" ? "border-[#FEDF89] bg-[#FFFAEB]" : "border-sev-high/30 bg-[#FEF3F2]")}>
          {outcome.verdict === "reproduced" || outcome.verdict === "fixed"
            ? <CheckCircle2 size={16} className="mt-0.5 text-[#027A48]" />
            : <span className="mt-0.5 text-xs font-semibold uppercase text-[#B54708]">!</span>}
          <div>
            <div className="font-medium text-ink-900">{outcome.kind === "verify" ? "Verification" : "Retest"}: {outcome.verdict}</div>
            <div className="text-ink-700">{outcome.detail}</div>
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
        <div className="space-y-4">
          <Card title="Description">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink-700">{f.description || "No description recorded."}</p>
          </Card>
          <Card title="Impact">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink-700">{f.impact || "No impact statement recorded."}</p>
          </Card>
          <Card title="Remediation">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink-700">{f.remediation || "No remediation guidance recorded."}</p>
          </Card>

          <Card title={`Evidence (${f.exchanges?.length || 0} exchanges)`} description="Redacted at rest by the API. Expand an exchange to read the captured request and response." padded={false}>
            {!(f.exchanges || []).length ? (
              <EmptyState title="No exchanges bound" description="This finding has no captured HTTP exchange. Without one it cannot be promoted to validated." />
            ) : (
              <ul className="divide-y divide-line/70">
                {(f.exchanges || []).map((x) => <ExchangeRow key={x.id} x={x} />)}
              </ul>
            )}
          </Card>

          <Card title="Verification history" padded={false}>
            {!(f.verifications || []).length ? (
              <EmptyState title="Not verified yet" description="Run Verify to replay the proof request and independently reproduce the claim." />
            ) : (
              <Table
                rows={f.verifications || []}
                getKey={(v) => v.id || String(v.attempt)}
                columns={[
                  { key: "attempt", label: "Attempt", render: (v) => <span className="tabular-nums">{v.attempt}</span> },
                  { key: "verdict", label: "Verdict", render: (v) => <Badge tone={v.verdict === "reproduced" ? "success" : v.verdict === "not_reproduced" ? "danger" : "warning"}>{v.verdict}</Badge> },
                  { key: "method", label: "Method", render: (v) => <span className="font-mono text-xs text-ink-500">{v.method || "—"}</span> },
                  { key: "detail", label: "Detail", render: (v) => <span className="block max-w-[420px] text-xs text-ink-700">{v.detail || "—"}</span> },
                  { key: "created", label: "When", render: (v) => <span className="whitespace-nowrap text-xs text-ink-500">{fmtTime(v.created_at)}</span> },
                ]}
              />
            )}
          </Card>

          {(f.retests || []).length > 0 && (
            <Card title="Retests" padded={false}>
              <Table
                rows={f.retests || []}
                getKey={(r) => r.id || String(r.created_at)}
                columns={[
                  { key: "verdict", label: "Verdict", render: (r) => <Badge tone={r.verdict === "fixed" ? "success" : r.verdict === "persists" ? "critical" : "warning"}>{r.verdict}</Badge> },
                  { key: "detail", label: "Detail", render: (r) => <span className="text-xs text-ink-700">{r.detail || "—"}</span> },
                  { key: "when", label: "When", render: (r) => <span className="whitespace-nowrap text-xs text-ink-500">{fmtTime(r.created_at)}</span> },
                ]}
              />
            </Card>
          )}
        </div>

        <div className="space-y-4">
          <Card title="Metadata">
            <dl className="space-y-3 text-sm">
              <div><dt className="text-xs text-ink-500">Endpoint</dt><dd className="mt-0.5 break-all font-mono text-xs text-ink-900">{f.endpoint || "—"}</dd></div>
              <div><dt className="text-xs text-ink-500">Confidence</dt><dd className="mt-0.5 capitalize">{f.confidence}</dd></div>
              <div><dt className="text-xs text-ink-500">Dedup key</dt><dd className="mt-0.5 break-all font-mono text-2xs text-ink-500">{f.dedup_key || "—"}</dd></div>
              <div><dt className="text-xs text-ink-500">Updated</dt><dd className="mt-0.5 text-xs">{fmtTime(f.updated_at)}</dd></div>
              <div><dt className="text-xs text-ink-500">Evidence objects</dt><dd className="mt-0.5 font-mono text-2xs text-ink-500 break-all">{(f.evidence_ids || []).join(", ") || "none"}</dd></div>
            </dl>
          </Card>

          <Card title="Evidence integrity" description="Hash-chained ledger for this engagement.">
            {chainError && <ErrorNote error={chainError} />}
            {!chain && !chainError && <Skeleton className="h-10 w-full" />}
            {chain && (
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  {chain.ok ? <CheckCircle2 size={15} className="text-[#027A48]" /> : <XCircle size={15} className="text-sev-high" />}
                  <span className={chain.ok ? "text-[#027A48]" : "text-sev-high"}>{chain.ok ? "Chain intact" : "Chain broken"}</span>
                </div>
                <div className="text-xs text-ink-500">{chain.checked} evidence objects verified{chain.broken_at ? ` · broken at ${chain.broken_at}` : ""}</div>
                {chain.head && <div className="break-all font-mono text-2xs text-ink-500">head {chain.head}</div>}
                {chain.error && <div className="text-xs text-sev-high">{chain.error}</div>}
              </div>
            )}
            {!f.evidence_ids?.length && <p className="mt-2 text-xs text-ink-500">No evidence bound, so there is nothing to verify.</p>}
          </Card>

          <Card title="State rules" description="Ruling out requires a reason and is recorded in the audit trail.">
            <p className="text-xs text-ink-500">
              Promotion to <span className="text-ink-700">validated</span> is only possible through a reproduced verification — the state API rejects it otherwise.
            </p>
          </Card>
        </div>
      </div>

      <Modal open={ruleOut} onClose={() => setRuleOut(false)} title="Rule out this finding"
        footer={<>
          <Button variant="ghost" onClick={() => setRuleOut(false)}>Cancel</Button>
          <Button variant="danger" disabled={!reason.trim()} loading={busy === "ruled_out"} onClick={() => transition("ruled_out", reason.trim())}>Rule out finding</Button>
        </>}>
        <Field label="Reason" htmlFor="reason" required hint="Recorded with the state change. Be specific: duplicate, false positive, out of scope.">
          <Textarea id="reason" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} autoFocus placeholder="e.g. duplicate of finding on /login; same root cause" />
        </Field>
      </Modal>
    </div>
  );
}

function Back({ id }: { id: string | null }) {
  return (
    <Link to={id ? `/engagements/${id}?tab=findings` : "/"} className="inline-flex items-center gap-1 text-xs text-ink-500 hover:text-ink-900">
      <ArrowLeft size={13} /> {id ? "Back to findings" : "All engagements"}
    </Link>
  );
}

function ExchangeRow({ x }: { x: Exchange }) {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<Exchange | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggle = useCallback(async () => {
    if (open) { setOpen(false); return; }
    setOpen(true);
    if (detail) return;
    setLoading(true);
    try {
      setDetail(await get<Exchange>(`/api/exchanges/${x.id}`));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [open, detail, x.id]);

  const req = detail?.blob?.request;
  const res = detail?.blob?.response;

  return (
    <li>
      <button onClick={toggle} aria-expanded={open} className="flex w-full items-center gap-2 px-4 py-2.5 text-left transition-colors hover:bg-ink-100/50">
        <ChevronRight size={13} className={cx("shrink-0 text-ink-500 transition-transform duration-150", open && "rotate-90")} />
        <span className="w-12 shrink-0 font-mono text-xs font-medium">{x.method || "GET"}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-ink-700" title={x.url}>{x.url}</span>
        <span className={cx("w-10 shrink-0 text-right font-mono text-xs tabular-nums", (x.status || 0) >= 400 ? "text-sev-high" : "text-ink-700")}>{x.status ?? "—"}</span>
        <span className="w-12 shrink-0 text-right font-mono text-2xs tabular-nums text-ink-500">{fmtDuration(x.duration_ms)}</span>
        <span className="w-24 shrink-0 text-right text-2xs tabular-nums text-ink-300" title={fmtTime(x.created_at)}>{x.tool || ""}</span>
      </button>
      {open && (
        <div className="space-y-2 bg-canvas px-4 py-3">
          {loading && <Skeleton className="h-24 w-full" />}
          <ErrorNote error={error} />
          {req && <CodeBlock label="request" maxHeight={260} content={`${req.method || "GET"} ${req.url || x.url}\n\n${formatHeaders(req.headers)}\n\n${req.body || ""}`} />}
          {res && <CodeBlock label="response" maxHeight={320} content={`HTTP ${res.status ?? x.status}\n\n${formatHeaders(res.headers)}\n\n${res.body || ""}`} />}
          {detail && !req && <CodeBlock label="exchange" content={JSON.stringify(detail, null, 2)} maxHeight={240} />}
        </div>
      )}
    </li>
  );
}

function formatHeaders(h?: Record<string, string>) {
  if (!h) return "";
  return Object.entries(h).map(([k, v]) => `${k}: ${v}`).join("\n");
}
