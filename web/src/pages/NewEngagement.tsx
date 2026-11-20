import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, Rocket } from "lucide-react";
import { post } from "../api";
import type { Settings, ToolInfo } from "../types";
import { useApi } from "../lib/hooks";
import { Button, ErrorNote, cx, useToast } from "../components/ui";
import {
  EMPTY, STEPS, buildBody, clearDraft, loadDraft, providerReady, saveDraft, validateStep,
  type WizardState,
} from "../lib/wizard";
import TargetType from "./wizard/TargetType";
import Scope from "./wizard/Scope";
import Access from "./wizard/Access";
import Profile from "./wizard/Profile";
import Readiness from "./wizard/Readiness";
import Launch from "./wizard/Launch";

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** The first step that fails validation, so a jump forward lands on the real problem. */
function firstInvalid(s: WizardState, upto: number) {
  for (let i = 0; i <= upto; i++) {
    const errors = validateStep(i, s);
    if (Object.keys(errors).length) return { step: i, errors };
  }
  return null;
}

export default function NewEngagement() {
  const navigate = useNavigate();
  const toast = useToast();
  const [s, setS] = useState<WizardState>(EMPTY);
  const [step, setStep] = useState(0);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"start" | "draft" | null>(null);
  const [draft, setDraft] = useState(() => loadDraft());

  const tools = useApi<ToolInfo[]>("/api/tools");
  const cfg = useApi<Settings>("/api/settings");
  const provider = providerReady(cfg.data?.llm);

  const patch = useCallback((p: Partial<WizardState>) => setS((prev) => ({ ...prev, ...p })), []);

  // A step change moves focus into the new content, so keyboard and screen-reader users are not left in the nav.
  const region = useRef<HTMLElement>(null);
  const moved = useRef(false);
  useEffect(() => {
    if (moved.current) region.current?.focus();
    else moved.current = true;
  }, [step]);

  const go = (to: number) => {
    if (to > step) {
      const bad = firstInvalid(s, step);
      if (bad) { setStep(bad.step); setErrors(bad.errors); setError("Fix the highlighted fields to continue."); return; }
    }
    setError(null);
    setErrors({});
    setStep(to);
    if (to > 0) saveDraft(s, to);
  };

  const next = () => go(Math.min(step + 1, STEPS.length - 1));

  const resume = () => {
    if (!draft?.state) return;
    setS({ ...EMPTY, ...draft.state });
    setStep(Math.min(Math.max(draft.step, 0), STEPS.length - 1));
    setDraft(null);
    setError(null);
  };

  const discard = () => { clearDraft(); setDraft(null); };

  const launch = async (start: boolean) => {
    const bad = firstInvalid(s, 2);
    if (bad) { setStep(bad.step); setErrors(bad.errors); setError("Fix the highlighted fields before creating the engagement."); return; }
    if (start && !provider && s.mode !== "deterministic") {
      setError("That mode needs an AI provider. Configure one in Settings, or start deterministically.");
      return;
    }
    setBusy(start ? "start" : "draft");
    setError(null);
    try {
      const res = await post<{ id: string }>("/api/engagements", buildBody(s));
      const notes: string[] = [];
      if (s.access === "login") {
        try {
          const ctx = await post<{ status?: string; reason?: string }>(`/api/engagements/${res.id}/auth-contexts`, {
            base_url: s.login.base_url.trim(), login_url: s.login.login_url.trim(),
            username: s.login.username.trim(), password: s.login.password,
            ...(s.login.selectors.trim() ? { selectors: JSON.parse(s.login.selectors) } : {}),
            ...(s.login.success.trim() ? { success_assertion: s.login.success.trim() } : {}),
          });
          if (ctx.status !== "active") notes.push(`login flow: ${ctx.reason || ctx.status || "failed"}`);
        } catch (err) { notes.push(`login flow: ${msg(err)}`); }
      }
      if (s.workflow.steps.trim()) {
        try {
          await post(`/api/engagements/${res.id}/workflows`, {
            name: s.workflow.name.trim() || "wizard workflow", steps: JSON.parse(s.workflow.steps),
          });
        } catch (err) { notes.push(`workflow: ${msg(err)}`); }
      }
      if (start) {
        try { await post(`/api/engagements/${res.id}/start`, { mode: s.mode }); }
        catch (err) { notes.push(`start: ${msg(err)}`); }
      }
      clearDraft();
      toast(
        notes.length ? `Engagement ${res.id} created. ${notes.join("; ")}`
          : start ? "Engagement created and started." : "Engagement saved as a draft.",
        notes.length ? "warning" : "success",
      );
      navigate(`/engagements/${res.id}?tab=overview`);
    } catch (err) {
      setError(msg(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <form className="mx-auto max-w-[880px] space-y-5" noValidate
      onSubmit={(e) => { e.preventDefault(); if (step < STEPS.length - 1) next(); else launch(true); }}>
      <div>
        <Link to="/" className="inline-flex items-center gap-1 text-xs text-ink-500 hover:text-ink-900"><ArrowLeft size={13} /> Engagements</Link>
        <h1 className="mt-2 text-xl font-semibold tracking-tight text-ink-900">New engagement</h1>
        <p className="mt-1 text-sm text-ink-500">
          Step {step + 1} of {STEPS.length} · {STEPS[step]} · nothing runs until the last step.
        </p>
      </div>

      {draft && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-accent/30 bg-accent-soft/60 px-4 py-3">
          <p className="min-w-0 text-sm text-ink-700">
            Unsaved draft from {new Date(draft.savedAt).toLocaleString()} — {draft.state.name || "unnamed"}.
            <span className="mt-0.5 block text-xs text-ink-500">Targets, limits and choices only. Credentials are never stored.</span>
          </p>
          <div className="flex gap-2">
            <Button type="button" size="sm" onClick={resume}>Resume draft</Button>
            <Button type="button" size="sm" variant="ghost" onClick={discard}>Discard</Button>
          </div>
        </div>
      )}

      <nav aria-label="Wizard steps" className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 lg:grid-cols-6">
        {STEPS.map((label, i) => (
          <button key={label} type="button" onClick={() => go(i)} aria-current={i === step ? "step" : undefined}
            className={cx("flex items-center gap-2 rounded border px-2.5 py-2 text-left text-xs transition-colors",
              i === step ? "border-accent/40 bg-accent-soft font-medium text-accent"
                : i < step ? "border-line bg-white text-ink-700 hover:border-ink-300"
                  : "border-line bg-white text-ink-500 hover:border-ink-300 hover:text-ink-900")}>
            <span className={cx("flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-2xs tabular-nums",
              i === step ? "bg-accent text-white" : "bg-ink-100 text-ink-500")}>{i + 1}</span>
            <span className="truncate">{label}</span>
          </button>
        ))}
      </nav>

      <ErrorNote error={error} />

      <section ref={region} tabIndex={-1} aria-label={STEPS[step]} className="space-y-4 outline-none">
        {step === 0 && <TargetType s={s} patch={patch} errors={errors} />}
        {step === 1 && <Scope s={s} patch={patch} errors={errors} />}
        {step === 2 && <Access s={s} patch={patch} errors={errors} />}
        {step === 3 && <Profile s={s} patch={patch} />}
        {step === 4 && <Readiness s={s} tools={tools.data} cfg={cfg.data} toolsError={tools.error} />}
        {step === 5 && <Launch s={s} patch={patch} provider={provider} offline={!cfg.loading && !provider} />}
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
        <Button type="button" variant="ghost" disabled={step === 0 || !!busy} onClick={() => go(step - 1)}
          icon={<ArrowLeft size={14} />}>Back</Button>
        <div className="flex flex-wrap items-center gap-2">
          {step >= 3 && (
            <Button type="button" disabled={!!busy} loading={busy === "draft"} onClick={() => launch(false)}>Save as draft</Button>
          )}
          {step < STEPS.length - 1
            ? <Button type="submit" variant="primary" disabled={!!busy}>Next <ArrowRight size={14} /></Button>
            : <Button type="button" variant="primary" icon={<Rocket size={14} />} disabled={!!busy}
                loading={busy === "start"} onClick={() => launch(true)}>Create &amp; start</Button>}
        </div>
      </div>
    </form>
  );
}