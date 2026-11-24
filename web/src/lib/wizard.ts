import type { TargetKind } from "../types";

export interface Row { kind: TargetKind; value: string; include_subdomains: boolean }
/** Exclusions take a narrower kind set than targets (no repo/image/cloud). */
export type ExclusionKind = "url_prefix" | "domain" | "cidr" | "ip";
export interface ExRow { kind: ExclusionKind; value: string }
export interface Identity { username: string; password: string; login_url: string }
export interface Login { base_url: string; login_url: string; username: string; password: string; success: string; selectors: string }

export interface WizardState {
  /** Preset the operator picked on step 1. Drives the default kind, categories and lab prefill. */
  targetType: string;
  name: string;
  targets: Row[];
  exclusions: ExRow[];
  categories: string[];
  authorized: boolean;
  /** datetime-local values. Converted to ISO on submit. */
  windowStart: string;
  windowEnd: string;
  rps: string;
  concurrency: string;
  duration: string;
  budget: string;
  access: "none" | "login" | "identities";
  identities: Identity[];
  login: Login;
  openapi: string;
  graphql: string;
  hints: string;
  workflow: { name: string; steps: string };
  profileId: string;
  profile: string;
  mode: string;
}

export type Patch = (patch: Partial<WizardState>) => void;

export const STEPS = ["Target type", "Scope", "Access", "Profile", "Readiness", "Start"] as const;

export const TARGET_TYPES = [
  { id: "website", label: "Website", hint: "A running web app you can browse.", kind: "url" as TargetKind,
    placeholder: "https://app.example.com", categories: ["recon", "web"] },
  { id: "rest", label: "REST API", hint: "HTTP endpoints, ideally with an OpenAPI file.", kind: "url" as TargetKind,
    placeholder: "https://api.example.com", categories: ["recon", "api"] },
  { id: "graphql", label: "GraphQL API", hint: "One endpoint, schema behind introspection.", kind: "url" as TargetKind,
    placeholder: "https://app.example.com/graphql", categories: ["recon", "api"] },
  { id: "repo", label: "Source repository", hint: "Static audit of code on this server.", kind: "repo" as TargetKind,
    placeholder: "/srv/app", categories: ["code"] },
  { id: "image", label: "Container image", hint: "Local image tag, scanned for known CVEs.", kind: "image" as TargetKind,
    placeholder: "app:latest", categories: ["code"] },
  { id: "host", label: "Infrastructure host or CIDR", hint: "Ports and service posture.", kind: "cidr" as TargetKind,
    placeholder: "10.0.0.0/24", categories: ["infra"] },
  { id: "cloud", label: "Cloud account", hint: "Read-only AWS posture check.", kind: "cloud" as TargetKind,
    placeholder: "123456789012", categories: ["cloud"] },
  { id: "demo", label: "Local demo lab", hint: "The bundled vulnerable app, for a first run.", kind: "url" as TargetKind,
    placeholder: "http://127.0.0.1:8801", value: "http://127.0.0.1:8801", categories: ["recon", "web"],
    note: "Start the lab first: python labs/pairlab/app.py serves it on 127.0.0.1:8801." },
];

export const CATEGORIES = [
  { id: "recon", label: "Recon", hint: "Host discovery, crawling, content mapping.", tools: ["recon"] },
  { id: "web", label: "Web", hint: "Header, cookie, transport and injection checks.", tools: ["web"] },
  { id: "api", label: "API", hint: "OpenAPI-driven and GraphQL endpoint audits.", tools: ["web"] },
  { id: "infra", label: "Infra", hint: "Service and port posture checks.", tools: ["infra"] },
  { id: "code", label: "Code", hint: "Source audit: semgrep, secrets, dependencies.", tools: ["code"] },
  { id: "cloud", label: "Cloud", hint: "Read-only AWS posture against a scoped endpoint.", tools: [] },
];

export const PROFILES = [
  { id: "quick", label: "Quick", profile: "passive", mode: "deterministic",
    runs: ["Crawl and fingerprint in-scope pages", "Read-only header, cookie, CORS and exposed-path checks", "Static code or image scan when the target is a repo or image"],
    stops: ["No nuclei templates, no port scans", "No injection probes", "No authenticated API audit"] },
  { id: "standard", label: "Standard", profile: "safe_active", mode: "deterministic",
    runs: ["Everything Quick runs", "Nuclei templates and port posture", "API and GraphQL audits with a spec or endpoint", "Non-destructive injection probes (XSS, SQLi, SSTI, SSRF, IDOR)"],
    stops: ["Nothing that writes or deletes data on the target", "No agent reasoning loops"] },
  { id: "prod", label: "Production-safe", profile: "production_safe", mode: "deterministic",
    runs: ["The passive surface only, labelled for a live production system", "Every refusal is recorded as a policy restriction, not a clean result"],
    stops: ["No active checks at all: no scanners, no injection probes", "Use this when the target must stay strictly read-only"] },
  { id: "deep", label: "Deep", profile: "advanced_validation", mode: "agent",
    runs: ["Everything Standard runs", "AI specialist agent loops (web, api, authz, infra) that plan extra checks", "Agents are told the scope authorizes independent replay validation"],
    stops: ["Needs a configured AI provider: without one, starting is refused (choose Standard)", "Still bounded by rate, concurrency and the declared window"] },
  { id: "custom", label: "Custom", profile: "safe_active", mode: "deterministic",
    runs: ["Pick the policy ceiling yourself", "Pick the execution mode on the start step"],
    stops: ["No presets: an unauthorised combination is refused at start"] },
];

export const MODES = [
  { id: "deterministic", label: "Deterministic", hint: "Fixed pipeline. No model, fully repeatable." },
  { id: "llm", label: "LLM planner", hint: "A model proposes intents inside the compile gate." },
  { id: "agent", label: "Agent", hint: "Specialist reasoning loops. Needs a provider." },
];

export const EXCLUSION_KINDS: ExclusionKind[] = ["url_prefix", "domain", "cidr", "ip"];

const row = (kind: TargetKind, value = ""): Row => ({ kind, value, include_subdomains: false });

export const EMPTY: WizardState = {
  targetType: "",
  name: "",
  targets: [row("url")],
  exclusions: [],
  categories: ["recon", "web"],
  authorized: false,
  windowStart: "",
  windowEnd: "",
  rps: "10",
  concurrency: "4",
  duration: "",
  budget: "",
  access: "none",
  identities: [],
  login: { base_url: "", login_url: "", username: "", password: "", success: "", selectors: "" },
  openapi: "",
  graphql: "",
  hints: "",
  workflow: { name: "", steps: "" },
  profileId: "standard",
  profile: "safe_active",
  mode: "deterministic",
};

/* ------------------------------- validation -------------------------------- */

const IPV4 = (v: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v) && v.split(".").every((o) => Number(o) <= 255);
const IPV6 = (v: string) => v.includes(":") && /^[0-9a-f:]+$/i.test(v);
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

/** The server is the authority; this only catches what is wrong before the round trip. */
export function targetError(kind: TargetKind | ExclusionKind, raw: string): string | null {
  const v = raw.trim();
  if (!v) return "Add a value or remove this row.";
  switch (kind) {
    case "url":
      return /^https?:\/\/[^\s/?#]+(\/[^\s]*)?$/i.test(v) ? null : "Needs a full http:// or https:// URL.";
    case "domain":
      return HOSTNAME.test(v) ? null : "Bare hostname only, e.g. app.example.com.";
    case "ip":
      return IPV4(v) || IPV6(v) ? null : "Not an IP address.";
    case "cidr":
      if (/^[0-9a-f:.]+\/\d{1,3}$/i.test(v)) return null;
      return "Use CIDR, e.g. 10.0.0.0/24 (one host is 10.0.0.5/32).";
    case "repo":
      return v.startsWith("/") && !v.split("/").includes("..") ? null : "An absolute path on the server, e.g. /srv/app.";
    case "image":
      return /[ ;|&$`\n\r\t]/.test(v) ? "No spaces or shell characters." : null;
    case "cloud":
      if (/^\d{12}$/.test(v)) return null;
      return /^https?:\/\/[^\s/?#]+/i.test(v) ? null : "A 12-digit account id or an http(s) endpoint URL.";
    case "url_prefix":
      return /^https?:\/\/[^\s/?#]+/i.test(v) ? null : "An http:// or https:// prefix.";
    default:
      return null;
  }
}

export const iso = (local: string) => (local ? new Date(local).toISOString() : undefined);

/** Errors keyed by field, for the step being left. Empty object means the step passes. */
export function validateStep(i: number, s: WizardState): Record<string, string> {
  const e: Record<string, string> = {};
  if (i === 0 && !s.targetType) e.targetType = "Pick what you are assessing.";
  if (i === 1) {
    const filled = s.targets.filter((t) => t.value.trim());
    if (!filled.length) e.targets = "At least one in-scope target. Scope is fail-closed: nothing runs without it.";
    else {
      const bad = s.targets.findIndex((t) => targetError(t.kind, t.value));
      if (bad >= 0) e.targets = `Target ${bad + 1}: ${targetError(s.targets[bad].kind, s.targets[bad].value)}`;
    }
    const badEx = s.exclusions.findIndex((x) => targetError(x.kind, x.value));
    if (badEx >= 0) e.exclusions = `Exclusion ${badEx + 1}: ${targetError(s.exclusions[badEx].kind, s.exclusions[badEx].value)}`;
    if (!(Number(s.rps) > 0)) e.rps = "Rate must be greater than 0.";
    if (!(Number.isInteger(Number(s.concurrency)) && Number(s.concurrency) > 0)) e.concurrency = "Concurrency must be a whole number above 0.";
    if (s.duration && !(Number(s.duration) > 0)) e.duration = "Duration must be a positive number of seconds.";
    if (s.budget && !(Number(s.budget) > 0)) e.budget = "Budget must be a positive number.";
    if (!s.authorized) e.authorized = "Confirm you are authorized to test these targets.";
    if (!s.name.trim()) e.name = "Name the engagement so you can find it later.";
    if (s.windowStart && s.windowEnd && new Date(s.windowStart) >= new Date(s.windowEnd)) {
      e.window = "The window must end after it starts.";
    }
  }
  if (i === 2) {
    if (s.access === "login") {
      if (!(s.login.base_url.trim() && s.login.login_url.trim() && s.login.username.trim())) {
        e.login = "A login flow needs a base URL, a login URL and a username (password optional).";
      } else on(e, "login", urlError(s.login.base_url) || urlError(s.login.login_url));
    }
    if (s.access === "identities" && !s.identities.some((x) => x.username.trim())) {
      e.identities = "Add at least one account, or set access to none.";
    }
    if (s.openapi.trim() && !s.openapi.trim().startsWith("/")) e.openapi = "A server-side path, e.g. /srv/spec/openapi.json.";
    if (s.graphql.trim()) on(e, "graphql", urlError(s.graphql));
    on(e, "hints", jsonError(s.hints));
    on(e, "steps", stepsError(s.workflow.steps));
    on(e, "selectors", s.login.selectors.trim() ? jsonError(s.login.selectors) : null);
  }
  return e;
}

const on = (e: Record<string, string>, key: string, msg: string | null) => { if (msg) e[key] = msg; };
const urlError = (v: string) => (/^https?:\/\/[^\s/?#]+/i.test(v.trim()) ? null : "Needs an http:// or https:// URL.");

function jsonError(raw: string): string | null {
  if (!raw.trim()) return null;
  try { JSON.parse(raw); return null; } catch { return "Not valid JSON."; }
}

function stepsError(raw: string): string | null {
  if (!raw.trim()) return null;
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) && v.length ? null : "Steps must be a non-empty array of actions.";
  } catch { return "Not valid JSON."; }
}

/* --------------------------------- payload -------------------------------- */

export interface Body {
  name: string;
  scope: {
    targets: { kind: TargetKind; value: string; include_subdomains?: boolean }[];
    exclusions: { kind: ExclusionKind; value: string }[];
    categories: string[];
    rate_limit_rps: number;
    max_concurrency: number;
    advanced_validation: boolean;
  };
  profile: string;
  budgets: { max_duration_s?: number; max_usd?: number };
  auth: Record<string, unknown>;
  window_start?: string;
  window_end?: string;
}

/** The exact POST /api/engagements body, built from validated state only. */
export function buildBody(s: WizardState): Body {
  const advanced = s.profile === "advanced_validation";
  const hints = s.hints.trim() ? JSON.parse(s.hints) : undefined;
  const body: Body = {
    name: s.name.trim(),
    scope: {
      targets: s.targets.filter((t) => t.value.trim()).map((t) => ({
        kind: t.kind, value: t.value.trim(),
        ...(t.kind === "domain" && t.include_subdomains ? { include_subdomains: true } : {}),
      })),
      exclusions: s.exclusions.filter((x) => x.value.trim()).map((x) => ({ kind: x.kind, value: x.value.trim() })),
      categories: s.categories,
      rate_limit_rps: Number(s.rps),
      max_concurrency: Number(s.concurrency),
      advanced_validation: advanced,
    },
    profile: s.profile,
    budgets: {
      ...(s.duration ? { max_duration_s: Number(s.duration) } : {}),
      ...(s.budget ? { max_usd: Number(s.budget) } : {}),
    },
    auth: {
      identities: s.access === "identities"
        ? s.identities.filter((i) => i.username || i.password || i.login_url)
          .map((i) => ({ username: i.username, password: i.password, login_url: i.login_url }))
        : [],
      ...(s.openapi.trim() ? { openapi: s.openapi.trim() } : {}),
      ...(s.graphql.trim() ? { graphql: s.graphql.trim() } : {}),
      ...(hints !== undefined ? { test_hints: hints } : {}),
    },
  };
  const start = iso(s.windowStart), end = iso(s.windowEnd);
  if (start) body.window_start = start;
  if (end) body.window_end = end;
  return body;
}

/* --------------------------------- drafts --------------------------------- */

const DRAFT_KEY = "libella.wizard.draft.v1";

/** Non-secret fields only: identities, login fields, hints and workflow steps are dropped (they can hold credentials). */
export function saveDraft(s: WizardState, step: number) {
  const state: Partial<WizardState> = {
    targetType: s.targetType, name: s.name, targets: s.targets, exclusions: s.exclusions,
    categories: s.categories, authorized: s.authorized, windowStart: s.windowStart,
    windowEnd: s.windowEnd, rps: s.rps, concurrency: s.concurrency, duration: s.duration,
    budget: s.budget, access: s.access === "identities" ? "none" : s.access, openapi: s.openapi,
    graphql: s.graphql, profileId: s.profileId, profile: s.profile, mode: s.mode,
  };
  try { localStorage.setItem(DRAFT_KEY, JSON.stringify({ step, savedAt: Date.now(), state })); }
  catch { /* storage blocked */ }
}

export function loadDraft(): { state: Partial<WizardState>; step: number; savedAt: number } | null {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    if (!raw) return null;
    const d = JSON.parse(raw);
    return d?.state && typeof d.state === "object" && typeof d.savedAt === "number" ? d : null;
  } catch { return null; }
}

export const clearDraft = () => { try { localStorage.removeItem(DRAFT_KEY); } catch { /* storage blocked */ } };

/* -------------------------------- readiness ------------------------------- */

export const toolTypes = (cats: string[]) =>
  [...new Set(CATEGORIES.filter((c) => cats.includes(c.id)).flatMap((c) => c.tools))];

export const providerReady = (llm?: { api_key?: string; base_url?: string } | null) =>
  !!(llm?.api_key === "[SET]" || (llm?.api_key && llm.api_key !== ""));

/** Everything that will not work as chosen, in plain language and with the consequence. */
export function warnings(s: WizardState, tools: { name: string; available: boolean; category: string }[] | null, provider: boolean, hasTarget: (k: string) => boolean): string[] {
  const out: string[] = [];
  const cats = s.categories;
  const missing = (tools || []).filter((t) => !t.available && toolTypes(cats).includes(t.category)).map((t) => t.name);
  if (tools && missing.length) out.push(`${missing.join(", ")} not installed: those checks are skipped and recorded as degradations, so coverage is smaller than the report implies.`);

  if (cats.includes("api") && !s.openapi.trim()) out.push("API category without an OpenAPI file: endpoint discovery falls back to crawling, and schema checks (BOLA, BFLA, mass assignment) cannot run.");
  if (cats.includes("api") && s.access !== "identities" && !s.login.base_url) out.push("API category without a test account: only unauthenticated surface is assessed.");
  if (s.graphql.trim() && !cats.includes("api")) out.push("A GraphQL endpoint is set but the API category is off, so the GraphQL audit will not run.");
  if (cats.includes("infra") && !(hasTarget("ip") || hasTarget("cidr"))) out.push("Infra category without a host, IP or CIDR target: a URL authorises only its own host and port, so port scans are skipped.");
  if (cats.includes("code") && !(hasTarget("repo") || hasTarget("image"))) out.push("Code category without a repository or image target: static audit has nothing to read.");
  if (cats.includes("cloud") && !hasTarget("cloud")) out.push("Cloud category without a cloud account target: the posture check is skipped.");
  if (s.profile === "passive" && cats.includes("api")) out.push("Quick profile refuses API and GraphQL audits (they need Standard): they are skipped as policy restrictions, not as clean results.");
  if (s.profile === "production_safe" && cats.some((c) => ["infra", "api"].includes(c))) out.push("Production-safe refuses scanners and active probes, so the infra and API categories will be skipped.");
  if (!provider && (s.mode === "agent" || s.mode === "llm")) out.push("No AI provider configured: the run is refused in agent or planner mode. Start it deterministically or configure a provider in Settings.");
  if (s.access === "login") out.push("The login flow is attempted once, right after creation. If it fails, the run continues unauthenticated and the report records that limit.");
  return out;
}

/* --------------------------------- presets -------------------------------- */

export function applyType(s: WizardState, id: string): Partial<WizardState> {
  const t = TARGET_TYPES.find((x) => x.id === id);
  if (!t) return { targetType: id };
  const first: Row = { kind: t.kind, value: t.value || "", include_subdomains: false };
  return {
    targetType: id,
    targets: [first],
    exclusions: [],
    categories: [...t.categories],
    access: s.access,
  };
}

export function applyProfile(id: string): Partial<WizardState> {
  const p = PROFILES.find((x) => x.id === id);
  if (!p) return { profileId: id };
  return { profileId: id, profile: p.profile, mode: p.mode };
}