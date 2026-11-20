export type TargetKind = "url" | "domain" | "cidr" | "ip" | "repo" | "image" | "cloud";
export interface Target { kind: TargetKind; value: string; include_subdomains?: boolean }
export interface Scope { targets: Target[]; exclusions: Target[]; allowed_ports?: number[]; categories: string[]; rate_limit_rps?: number; max_concurrency?: number; advanced_validation?: boolean }
export interface Identity { username?: string; password?: string; login_url?: string; username_field?: string; password_field?: string }

export interface Engagement {
  id: string; name: string; profile: string; status: string;
  scope: Scope; budgets: { max_duration_s?: number; max_usd?: number };
  auth: { identities: Identity[]; test_hints?: unknown };
  objectives_json?: string;
  created_at: number; started_at?: number | null; finished_at?: number | null;
  status_detail?: string | null;
  spend?: { cost_usd?: number; input_tokens?: number; output_tokens?: number };
  summary?: number;
}

export interface Finding {
  id: string; engagement_id: string; title: string; cwe?: string | null; owasp?: string | null;
  severity: string; cvss?: number | null; confidence: string; endpoint?: string | null;
  state: string; description?: string | null; impact?: string | null; remediation?: string | null;
  dedup_key?: string; evidence_ids: string[]; created_at: number; updated_at?: number;
  owner?: string | null; remediation_notes?: string | null; fix_commit?: string | null;
  remediated_at?: number | null;
  verifications?: Verification[]; retests?: Retest[]; exchanges?: Exchange[];
}

export interface Verification { id?: string; finding_id?: string; attempt: number; method?: string; verdict: string; detail?: string; created_at?: number; replay_exchange_id?: string | null }
export interface Retest { id?: string; finding_id?: string; exchange_id?: string | null; verdict: string; detail?: string; created_at?: number }

export interface Asset { id: string; engagement_id: string; kind: string; key: string; value: Record<string, unknown>; parent_id?: string | null; discovered_by?: string | null; first_seen?: number; last_seen?: number }
export interface Intent { id: string; engagement_id: string; role: string; objective: string; status: string; attempts: number; depends_on: string[]; informed_by?: string[]; created_at?: number; finished_at?: number; result?: unknown }
export interface ToolCall { id: string; engagement_id: string; intent_id?: string | null; tool: string; argv: string[]; target?: string | null; scope_decision?: string | null; exit_code?: number | null; duration_ms?: number | null; error?: string | null; created_at?: number }
export interface Event { seq: number; engagement_id?: string; kind: string; payload: Record<string, any>; created_at?: number }
export interface Exchange {
  id: string; engagement_id: string; evidence_id?: string | null; method?: string; url?: string;
  status?: number | null; duration_ms?: number | null; tool?: string; peer_ip?: string; created_at?: number;
  req_headers_json?: string; resp_headers_json?: string; req_body?: string;
  replay_of?: string | null; tags_json?: string | null;
  blob?: { request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string }; response?: { status?: number; headers?: Record<string, string>; body?: string } };
}
export interface EvidenceDetail { id: string; kind: string; sha256: string; content: string }
export interface ChainStatus { ok: boolean; checked: number; head?: string; broken_at?: string; error?: string }
export interface ToolInfo {
  name: string; description: string; category: string; read_only: boolean; destructive: boolean;
  available: boolean; parameters?: { type?: string; properties?: Record<string, unknown>; required?: string[] };
}

export type GraphNodeType =
  | "asset" | "endpoint" | "auth_context" | "intent" | "agent_run"
  | "observation" | "evidence" | "hypothesis" | "finding" | "verification" | "retest";

export interface GraphNode { id: string; type: GraphNodeType; kind: string; label: string; data: Record<string, any> }
export interface GraphEdge { source: string; target: string; kind: string; verified?: boolean }
export interface GraphTimelineStep { seq: number; kind: string; summary: string; run_id?: string | null; at?: number | null }
export interface GraphCoverage {
  assets_total: number; assets_investigated: number; findings: number; validated: number;
  hypotheses_open: number; agent_runs: number;
}
export interface GraphData {
  nodes: GraphNode[]; edges: GraphEdge[];
  timeline?: GraphTimelineStep[]; coverage?: GraphCoverage;
}

export interface AgentRun {
  id: string; engagement_id: string; intent_id?: string | null; role: string; model?: string | null;
  status: string; iterations: number; tokens_in: number; tokens_out: number; cost_usd: number;
  started_at?: number | null; finished_at?: number | null; summary?: string | null; exit_reason?: string | null;
}

export interface InvestigationStep {
  id: string; engagement_id: string; intent_id?: string | null; agent_run_id?: string | null;
  seq: number; action_kind: string; summary?: string | null; tool_call_id?: string | null;
  observation_id?: string | null; evidence_id?: string | null; hypothesis_id?: string | null;
  model?: string | null; tokens?: number; created_at?: number | null;
}

export interface Hypothesis {
  id: string; engagement_id: string; asset_id?: string | null; intent_id?: string | null;
  kind?: string | null; statement: string; status: string; confidence: number;
  created_by?: string | null; created_at?: number | null; updated_at?: number | null;
}

export interface TrafficItem {
  id: string; method?: string; url?: string; status?: number | null; tool?: string;
  duration_ms?: number | null; peer_ip?: string; evidence_id?: string | null;
  replay_of?: string | null; tags_json?: string | null; created_at?: number | null; match?: string;
}
export interface TrafficPage {
  items: TrafficItem[]; page: number; page_size: number; total: number; pages: number;
  scanned?: number; scan_truncated?: boolean;
}

export interface ExchangeDetail extends Exchange {
  req_headers?: Record<string, string>; resp_headers?: Record<string, string>;
  replay_of?: string | null; tags_json?: string | null;
}

export interface ReplayDiff {
  status_original?: number | null; status_replay?: number | null; status_changed?: boolean;
  length_original?: number; length_replay?: number; length_delta?: number;
  body_identical?: boolean; similarity?: number; truncated_compare?: boolean;
}
export interface ReplayResult {
  ok: boolean; exchange_id?: string; evidence_id?: string; diff?: ReplayDiff;
  url?: string; error?: string; body?: string; status?: number;
}

export interface CorrelationGroup {
  endpoint: string; requests: number; methods: string[]; statuses: Record<string, number>;
  tools: string[]; exchange_ids: string[]; evidence_ids: string[]; first_seen?: number; last_seen?: number;
  findings: { id: string; title: string; severity: string; state: string; endpoint?: string }[];
  observations: { id: string; kind: string; summary: string }[];
}
export interface Correlation { groups: CorrelationGroup[]; endpoints: number; exchanges: number }

export interface AuthContext {
  id: string; engagement_id: string; name?: string | null; username?: string | null;
  status: string; last_verified_at?: number | null; created_at?: number | null;
  login_flow?: Record<string, unknown>; cookie_count?: number;
  evidence_id?: string; reason?: string;
}
export interface Workflow {
  id: string; engagement_id: string; name?: string; auth_context_id?: string | null;
  steps?: WorkflowStep[]; steps_json?: string; status: string; created_at?: number;
}
export interface WorkflowStep { action: string; selector?: string; value?: string; url?: string }

export interface MemoryFact {
  id: string; target_key: string; kind: string; value_json?: string; source_engagement_id?: string;
  confidence?: number; first_seen?: number; last_seen?: number;
}

export interface CompareResult {
  a: { id: string; name: string; findings: number };
  b: { id: string; name: string; findings: number };
  new: Finding[];
  fixed: Finding[];
  persisting: Finding[];
  severity_changed: (Finding & { previous_severity?: string; direction?: "worse" | "better" })[];
  counts: { new: number; fixed: number; persisting: number; severity_changed: number };
  retest_verdicts?: Record<string, string[]>;
}

export interface RemediationBoard {
  engagement_id: string;
  columns: { status: string; label: string; findings: Finding[] }[];
  counts: Record<string, number>;
  total: number;
}
export interface Report {
  engagement: { id: string; name: string; status: string; profile: string; started_at?: number; finished_at?: number; status_detail?: string };
  scope: Scope;
  summary: Record<string, number | Record<string, number>>;
  findings: Finding[];
  degradations: { code: string; detail: string }[];
  generated_at: number;
}
export interface Settings { llm: { base_url?: string; api_key?: string; default_model?: string; models?: Record<string, string>; fallback?: string[] } }

export type Tone = "neutral" | "accent" | "success" | "warning" | "danger" | "critical" | "info";
