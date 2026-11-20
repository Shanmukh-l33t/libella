export type TargetKind = "url" | "domain" | "cidr" | "ip";
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
  blob?: { request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string }; response?: { status?: number; headers?: Record<string, string>; body?: string } };
}
export interface EvidenceDetail { id: string; kind: string; sha256: string; content: string }
export interface ChainStatus { ok: boolean; checked: number; head?: string; broken_at?: string; error?: string }
export interface ToolInfo { name: string; description: string; category: string; read_only: boolean; destructive: boolean; available: boolean; parameters?: unknown }
export interface GraphNode { id: string; type: "asset" | "finding" | "intent"; kind: string; label: string; data: Record<string, any> }
export interface GraphEdge { source: string; target: string; kind: string; verified?: boolean }
export interface GraphData { nodes: GraphNode[]; edges: GraphEdge[] }
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
