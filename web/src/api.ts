import type { Settings, ToolInfo } from "./types";

// In memory only: never persisted to browser storage or echoed into a URL.
// Pre-hardening builds kept the token under this key; drop any leftover copy on load.
try { localStorage.removeItem("libella.token"); } catch { /* storage blocked */ }
let token = "";
export const getToken = () => token;
export const setToken = (t: string) => { token = t.trim(); };
export const clearToken = () => { token = ""; };

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

/** Error bodies carry the actionable reason; a bare status hides it. */
async function failure(res: Response): Promise<ApiError> {
  let msg = `${res.status} ${res.statusText}`;
  try {
    const j = await res.json();
    if (j?.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
  } catch { /* non-JSON error body */ }
  return new ApiError(res.status, msg);
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { Authorization: `Bearer ${getToken()}`, ...(init.headers as Record<string, string>) };
  if (init.body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event("libella:unauthorized"));
    throw new ApiError(401, "invalid token");
  }
  if (!res.ok) throw await failure(res);
  const ct = res.headers.get("content-type") || "";
  return (ct.includes("application/json") ? await res.json() : await res.text()) as T;
}

export const get = <T>(path: string) => api<T>(path);
export const post = <T>(path: string, body?: unknown) => api<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });
export const put = <T>(path: string, body: unknown) => api<T>(path, { method: "PUT", body: JSON.stringify(body) });

export const tools = () => get<ToolInfo[]>("/api/tools");
export const settings = () => get<Settings>("/api/settings");

/** EventSource cannot send headers: a single-use 60s ticket for this engagement's stream. */
export const mintTicket = (eid: string) =>
  post<{ ticket: string }>("/api/ticket", { engagement_id: eid }).then((r) => r.ticket);

/** Downloads use fetch so the bearer header travels instead of a token in the URL. */
export type ReportFormat = "md" | "sarif" | "pdf" | "dojo" | "html" | "docx" | "xlsx" | "csv";
export async function downloadReport(eid: string, format: ReportFormat) {
  const path = `/api/engagements/${encodeURIComponent(eid)}/report?format=${format}`;
  const res = await fetch(path, { headers: { Authorization: `Bearer ${getToken()}` } });
  if (!res.ok) throw await failure(res);
  const href = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = href;
  a.download = format === "dojo" ? `libella-${eid}-defectdojo.json` : `${eid}.${format}`;
  a.click();
  URL.revokeObjectURL(href);
}

/** Query string from defined, non-empty values. */
export function qs(params: Record<string, string | number | undefined | null>) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && String(v) !== "") sp.set(k, String(v));
  const s = sp.toString();
  return s ? `?${s}` : "";
}
