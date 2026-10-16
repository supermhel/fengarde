// Data layer: the same same-origin /api/* routes nginx proxies for the legacy
// console (services/ws7-dashboard/templates/default.conf.template). No mocks:
// an unreachable backend yields `ok:false` and the views say so.

import { DEMO } from "../demo/flag";

export type Level = "critical" | "high" | "medium" | "low" | "info" | string;

export interface Mitre { tactic?: string; technique?: string; tactics?: string[]; techniques?: string[] }

/** Normalize the single- and list-valued MITRE shapes the backends emit. */
export function mitreTags(m: Mitre | null | undefined): { tactics: string[]; techniques: string[] } {
  if (!m) return { tactics: [], techniques: [] };
  return {
    tactics: [...(m.tactics || []), ...(m.tactic ? [m.tactic] : [])],
    techniques: [...(m.techniques || []), ...(m.technique ? [m.technique] : [])],
  };
}

export interface Alert {
  alert_id: string;
  rule_id?: string;
  rule_title: string;
  level: Level;
  score?: number;
  time: number;
  sector?: string;
  tenant_id?: string;
  src_endpoint?: { ip?: string; hostname?: string };
  dst_endpoint?: { ip?: string; hostname?: string; port?: number };
  actor?: { user?: { name?: string } };
  mitre?: Mitre | null;
  event_ids?: string[];
  triage?: { status?: string; note?: string; updated_by?: string; updated_at?: number };
  ai?: { engine?: string; level?: string; model?: string | null; summary?: string; verdict?: string };
}

export interface OcsfEvent {
  time: number;
  class_uid?: number;
  activity_id?: number;
  type_uid?: number;
  severity_id?: number;
  status?: string;
  message?: string;
  src_endpoint?: { ip?: string; hostname?: string };
  dst_endpoint?: { ip?: string; port?: number };
  actor?: { user?: { name?: string } };
  metadata?: { uid?: string; original_event_uid?: string; product?: { name?: string } };
  siem?: { source_type?: string; sector?: string; ingest_id?: string; tenant?: string };
  [k: string]: unknown;
}

export interface Incident {
  incident_id: string;
  entity_type: string;
  entity_value: string;
  first_seen: number;
  last_seen: number;
  member_alert_ids: string[];
  member_count: number;
  severity: number;
  tactics: string[];
  tenant_id?: string;
  truncated?: boolean;
}

export interface GraphNode { entity_id: string; entity_type: string; entity_value: string; label?: string }
export interface GraphEdge { from: string; to: string; kind: string; ts_ms?: number; event_id?: string }
export interface IncidentGraph { nodes: GraphNode[]; edges: GraphEdge[]; incident_id: string }
export interface EvidencePackage {
  package_id: string; incident_id: string; built_at_ms: number;
  blocks: { block_id: string; content?: unknown; header_hash?: string }[];
  chain?: unknown;
}

export interface Rule {
  id: string; title: string; level: Level; sector?: string; score_weight?: number;
  enabled?: boolean; default_enabled?: boolean; opt_in?: boolean; stateful?: boolean;
  mitre?: Mitre | null;
}

export interface OpsMetrics { service: string; topics: Record<string, Record<string, number>>; extra: Record<string, unknown> }
export interface Asset {
  mac: string; hostname?: string; ip_current?: string; sector?: string; type?: string; status?: string;
  protocols_seen?: string[]; last_seen?: string; first_seen?: string; tenant_id?: string;
  ip_history?: { ip: string; from?: string; to?: string | null }[];
}
export interface ApiKeyMeta { key_id: string; tenant_id: string; scope?: string; source?: string; created_at?: string; last_used_at?: string | null }
export interface AuditEntry { ts: string; event: string; actor: string; tenant_id?: string | null; detail?: Record<string, unknown> }
export interface UserRow { username: string; role: string; tenant_id: string; created_at?: string; last_login_at?: number | null; /* epoch seconds */ mfa_active: boolean; disabled: boolean }
export interface WebhookRow { id: string; scheme: string; host: string; tenant_id?: string; min_score?: number; secret_env: string; enabled: boolean }
export interface Session { username: string; role: string; tenant_id: string; csrf_token?: string }

export type Result<T> = { ok: true; data: T } | { ok: false; status: number; reason: string };

declare global { interface Window { FENGARDE_API_KEY?: string } }

let csrf: string | null = null;
let tenant: string | null = null;
/** Tenant scope for the tenant-aware routes (rules, incidents, inventory), like the classic console's tenantQuery(). */
export const setTenant = (t: string | null) => { tenant = t; };
const tq = (sep: "?" | "&") => (tenant ? `${sep}tenant_id=${encodeURIComponent(tenant)}` : "");
export const setCsrf = (t: string | null) => { csrf = t; };

function headers(extra: Record<string, string> = {}): Record<string, string> {
  const h: Record<string, string> = { Accept: "application/json", ...extra };
  if (window.FENGARDE_API_KEY) h["X-Api-Key"] = window.FENGARDE_API_KEY;
  if (csrf) h["X-CSRF-Token"] = csrf;
  return h;
}

async function call<T>(path: string, init: RequestInit = {}): Promise<Result<T>> {
  if (DEMO) return (await import("../demo/adapter")).demoCall(path, init) as Promise<Result<T>>;
  try {
    const r = await fetch(path, {
      credentials: "same-origin", ...init,
      headers: headers((init.headers as Record<string, string>) || {}),
    });
    if (!r.ok) {
      let reason = r.statusText || `HTTP ${r.status}`;
      try { const b = await r.json(); reason = b.error || b.detail || reason; } catch { /* non-JSON error body */ }
      return { ok: false, status: r.status, reason };
    }
    return { ok: true, data: (await r.json()) as T };
  } catch (e) {
    return { ok: false, status: 0, reason: "backend unreachable" };
  }
}

type Hits<T> = { hits?: { hits?: { _source?: T }[] }; _fengarde_proxy?: string };

function unwrap<T>(r: Result<Hits<T>>): Result<T[]> {
  if (!r.ok) return r;
  if (r.data._fengarde_proxy === "opensearch_unavailable") return { ok: false, status: 503, reason: "OpenSearch unavailable" };
  return { ok: true, data: (r.data.hits?.hits || []).map((h) => h._source).filter(Boolean) as T[] };
}

export const api = {
  me: () => call<Session>("/api/auth/me"),
  // totp_code is only sent when given: WS-3 answers a missing/wrong code with the same uniform 401 as a bad password.
  login: (username: string, password: string, totp_code?: string) =>
    call<Session>("/api/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(totp_code ? { username, password, totp_code } : { username, password }),
    }),
  logout: () => call<unknown>("/api/auth/logout", { method: "POST" }),

  alerts: async (gte: number) => unwrap(await call<Hits<Alert>>(`/api/alerts?gte=${gte}`)),
  events: async (gte: number) => unwrap(await call<Hits<OcsfEvent>>(`/api/events?gte=${gte}`)),
  aiTriage: async () => unwrap(await call<Hits<Alert>>("/api/ai-triage")),
  incidents: () => call<{ incidents: Incident[]; count: number }>(`/api/incidents${tq("?")}`),
  incidentGraph: (id: string) => call<IncidentGraph>(`/api/incidents/${encodeURIComponent(id)}/graph${tq("?")}`),
  incidentEvidence: (id: string) => call<EvidencePackage>(`/api/incidents/${encodeURIComponent(id)}/evidence${tq("?")}`),
  rules: () => call<{ rules: Rule[]; count: number }>(`/api/rules${tq("?")}`),
  assets: () => call<Asset[]>(`/api/inventory/assets?limit=200${tq("&")}`),
  asset: (mac: string) => call<Asset>(`/api/inventory/assets/${encodeURIComponent(mac)}${tq("?")}`),
  keys: () => call<{ keys: ApiKeyMeta[] }>("/api/inventory/keys"),
  // Admin manual device add: WS-3 session route (nginx /api/inventory/ is GET-only).
  addAsset: (body: { mac: string; hostname?: string; ip?: string; sector?: string; type?: string; tenant_id?: string }) =>
    call<Asset & { new_device?: boolean }>("/api/triage/inventory/assets", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }),
  audit: () => call<{ entries: AuditEntry[]; count: number }>("/api/audit?limit=200"),
  mfaEnable: (password: string) =>
    call<{ username: string; otpauth_uri: string }>("/api/auth/mfa/enable", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }),
    }),
  mfaVerify: (password: string, totp_code: string) =>
    call<{ username: string; mfa_active: boolean }>("/api/auth/mfa/verify", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password, totp_code }),
    }),
  // Admin-only routes (WS-3 session RBAC; other roles get 404, no session 401).
  users: () => call<{ users: UserRow[]; count: number }>("/api/triage/users"),
  createUser: (b: { username: string; password: string; role: string; tenant_id?: string }) =>
    call<UserRow>("/api/triage/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) }),
  updateUser: (name: string, b: { role?: string; password?: string; disabled?: boolean }) =>
    call<UserRow>(`/api/triage/users/${encodeURIComponent(name)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) }),
  webhooks: () => call<{ webhooks: WebhookRow[]; count: number }>("/api/triage/webhooks"),
  setRuleEnabled: (id: string, enabled: boolean) =>
    call<{ id: string; enabled: boolean }>(`/api/triage/rules/${encodeURIComponent(id)}/enabled`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(tenant ? { enabled, tenant_id: tenant } : { enabled }),
    }),
  ops: (ws: "ws1"| "ws2" | "ws3" | "ws4" | "ws5" | "ws8") => call<OpsMetrics>(`/api/ops/${ws}`),
  setTriage: (alertId: string, status: string, note: string) =>
    call<{ status: string; note: string }>(`/api/triage/alerts/${encodeURIComponent(alertId)}/triage`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, note }),
    }),
  report: (alertId: string, query: string) =>
    call<{ body?: string }>(`/api/triage/alerts/${encodeURIComponent(alertId)}/report${query}`, { method: "POST" }),
  incidentReport: (id: string, lang: string) =>
    call<{ body?: string; report_id?: string }>(`/api/incidents/${encodeURIComponent(id)}/report?lang=${lang}${tq("&")}`, { method: "POST" }),
  entity: (id: string) => call<Record<string, unknown>>(`/api/entities/${encodeURIComponent(id)}${tq("?")}`),
  // Read-only Prometheus window (nginx allows exactly these two GET paths).
  promTargets: () => call<PromEnvelope<{ activeTargets: PromTarget[] }>>("/api/prom/api/v1/targets?state=active"),
  promQuery: (q: string) => call<PromEnvelope<{ resultType: string; result: PromSample[] }>>(`/api/prom/api/v1/query?query=${encodeURIComponent(q)}`),
};

/** Prometheus HTTP API v1 shapes (only the fields the console reads). */
export interface PromEnvelope<T> { status: "success" | "error"; data: T; error?: string }
export interface PromTarget {
  labels: { job?: string; instance?: string; [k: string]: string | undefined };
  scrapeUrl: string; health: "up" | "down" | "unknown"; lastError: string;
  lastScrape: string; lastScrapeDuration: number;
}
export interface PromSample { metric: Record<string, string>; value: [number, string] }
