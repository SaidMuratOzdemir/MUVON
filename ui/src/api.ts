import type {
  Host,
  Route,
  LogEntry,
  LogBody,
  LogStats,
  TLSCert,
  SystemStats,
  PaginatedResponse,
  AuditEntry,
  ServiceHealth,
  WafRule,
  WafIPState,
  WafEvent,
  WafStats,
  WafExclusion,
  Agent,
} from "./types";

const API_BASE = "";

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem("dialog_token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const opts: RequestInit = {
    method,
    headers: authHeaders(),
  };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`${API_BASE}${path}`, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    let message = `HTTP ${res.status}`;
    try {
      const parsed = JSON.parse(text);
      if (parsed.error) message = parsed.error;
    } catch {
      if (text) message = text;
    }
    throw new ApiError(message, res.status);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }

  get isServiceUnavailable(): boolean {
    return this.status === 503;
  }
}

export function isServiceUnavailable(err: unknown): boolean {
  return err instanceof ApiError && err.status === 503;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function login(
  username: string,
  password: string,
): Promise<{ token: string }> {
  return request<{ token: string }>("POST", "/api/auth/login", {
    username,
    password,
  });
}

export async function setup(
  username: string,
  password: string,
): Promise<{ token: string }> {
  return request<{ token: string }>("POST", "/api/auth/setup", {
    username,
    password,
  });
}

export async function me(): Promise<{ username: string }> {
  return request<{ username: string }>("GET", "/api/auth/me");
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

export async function listHosts(): Promise<Host[]> {
  return request<Host[]>("GET", "/api/hosts");
}

export async function createHost(
  data: Pick<Host, "domain" | "is_active" | "force_https" | "trusted_proxies">,
): Promise<Host> {
  return request<Host>("POST", "/api/hosts", data);
}

export async function getHost(id: number): Promise<Host> {
  return request<Host>("GET", `/api/hosts/${id}`);
}

export async function updateHost(
  id: number,
  data: Partial<Pick<Host, "domain" | "is_active" | "force_https" | "trusted_proxies">>,
): Promise<Host> {
  return request<Host>("PUT", `/api/hosts/${id}`, data);
}

export async function deleteHost(id: number): Promise<void> {
  return request<void>("DELETE", `/api/hosts/${id}`);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

export async function listRoutesByHost(hostId: number): Promise<Route[]> {
  return request<Route[]>("GET", `/api/hosts/${hostId}/routes`);
}

export async function createRoute(
  hostId: number,
  data: Omit<Route, "id" | "host_id" | "created_at" | "updated_at">,
): Promise<Route> {
  return request<Route>("POST", `/api/hosts/${hostId}/routes`, data);
}

export async function getRoute(routeId: number): Promise<Route> {
  return request<Route>("GET", `/api/routes/${routeId}`);
}

export async function updateRoute(
  routeId: number,
  data: Partial<Omit<Route, "id" | "host_id" | "created_at" | "updated_at">>,
): Promise<Route> {
  return request<Route>("PUT", `/api/routes/${routeId}`, data);
}

export async function deleteRoute(routeId: number): Promise<void> {
  return request<void>("DELETE", `/api/routes/${routeId}`);
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

export interface LogSearchParams {
  host?: string;
  method?: string;
  path?: string;
  status_min?: number;
  status_max?: number;
  from?: string;
  to?: string;
  search?: string;
  limit?: number;
  offset?: number;
  waf_blocked?: boolean;
  client_ip?: string;
  response_time_min?: number;
  response_time_max?: number;
  starred?: boolean;
}

export async function searchLogs(
  params: LogSearchParams = {},
): Promise<PaginatedResponse<LogEntry>> {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      qs.set(key, String(value));
    }
  }
  const query = qs.toString();
  return request<PaginatedResponse<LogEntry>>(
    "GET",
    `/api/logs${query ? `?${query}` : ""}`,
  );
}

export async function getLogDetail(
  id: number,
): Promise<LogEntry & { body?: LogBody }> {
  return request<LogEntry & { body?: LogBody }>("GET", `/api/logs/${id}`);
}

export async function getLogStats(
  from?: string,
  to?: string,
): Promise<LogStats> {
  const qs = new URLSearchParams();
  if (from) qs.set("from", from);
  if (to) qs.set("to", to);
  const query = qs.toString();
  return request<LogStats>(
    "GET",
    `/api/logs/stats${query ? `?${query}` : ""}`,
  );
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

export async function getSettings(): Promise<Record<string, string>> {
  return request<Record<string, string>>("GET", "/api/settings");
}

export async function updateSetting(
  key: string,
  value: unknown,
): Promise<void> {
  return request<void>("PUT", `/api/settings/${key}`, { value });
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

export async function listCerts(): Promise<TLSCert[]> {
  return request<TLSCert[]>("GET", "/api/tls/certificates");
}

export async function uploadCert(data: { domain: string; cert_pem: string; key_pem: string }): Promise<{ status: string; domain: string }> {
  return request("POST", "/api/tls/certificates", data);
}

export async function deleteCert(id: number): Promise<void> {
  return request<void>("DELETE", `/api/tls/certificates/${id}`);
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

export async function health(): Promise<ServiceHealth> {
  return request<ServiceHealth>("GET", "/api/system/health");
}

export async function systemStats(): Promise<SystemStats> {
  return request<SystemStats>("GET", "/api/system/stats");
}

export async function reload(): Promise<{ message: string }> {
  return request<{ message: string }>("POST", "/api/system/reload");
}

export async function getBackendHealth(): Promise<Record<string, string>> {
  return request<Record<string, string>>("GET", "/api/system/health/backends");
}

// ---------------------------------------------------------------------------
// Log star / note
// ---------------------------------------------------------------------------

export async function toggleLogStar(id: number): Promise<{ is_starred: boolean }> {
  return request<{ is_starred: boolean }>("POST", `/api/logs/${id}/star`);
}

export async function upsertLogNote(id: number, note: string): Promise<void> {
  return request<void>("PUT", `/api/logs/${id}/note`, { note });
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export interface AuditSearchParams {
  from?: string;
  to?: string;
  action?: string;
  limit?: number;
  offset?: number;
}

export async function listAuditLog(
  params: AuditSearchParams = {},
): Promise<PaginatedResponse<AuditEntry>> {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      qs.set(key, String(value));
    }
  }
  const query = qs.toString();
  return request<PaginatedResponse<AuditEntry>>(
    "GET",
    `/api/audit${query ? `?${query}` : ""}`,
  );
}

// ---------------------------------------------------------------------------
// SSE log stream — returns an EventSource-like object using native EventSource
// ---------------------------------------------------------------------------

export function createLogStream(
  onEntry: (entry: LogEntry) => void,
  onError?: () => void,
): () => void {
  const token = localStorage.getItem("dialog_token");
  const url = token
    ? `/api/logs/stream?token=${encodeURIComponent(token)}`
    : "/api/logs/stream";
  const es = new EventSource(url);
  es.onmessage = (e) => {
    try {
      const entry = JSON.parse(e.data) as LogEntry;
      onEntry(entry);
    } catch {
      // ignore malformed events
    }
  };
  if (onError) es.onerror = onError;
  return () => es.close();
}

// ---------------------------------------------------------------------------
// WAF Rules
// ---------------------------------------------------------------------------

export async function listWafRules(): Promise<WafRule[]> {
  return request<WafRule[]>("GET", "/api/waf/rules");
}

export async function getWafRule(id: number): Promise<WafRule> {
  return request<WafRule>("GET", `/api/waf/rules/${id}`);
}

export async function createWafRule(
  data: Pick<WafRule, "pattern" | "is_regex" | "category" | "severity" | "description">,
): Promise<WafRule> {
  return request<WafRule>("POST", "/api/waf/rules", data);
}

export async function updateWafRule(
  id: number,
  data: Partial<Pick<WafRule, "pattern" | "is_regex" | "category" | "severity" | "description" | "is_active">>,
): Promise<WafRule> {
  return request<WafRule>("PUT", `/api/waf/rules/${id}`, data);
}

export async function deleteWafRule(id: number): Promise<void> {
  return request<void>("DELETE", `/api/waf/rules/${id}`);
}

export async function importWafRules(
  rules: Pick<WafRule, "pattern" | "is_regex" | "category" | "severity" | "description">[],
): Promise<{ imported: number; total: number }> {
  return request<{ imported: number; total: number }>("POST", "/api/waf/rules/import", rules);
}

// ---------------------------------------------------------------------------
// WAF IPs
// ---------------------------------------------------------------------------

export async function listWafIPs(): Promise<{ ips: WafIPState[] }> {
  return request<{ ips: WafIPState[] }>("GET", "/api/waf/ips");
}

export async function banIP(ip: string, reason: string, duration_minutes: number): Promise<void> {
  return request<void>("POST", "/api/waf/ips/ban", { ip, reason, duration_minutes });
}

export async function unbanIP(ip: string): Promise<void> {
  return request<void>("POST", "/api/waf/ips/unban", { ip });
}

export async function whitelistIP(ip: string): Promise<void> {
  return request<void>("POST", "/api/waf/ips/whitelist", { ip });
}

export async function removeWhitelist(ip: string): Promise<void> {
  return request<void>("DELETE", `/api/waf/ips/whitelist/${encodeURIComponent(ip)}`);
}

// ---------------------------------------------------------------------------
// WAF Exclusions
// ---------------------------------------------------------------------------

export async function listWafExclusions(): Promise<WafExclusion[]> {
  return request<WafExclusion[]>("GET", "/api/waf/exclusions");
}

export async function createWafExclusion(
  data: Pick<WafExclusion, "rule_id" | "route_id" | "location" | "parameter">,
): Promise<WafExclusion> {
  return request<WafExclusion>("POST", "/api/waf/exclusions", data);
}

export async function deleteWafExclusion(id: number): Promise<void> {
  return request<void>("DELETE", `/api/waf/exclusions/${id}`);
}

// ---------------------------------------------------------------------------
// WAF Events & Stats
// ---------------------------------------------------------------------------

export interface WafEventSearchParams {
  client_ip?: string;
  action?: string;
  host?: string;
  limit?: number;
  offset?: number;
}

export async function searchWafEvents(
  params: WafEventSearchParams = {},
): Promise<{ events: WafEvent[]; total: number; limit: number; offset: number }> {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      qs.set(key, String(value));
    }
  }
  const query = qs.toString();
  return request("GET", `/api/waf/events${query ? `?${query}` : ""}`);
}

export async function getWafStats(): Promise<WafStats> {
  return request<WafStats>("GET", "/api/waf/stats");
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

export async function listAgents(): Promise<Agent[]> {
  return request<Agent[]>("GET", "/api/agents");
}

export async function createAgent(name: string): Promise<Agent> {
  return request<Agent>("POST", "/api/agents", { name });
}

export async function deleteAgent(id: string): Promise<void> {
  return request<void>("DELETE", `/api/agents/${id}`);
}
