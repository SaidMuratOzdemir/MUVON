import type {
  AdminUser,
  Alert,
  AlertStats,
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
  DeployProjectSummary,
  Deployment,
  DeploymentEvent,
} from "./types";

const API_BASE = "";

// Authentication is cookie-based:
//   • __Host-muvon_access  — HttpOnly JWT, 15 min
//   • muvon_refresh        — HttpOnly refresh token, 30 days, path=/api/auth
//   • muvon_csrf           — JS-readable CSRF token, mirrored in X-CSRF-Token
//
// The browser attaches the cookies for us; this module only has to (a) echo
// the CSRF token on state-changing requests and (b) transparently refresh on
// 401.

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// Endpoints where a 401 must NOT trigger an automatic refresh+retry:
// calling them IS the refresh / login / logout, so looping back would be
// meaningless (login: wrong password; refresh: expired refresh token;
// logout: no session anyway). /api/auth/me is deliberately absent — a
// stale access cookie there should transparently rotate.
const NO_REFRESH_PATHS = new Set([
  "/api/auth/login",
  "/api/auth/setup",
  "/api/auth/refresh",
  "/api/auth/logout",
]);

function readCSRF(): string {
  const m = document.cookie.match(/(?:^|;\s*)muvon_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

function buildHeaders(method: string, hasBody: boolean): Record<string, string> {
  const headers: Record<string, string> = {};
  if (hasBody) headers["Content-Type"] = "application/json";
  if (!SAFE_METHODS.has(method)) {
    const csrf = readCSRF();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  return headers;
}

// Single-flight refresh: if N concurrent requests see 401 at once, only one
// /api/auth/refresh call is in flight. The rest await the same promise.
let refreshInFlight: Promise<void> | null = null;
// Callback fired when refresh fails (e.g. refresh token expired or revoked).
// AuthContext registers a handler to clear user state and bounce to login.
let onAuthExpired: (() => void) | null = null;

export function setAuthExpiredHandler(fn: (() => void) | null): void {
  onAuthExpired = fn;
}

async function doRefresh(): Promise<void> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    const res = await fetch(`${API_BASE}/api/auth/refresh`, {
      method: "POST",
      credentials: "include",
    });
    if (!res.ok) {
      throw new ApiError("session expired", res.status);
    }
  })().finally(() => {
    refreshInFlight = null;
  });
  return refreshInFlight;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const init: RequestInit = {
    method,
    credentials: "include",
    headers: buildHeaders(method, body !== undefined),
  };
  if (body !== undefined) init.body = JSON.stringify(body);

  let res = await fetch(`${API_BASE}${path}`, init);

  // On 401, try to refresh the session once and replay the request. A 401 on
  // login/setup/refresh/logout is NOT an expired session — it means the call
  // itself failed (bad credentials, bad refresh token, etc.) so we must not
  // loop back into doRefresh. Everything else — including /api/auth/me — IS
  // allowed to refresh, so stale access cookies heal transparently.
  if (res.status === 401 && !NO_REFRESH_PATHS.has(path)) {
    try {
      await doRefresh();
      init.headers = buildHeaders(method, body !== undefined);
      res = await fetch(`${API_BASE}${path}`, init);
    } catch {
      if (onAuthExpired) onAuthExpired();
    }
  }

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

type WireLogEntry = Partial<LogEntry> & {
  starred?: boolean;
  request_body?: string;
  response_body?: string;
  is_request_truncated?: boolean;
  is_response_truncated?: boolean;
};

type WireLogDetail = Partial<LogEntry> & {
  entry?: WireLogEntry;
  body?: LogBody;
  note?: string;
  starred?: boolean;
};

function logIdentifier(entry: WireLogEntry): string {
  return String(entry.id ?? entry.request_id ?? "");
}

function decodeProtoBody(value: unknown): string | undefined {
  if (typeof value !== "string" || value === "") return undefined;
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return value;
  }
}

function normalizeLogEntry(entry: WireLogEntry): LogEntry {
  const id = logIdentifier(entry);
  return {
    ...entry,
    id,
    request_id: entry.request_id ?? id,
    is_starred: entry.is_starred ?? entry.starred,
  } as LogEntry;
}

function normalizeLogDetail(detail: WireLogDetail): LogEntry & { body?: LogBody } {
  const entry = (detail.entry ?? detail) as WireLogEntry;
  const normalized = normalizeLogEntry(entry);
  const requestBody = detail.body?.request_body ?? decodeProtoBody(entry.request_body);
  const responseBody = detail.body?.response_body ?? decodeProtoBody(entry.response_body);
  const body: LogBody | undefined =
    requestBody !== undefined || responseBody !== undefined
      ? {
          request_body: requestBody,
          response_body: responseBody,
          is_request_truncated: detail.body?.is_request_truncated ?? entry.is_request_truncated ?? false,
          is_response_truncated: detail.body?.is_response_truncated ?? entry.is_response_truncated ?? false,
        }
      : detail.body;

  return {
    ...normalized,
    note: detail.note ?? normalized.note,
    is_starred: detail.is_starred ?? detail.starred ?? normalized.is_starred,
    body,
  };
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
): Promise<{ user: AdminUser }> {
  return request<{ user: AdminUser }>("POST", "/api/auth/login", {
    username,
    password,
  });
}

export async function setup(
  username: string,
  password: string,
): Promise<{ user: AdminUser }> {
  return request<{ user: AdminUser }>("POST", "/api/auth/setup", {
    username,
    password,
  });
}

export async function logout(): Promise<void> {
  return request<void>("POST", "/api/auth/logout");
}

export async function me(): Promise<AdminUser> {
  return request<AdminUser>("GET", "/api/auth/me");
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
  const response = await request<PaginatedResponse<LogEntry>>(
    "GET",
    `/api/logs${query ? `?${query}` : ""}`,
  );
  return {
    ...response,
    data: (response.data ?? []).map(normalizeLogEntry),
  };
}

export async function getLogDetail(
  id: string | number,
): Promise<LogEntry & { body?: LogBody }> {
  const detail = await request<WireLogDetail>("GET", `/api/logs/${id}`);
  return normalizeLogDetail(detail);
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
// Managed app deploys
// ---------------------------------------------------------------------------

export async function listDeployProjects(): Promise<DeployProjectSummary[]> {
  return request<DeployProjectSummary[]>("GET", "/api/deploy/projects");
}

export async function updateDeployProject(
  slug: string,
  data: { name?: string; source_repo?: string; webhook_secret?: string },
): Promise<DeployProjectSummary["project"]> {
  return request<DeployProjectSummary["project"]>("PUT", `/api/deploy/projects/${slug}`, data);
}

export async function listDeployments(limit = 50): Promise<Deployment[]> {
  return request<Deployment[]>("GET", `/api/deploy/deployments?limit=${limit}`);
}

export async function listDeploymentEvents(id: string): Promise<DeploymentEvent[]> {
  return request<DeploymentEvent[]>("GET", `/api/deploy/deployments/${id}/events`);
}

export async function rerunDeployment(id: string): Promise<{ deployment: Deployment; idempotent: boolean }> {
  return request<{ deployment: Deployment; idempotent: boolean }>("POST", `/api/deploy/deployments/${id}/rerun`);
}

export async function getDeployProjectSecret(slug: string): Promise<{ secret: string }> {
  return request<{ secret: string }>("GET", `/api/deploy/projects/${slug}/secret`);
}

export async function manualDeploy(
  projectSlug: string,
  data: {
    release_id: string;
    repo?: string;
    branch?: string;
    commit_sha?: string;
    components: Record<string, { image_ref: string; image_digest?: string }>;
  },
): Promise<{ deployment: Deployment; idempotent: boolean }> {
  return request<{ deployment: Deployment; idempotent: boolean }>("POST", `/api/deploy/projects/${projectSlug}/deploy`, {
    project: projectSlug,
    ...data,
  });
}

// ---------------------------------------------------------------------------
// Log star / note
// ---------------------------------------------------------------------------

export async function toggleLogStar(id: string | number): Promise<{ is_starred?: boolean }> {
  return request<{ is_starred: boolean }>("POST", `/api/logs/${id}/star`);
}

export async function upsertLogNote(id: string | number, note: string): Promise<void> {
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
  // EventSource sends same-origin cookies automatically; withCredentials=true
  // keeps it working when the SPA is served from a different origin than the
  // backend during local dev with a proxy.
  const es = new EventSource("/api/logs/stream", { withCredentials: true });
  es.onmessage = (e) => {
    try {
      const entry = JSON.parse(e.data) as LogEntry;
      onEntry(normalizeLogEntry(entry));
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
// Alerts (correlation engine output)
// ---------------------------------------------------------------------------

export interface AlertSearchParams {
  rule?: string;
  severity?: string;
  host?: string;
  source_ip?: string;
  fingerprint?: string;
  acknowledged?: boolean;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export async function searchAlerts(
  params: AlertSearchParams = {},
): Promise<PaginatedResponse<Alert>> {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      qs.set(key, String(value));
    }
  }
  const query = qs.toString();
  return request<PaginatedResponse<Alert>>(
    "GET",
    `/api/alerts${query ? `?${query}` : ""}`,
  );
}

export async function getAlert(id: string): Promise<Alert> {
  return request<Alert>("GET", `/api/alerts/${id}`);
}

export async function acknowledgeAlert(id: string): Promise<Alert> {
  return request<Alert>("POST", `/api/alerts/${id}/acknowledge`);
}

export async function getAlertStats(): Promise<AlertStats> {
  return request<AlertStats>("GET", "/api/alerts/stats");
}

export async function testSlackAlert(): Promise<{ status: string }> {
  return request<{ status: string }>("POST", "/api/alerting/test/slack");
}

export async function testSMTPAlert(): Promise<{ status: string }> {
  return request<{ status: string }>("POST", "/api/alerting/test/smtp");
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
