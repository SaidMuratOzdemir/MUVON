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
  Agent,
  DeployProjectSummary,
  Deployment,
  DeploymentEvent,
  ContainerSummary,
  ContainerLogChunk,
  ContainerLogRow,
  ContainerLogSearchParams,
  ContainerLogSearchResponse,
  IngestStatus,
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

// Fields the host edit form POSTs / PATCHes. jwt_secret is plaintext on
// write — backend encrypts at rest; empty means "keep existing".
type HostWriteFields =
  | "domain"
  | "is_active"
  | "force_https"
  | "tls_mode"
  | "trusted_proxies"
  | "jwt_identity_enabled"
  | "jwt_identity_mode"
  | "jwt_claims"
  | "jwt_secret";

export async function createHost(
  data: Pick<Host, HostWriteFields>,
): Promise<Host> {
  return request<Host>("POST", "/api/hosts", data);
}

export async function getHost(id: number): Promise<Host> {
  return request<Host>("GET", `/api/hosts/${id}`);
}

export async function updateHost(
  id: number,
  data: Partial<Pick<Host, HostWriteFields>>,
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
  client_ip?: string;
  response_time_min?: number;
  response_time_max?: number;
  starred?: boolean;
  /** Match against JWT claims (email, sub, name). Backend ORs all three
   *  so admins do not need to know which claim the upstream app uses. */
  user?: string;
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
  opts: { host?: string; from?: string; to?: string } = {},
): Promise<LogStats> {
  const qs = new URLSearchParams();
  if (opts.host) qs.set("host", opts.host);
  if (opts.from) qs.set("from", opts.from);
  if (opts.to) qs.set("to", opts.to);
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
// DNS status — lazy lookup, no caching server-side. Used by the host
// detail UI to surface "DNS A kaydını şu IP'ye yönlendir" feedback.
export interface DNSStatus {
  domain: string
  resolved_ips: string[]
  expected_ips: string[]
  status: 'ok' | 'stale' | 'unresolved' | 'no_target' | 'wildcard' | 'error'
  detail?: string
  checked_at: string
  resolve_time_ms: number
}

export async function getHostDNSStatus(id: number): Promise<DNSStatus> {
  return request<DNSStatus>("GET", `/api/hosts/${id}/dns-status`)
}

export interface HostTLSStatus {
  domain: string
  status: 'valid' | 'expiring' | 'expired' | 'missing' | 'off' | 'wildcard'
  issuer?: string
  expires_at?: string
  days_left: number
  tls_mode: string
}

export async function getHostTLSStatus(id: number): Promise<HostTLSStatus> {
  return request<HostTLSStatus>("GET", `/api/hosts/${id}/tls-status`)
}

// Managed app deploys
// ---------------------------------------------------------------------------

export async function listDeployProjects(): Promise<DeployProjectSummary[]> {
  return request<DeployProjectSummary[]>("GET", "/api/deploy/projects");
}

export async function createDeployProject(data: {
  slug: string;
  name: string;
  source_repo?: string;
  webhook_secret?: string;
}): Promise<DeployProjectSummary["project"]> {
  return request<DeployProjectSummary["project"]>("POST", "/api/deploy/projects", data);
}

export async function updateDeployProject(
  slug: string,
  data: { name?: string; source_repo?: string; webhook_secret?: string },
): Promise<DeployProjectSummary["project"]> {
  return request<DeployProjectSummary["project"]>("PUT", `/api/deploy/projects/${slug}`, data);
}

export async function deleteDeployProject(slug: string): Promise<void> {
  await request("DELETE", `/api/deploy/projects/${slug}`);
}

// Mutable subset of DeployComponent — the server fills in defaults for
// the omitted fields on create. Update can send only the fields that
// change (pointer-style optionals on the backend).
export interface DeployComponentInput {
  slug?: string;
  name?: string;
  source_repo?: string;
  image_repo?: string;
  internal_port?: number;
  health_path?: string;
  health_expected_status?: number;
  migration_command?: string[];
  restart_retries?: number;
  drain_timeout_seconds?: number;
  long_drain_timeout_seconds?: number;
  networks?: string[];
  env_file_path?: string;
  env?: Record<string, string>;
  env_secret_keys?: string[];
  mounts?: import("./types").Mount[];
  is_routable?: boolean;
  agent_id?: string;
  paused?: boolean;
  keep_releases?: number;
}

export async function getDeployComponent(
  projectSlug: string,
  componentSlug: string,
): Promise<import("./types").DeployComponent> {
  return request<import("./types").DeployComponent>(
    "GET",
    `/api/deploy/projects/${projectSlug}/components/${componentSlug}`,
  );
}

export async function createDeployComponent(
  projectSlug: string,
  data: DeployComponentInput,
): Promise<import("./types").DeployComponent> {
  return request<import("./types").DeployComponent>(
    "POST",
    `/api/deploy/projects/${projectSlug}/components`,
    data,
  );
}

export async function updateDeployComponent(
  projectSlug: string,
  componentSlug: string,
  data: DeployComponentInput,
): Promise<import("./types").DeployComponent> {
  return request<import("./types").DeployComponent>(
    "PUT",
    `/api/deploy/projects/${projectSlug}/components/${componentSlug}`,
    data,
  );
}

export async function deleteDeployComponent(projectSlug: string, componentSlug: string): Promise<void> {
  await request("DELETE", `/api/deploy/projects/${projectSlug}/components/${componentSlug}`);
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

// Rollback enqueues a deployment that redeploys the previous succeeded
// release. `from_release_id` is typically the latest release (the bad
// one); pass an explicit `to_release_id` to skip multiple bad releases.
export async function rollbackProject(
  slug: string,
  data: { from_release_id?: string; to_release_id?: string } = {},
): Promise<{ deployment: Deployment; idempotent: boolean; rolled_to: string; new_release: string }> {
  return request("POST", `/api/deploy/projects/${slug}/rollback`, data);
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

// Reveal the raw bearer token captured for a log row. Only succeeds when
// the host opted into store_raw_jwt and the row carried an Authorization
// header. Each reveal is audit-logged on the backend, including the
// requesting admin user.
export async function revealLogJWT(
  id: string | number,
): Promise<{ request_id: string; host: string; token: string }> {
  return request<{ request_id: string; host: string; token: string }>(
    "GET",
    `/api/logs/${id}/jwt`,
  );
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

// The plaintext API key flows back in this response exactly once. The
// list endpoint never re-exposes it; the operator must store it now or
// rotate the agent.
export async function createAgent(name: string): Promise<{ agent: Agent; api_key: string }> {
  return request<{ agent: Agent; api_key: string }>("POST", "/api/agents", { name });
}

export async function deleteAgent(id: string): Promise<void> {
  return request<void>("DELETE", `/api/agents/${id}`);
}

// updateAgentMounts replaces the operator-managed bind-mount list.
// Empty / whitespace entries are dropped server-side. The agent picks
// the new list up on its next config pull; applying it to the live
// container requires firing agent.self_upgrade afterwards.
export async function updateAgentMounts(id: string, mounts: string[]): Promise<{ extra_mounts: string[] }> {
  return request<{ extra_mounts: string[] }>("PATCH", `/api/agents/${id}/mounts`, { extra_mounts: mounts });
}

// ---------------------------------------------------------------------------
// Agent commands — central → agent control plane
// ---------------------------------------------------------------------------

export type AgentCommandKind =
  | "agent.cache_flush"
  | "agent.set_log_level"
  | "cert.renew"
  | "container.restart"
  | "agent.drain"
  | "deploy.abort"
  | "agent.restart"
  | "agent.self_upgrade"
  | "agent.revoke"

export interface AgentCommand {
  id: string
  agent_id: string
  kind: AgentCommandKind
  payload: Record<string, unknown>
  state: "pending" | "dispatched" | "succeeded" | "failed" | "expired"
  created_at: string
  dispatched_at?: string
  finished_at?: string
  expires_at: string
  result?: { output?: string; error?: string; data?: unknown }
  issued_by: string
}

export async function enqueueAgentCommand(
  agentID: string,
  data: { kind: AgentCommandKind; payload?: Record<string, unknown>; ttl_seconds?: number },
): Promise<AgentCommand> {
  return request<AgentCommand>("POST", `/api/agents/${agentID}/commands`, data)
}

export async function listAgentCommands(agentID: string, limit = 20): Promise<AgentCommand[]> {
  return request<AgentCommand[]>("GET", `/api/agents/${agentID}/commands?limit=${limit}`)
}

// ---------------------------------------------------------------------------
// Container Logs
// ---------------------------------------------------------------------------

export interface ListContainersParams {
  state?: 'running' | 'exited' | '';
  project?: string;
  component?: string;
  host_id?: string;
  limit?: number;
}

export async function listContainers(
  params: ListContainersParams = {},
): Promise<{ data: ContainerSummary[]; count: number }> {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      qs.set(key, String(value));
    }
  }
  const query = qs.toString();
  return request<{ data: ContainerSummary[]; count: number }>(
    "GET",
    `/api/containers${query ? `?${query}` : ""}`,
  );
}

export async function getContainer(id: string): Promise<{ live: boolean; container: unknown }> {
  return request<{ live: boolean; container: unknown }>("GET", `/api/containers/${encodeURIComponent(id)}`);
}

export async function searchContainerLogs(
  params: ContainerLogSearchParams = {},
): Promise<ContainerLogSearchResponse> {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (key === "attrs" && value && typeof value === "object") {
      for (const [k, v] of Object.entries(value as Record<string, string>)) {
        qs.append("attr", `${k}=${v}`);
      }
      continue;
    }
    if (value !== undefined && value !== "" && value !== false) {
      qs.set(key, String(value));
    }
  }
  const query = qs.toString();
  return request<ContainerLogSearchResponse>(
    "GET",
    `/api/container-logs${query ? `?${query}` : ""}`,
  );
}

export async function getContainerLogContext(id: string, n = 50): Promise<{ data: ContainerLogRow[] }> {
  return request<{ data: ContainerLogRow[] }>("GET", `/api/container-logs/${encodeURIComponent(id)}/context?n=${n}`);
}

export async function getIngestStatus(): Promise<IngestStatus> {
  return request<IngestStatus>("GET", "/api/system/health/ingest");
}

// ---------------------------------------------------------------------------
// System upgrade (Settings → Sistem)
// ---------------------------------------------------------------------------

export interface SystemVersion {
  running: string // human-friendly e.g. "v0.1.0 (2cdaf07)"
  tag: string     // bare version e.g. "v0.1.0"
}

export interface SystemVersionLatest {
  tag: string
  digest?: string
  fetched_at: string
  update_available: boolean
  running?: string
  error?: string
}

export interface UpgradeEvent {
  step: string   // locked, pre_check, backup, pull, restart, post_check, done, failed
  level: string  // info, warn, error
  message: string
  timestamp: string
  done: boolean
}

export async function getSystemVersion(): Promise<SystemVersion> {
  return request<SystemVersion>("GET", "/api/system/version")
}

export async function getSystemVersionLatest(): Promise<SystemVersionLatest> {
  return request<SystemVersionLatest>("GET", "/api/system/version/latest")
}

export async function startSystemUpgrade(
  data: { target_tag?: string; take_backup?: boolean },
): Promise<{ stream_url: string; target_tag: string }> {
  return request("POST", "/api/system/upgrade", data)
}

// createUpgradeStream opens an SSE connection to the upgrade event
// stream. The server replays history first then emits live events.
// onEvent fires for every upgrade event; onEnd when the stream closes
// (either via Done=true event or transport EOF). Returns a close fn
// so React effects can cancel on unmount.
export function createUpgradeStream(
  onEvent: (ev: UpgradeEvent) => void,
  onEnd?: () => void,
  onError?: (err: Event) => void,
): () => void {
  const url = "/api/system/upgrade/stream"
  const source = new EventSource(url, { withCredentials: true })
  source.addEventListener("upgrade", (e) => {
    try {
      onEvent(JSON.parse((e as MessageEvent).data))
    } catch {
      // Ignore malformed event — server should never send these.
    }
  })
  source.addEventListener("end", () => {
    source.close()
    onEnd?.()
  })
  source.addEventListener("idle", () => {
    source.close()
    onEnd?.()
  })
  source.onerror = (err) => {
    onError?.(err)
  }
  return () => source.close()
}

// Fetches CHANGELOG.md from GitHub raw — no auth needed for public
// repos. Returns the full markdown text; UI parses the top section
// (between the first two ## headings) for preview.
export async function fetchChangelog(): Promise<string> {
  const url = "https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/CHANGELOG.md"
  const res = await fetch(url, { mode: "cors" })
  if (!res.ok) throw new Error(`changelog fetch: HTTP ${res.status}`)
  return res.text()
}

// createContainerLogStream opens an EventSource against the live tail
// SSE bridge. onChunk is invoked for every server message; onError fires
// on stream error (browser-side). Returns a close function.
export function createContainerLogStream(
  containerId: string,
  opts: { tail?: number; follow?: boolean; streams?: ('stdout' | 'stderr')[]; since?: string },
  onChunk: (chunk: ContainerLogChunk) => void,
  onError?: () => void,
): () => void {
  const qs = new URLSearchParams();
  if (opts.tail !== undefined) qs.set("tail", String(opts.tail));
  if (opts.follow !== undefined) qs.set("follow", String(opts.follow));
  if (opts.streams && opts.streams.length > 0) {
    qs.set("streams", opts.streams.join(","));
    for (const s of opts.streams) qs.set(s, "true");
  }
  if (opts.since) qs.set("since", opts.since);
  const url = `/api/containers/${encodeURIComponent(containerId)}/logs/stream${qs.toString() ? `?${qs.toString()}` : ""}`;
  const es = new EventSource(url, { withCredentials: true });
  es.onmessage = (e) => {
    try {
      const chunk = JSON.parse(e.data) as ContainerLogChunk;
      onChunk(chunk);
    } catch {
      // ignore malformed events
    }
  };
  if (onError) es.onerror = onError;
  return () => es.close();
}
