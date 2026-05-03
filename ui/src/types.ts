export interface AdminUser {
  id: number;
  username: string;
  is_active: boolean;
  created_at: string;
}

export interface Host {
  id: number;
  domain: string;
  is_active: boolean;
  force_https: boolean;
  trusted_proxies: string[];
  // Per-host JWT identity override. When `jwt_identity_enabled` is true,
  // the central pipeline uses these claims/secret instead of the global
  // setting. `jwt_secret` comes back masked (`"********"`) from the API
  // when a secret is set; the UI treats any non-empty string as "set".
  jwt_identity_enabled?: boolean;
  jwt_identity_mode?: string;
  jwt_claims?: string;
  jwt_secret?: string;
  // Header that the SIEM identity enricher inspects. Defaults to
  // "Authorization". Use "X-Auth-Token" / "X-Access-Token" when the host
  // does not follow RFC 6750, or "Cookie:<name>" to pull a token from a
  // named cookie (the pipeline supports both forms).
  identity_header_name?: string;
  // Opt-in: persist the raw bearer token alongside each log row. UI shows
  // a stern warning when toggling on; the reveal flow audits every read.
  store_raw_jwt?: boolean;
  created_at: string;
  updated_at: string;
}

export interface Route {
  id: number;
  host_id: number;
  path_prefix: string;
  route_type: "proxy" | "static" | "redirect";
  backend_url?: string;
  backend_urls?: string[];
  managed_component_id?: number;
  static_root?: string;
  static_spa?: boolean;
  redirect_url?: string;
  strip_prefix: boolean;
  rewrite_pattern?: string;
  rewrite_to?: string;
  priority: number;
  is_active: boolean;
  log_enabled: boolean;
  waf_enabled: boolean;
  waf_exclude_paths?: string[];
  waf_detection_only?: boolean;
  // RFC3339 timestamp; while in the future the proxy forces detection-only
  // regardless of waf_detection_only. Used by the auto-rollout flow to give
  // newly-enabled routes a soak period.
  waf_detection_only_until?: string | null;
  rate_limit_rps?: number;
  rate_limit_burst?: number;
  max_body_bytes?: number;
  timeout_seconds?: number;
  cors_enabled?: boolean;
  cors_origins?: string;
  cors_methods?: string;
  cors_headers?: string;
  cors_max_age?: number;
  cors_credentials?: boolean;
  error_page_4xx?: string;
  error_page_5xx?: string;
  accel_root?: string;
  accel_signed_secret?: string;
  req_headers_add?: Record<string, string>;
  req_headers_del?: string[];
  resp_headers_add?: Record<string, string>;
  resp_headers_del?: string[];
  created_at: string;
  updated_at: string;
}

export interface UserIdentity {
  claims?: Record<string, string>;
  verified: boolean;
  /** "jwt_verify" | "jwt_decode" | "jwt_expired" */
  source: string;
  exp_expired?: boolean;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  host: string;
  client_ip: string;
  method: string;
  path: string;
  query_string?: string;
  request_headers?: Record<string, string>;
  response_status: number;
  response_headers?: Record<string, string>;
  response_time_ms?: number;
  request_size?: number;
  response_size?: number;
  user_agent?: string;
  error?: string;
  waf_blocked: boolean;
  waf_block_reason?: string;
  request_id?: string;
  is_starred?: boolean;
  note?: string;
  country?: string;
  city?: string;
  user_identity?: UserIdentity;
  // Summary-level display for list rows (LogSummary proto). Detail endpoint
  // populates the full user_identity; SearchLogs already resolves the best
  // claim so the list does not have to.
  user_display?: string;
  user_query?: string;
}

export interface Alert {
  id: string;
  timestamp: string;
  rule: string;
  /** "info" | "warning" | "critical" */
  severity: string;
  title: string;
  detail?: Record<string, unknown>;
  source_ip?: string;
  host?: string;
  fingerprint: string;
  notified: boolean;
  notified_at?: string;
  occurrences: number;
  last_seen_at: string;
  acknowledged: boolean;
  acknowledged_at?: string;
  acknowledged_by?: string;
}

export interface AlertStats {
  total_open: number;
  total_all: number;
  by_rule: Record<string, number>;
  by_severity: Record<string, number>;
  last_alert_at?: string;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  admin_user: string;
  action: string;
  target_type?: string;
  target_id?: string;
  detail?: unknown;
  ip?: string;
}

export interface LogBody {
  request_body?: string;
  response_body?: string;
  is_request_truncated: boolean;
  is_response_truncated: boolean;
}

export interface LogStats {
  total_requests: number;
  total_errors: number;
  status_counts: Record<string, number>;
  top_hosts: { host: string; count: number }[];
  top_paths: { path: string; count: number }[];
  top_countries: { country: string; count: number }[];
  /** Top users by request volume. `query` is the value to feed back into
   *  searchLogs({ user }) — it matches the same string against email, name
   *  or sub claims via JSONB containment. */
  top_users: { display: string; query: string; count: number }[];
  avg_response_ms: number;
  requests_per_min: number;
}

export interface TLSCert {
  id: number;
  domain: string;
  issuer: string;
  expires_at: string;
  created_at: string;
}

export interface SystemStats {
  uptime_seconds: number;
  goroutines: number;
  memory: {
    alloc_mb: number;
    total_alloc_mb: number;
    sys_mb: number;
    gc_cycles: number;
  };
  go_version: string;
  log_pipeline?: {
    enqueued: number;
    dropped: number;
    queue_len: number;
  };
  config?: {
    active_hosts: number;
  };
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

// ---------------------------------------------------------------------------
// WAF Types
// ---------------------------------------------------------------------------

export interface WafRule {
  id: number;
  pattern: string;
  is_regex: boolean;
  category: string;
  severity: number;
  description: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface WafIPState {
  ip: string;
  banned: boolean;
  whitelisted: boolean;
  cumulative_score: number;
  ban_reason: string;
  last_seen: string;
}

export interface WafEvent {
  id: number;
  request_id: string;
  client_ip: string;
  host: string;
  method: string;
  path: string;
  request_score: number;
  ip_score: number;
  action: string;
  matched_rules: string;
  created_at: string;
}

export interface WafStats {
  total_events: number;
  total_blocked: number;
  unique_ips: number;
  top_categories: { category: string; count: number }[];
  top_ips: { ip: string; count: number }[];
}

export interface WafExclusion {
  id: number;
  rule_id: number;
  route_id: number;
  location: string;
  parameter: string;
}

export interface Agent {
  id: string;
  name: string;
  api_key: string;
  is_active: boolean;
  last_seen_at?: string | null;
  // Stamped on every config pull from the agent — used to flag agents
  // that are alive on the SSE channel but lagging behind the current
  // central config version.
  last_config_pull_at?: string | null;
  config_version?: string;
  last_remote_addr?: string;
  last_user_agent?: string;
  created_at: string;
  updated_at: string;
}

export interface ServiceHealth {
  status: string;
  services: {
    database: string;
    waf: string;
    logging: string;
  };
  // Reported by diaLOG when reachable. The admin UI uses these to surface
  // "GeoIP enabled but failing" as a banner instead of leaving country/user
  // columns silently empty. Absent when diaLOG is unavailable.
  enrichment?: {
    geoip_state: 'disabled' | 'ok' | 'error';
    geoip_path: string;
    geoip_error: string;
    geoip_loaded_at: string;
    jwt_identity_state: 'disabled' | 'ok';
    jwt_identity_host_count: number;
  };
}

export interface DeployProject {
  id: number;
  slug: string;
  name: string;
  source_repo: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Mount {
  type: "bind" | "volume" | "tmpfs";
  source?: string;
  target: string;
  read_only?: boolean;
  bind_options?: {
    propagation?: string;
    create_mountpoint?: boolean;
  };
  volume_options?: {
    no_copy?: boolean;
    labels?: Record<string, string>;
  };
}

export interface DeployComponent {
  id: number;
  project_id: number;
  project_slug?: string;
  slug: string;
  name: string;
  source_repo: string;
  image_repo: string;
  internal_port: number;
  health_path: string;
  health_expected_status: number;
  migration_command: string[];
  restart_retries: number;
  drain_timeout_seconds: number;
  long_drain_timeout_seconds: number;
  networks: string[];
  env_file_path: string;
  env: Record<string, string>;
  mounts: Mount[];
  is_routable: boolean;
  created_at: string;
  updated_at: string;
}

export interface DeployInstance {
  id: string;
  component_id: number;
  project_slug?: string;
  component_slug?: string;
  release_uuid?: string;
  release_id?: string;
  container_id: string;
  container_name: string;
  backend_url: string;
  state: "warming" | "active" | "draining" | "unhealthy" | "stopped";
  health_status: string;
  in_flight: number;
  last_error: string;
  started_at?: string;
  drain_started_at?: string;
  stopped_at?: string;
  created_at: string;
  updated_at: string;
}

export interface DeployProjectSummary {
  project: DeployProject;
  components: DeployComponent[];
  instances: DeployInstance[];
}

export interface Deployment {
  id: string;
  project_id: number;
  project_slug?: string;
  release_uuid: string;
  release_id: string;
  repo?: string;
  branch?: string;
  commit_sha?: string;
  trigger: string;
  status: "pending" | "running" | "succeeded" | "failed" | "rolled_back";
  error: string;
  started_at?: string;
  finished_at?: string;
  created_at: string;
  updated_at: string;
}

export interface DeploymentEvent {
  id: number;
  deployment_id: string;
  event_type: string;
  message: string;
  detail: Record<string, unknown>;
  created_at: string;
}

// ── Container Logs ──────────────────────────────────────────────────────

// A single container known to the platform — merged from live deployer
// state and the dialog dimension table. Containers stay in this list
// even after Docker has destroyed them, so a search for a long-gone
// release still works (the user's incident scenario).
export interface ContainerSummary {
  container_id: string;
  container_name: string;
  image?: string;
  image_digest?: string;
  project?: string;
  component?: string;
  release_id?: string;
  deployment_id?: string;
  host_id: string;
  state: string;          // running | exited | unknown | dead
  status?: string;        // human-readable docker status when live
  live: boolean;          // visible in deployer's docker daemon view
  started_at?: string;
  finished_at?: string;
  exit_code?: number;
  last_log_at?: string;
  labels?: Record<string, string>;
}

// Live tail chunk emitted over SSE from /api/containers/{id}/logs/stream.
export interface ContainerLogChunk {
  timestamp?: string;
  stream: string;        // "stdout" | "stderr"
  line: string;
  truncated?: boolean;
  seq?: number;
  synthetic?: boolean;   // muvon-injected marker (drops, EOF)
}

// One historical row from /api/container-logs.
export interface ContainerLogRow {
  id: string;
  timestamp: string;
  received_at?: string;
  host_id: string;
  container_id: string;
  container_name: string;
  image?: string;
  project?: string;
  component?: string;
  release_id?: string;
  deployment_id?: string;
  stream: string;
  line: string;
  truncated?: boolean;
  seq?: number;
  attrs_json?: string;
}

export interface ContainerLogSearchParams {
  container_id?: string;
  container_name?: string;
  project?: string;
  component?: string;
  release_id?: string;
  deployment_id?: string;
  host_id?: string;
  stream?: 'stdout' | 'stderr' | '';
  from?: string;
  to?: string;
  q?: string;
  regex?: boolean;
  limit?: number;
  before?: string;
  after?: string;
  // attrs filters as repeated `attr=key=value` query string entries.
  attrs?: Record<string, string>;
}

export interface ContainerLogSearchResponse {
  data: ContainerLogRow[];
  next_before_cursor?: string;
  next_after_cursor?: string;
}

export interface IngestStatus {
  dialog_available: boolean;
  deployer_available: boolean;
  dialog?: {
    enqueued_total?: number;
    dropped_total?: number;
    queue_len?: number;
    spool_bytes?: number;
    spool_oldest_seconds?: number;
    degraded?: boolean;
    last_batch_at?: string;
    containers_active?: number;
  };
  deployer?: {
    ok?: boolean;
    last_tick_age_seconds?: number;
    active_tail_streams?: number;
    shipper_active_containers?: number;
  };
}
