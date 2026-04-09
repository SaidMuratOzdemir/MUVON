export interface Host {
  id: number;
  domain: string;
  is_active: boolean;
  force_https: boolean;
  trusted_proxies: string[];
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
  static_root?: string;
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

export interface LogEntry {
  id: number;
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
  status_counts: Record<string, number>;
  top_hosts: { host: string; count: number }[];
  top_paths: { path: string; count: number }[];
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
}
