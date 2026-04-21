package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- Host Queries ---

type Host struct {
	ID             int       `json:"id"`
	Domain         string    `json:"domain"`
	IsActive       bool      `json:"is_active"`
	ForceHTTPS     bool      `json:"force_https"`
	TrustedProxies []string  `json:"trusted_proxies"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

const hostSelectCols = `id, domain, is_active, force_https, trusted_proxies, created_at, updated_at`

func scanHost(scan func(...any) error) (Host, error) {
	var h Host
	var trusted []string
	err := scan(&h.ID, &h.Domain, &h.IsActive, &h.ForceHTTPS, &trusted, &h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		return h, err
	}
	if trusted == nil {
		trusted = []string{}
	}
	h.TrustedProxies = trusted
	return h, nil
}

func (d *DB) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+hostSelectCols+` FROM hosts ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		h, err := scanHost(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list hosts scan: %w", err)
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

func (d *DB) GetHost(ctx context.Context, id int) (Host, error) {
	h, err := scanHost(d.Pool.QueryRow(ctx,
		`SELECT `+hostSelectCols+` FROM hosts WHERE id = $1`, id,
	).Scan)
	if err != nil {
		return h, fmt.Errorf("get host: %w", err)
	}
	return h, nil
}

func (d *DB) CreateHost(ctx context.Context, domain string, isActive, forceHTTPS bool, trustedProxies []string) (Host, error) {
	if trustedProxies == nil {
		trustedProxies = []string{}
	}
	h, err := scanHost(d.Pool.QueryRow(ctx,
		`INSERT INTO hosts (domain, is_active, force_https, trusted_proxies) VALUES ($1, $2, $3, $4) RETURNING `+hostSelectCols,
		domain, isActive, forceHTTPS, trustedProxies,
	).Scan)
	if err != nil {
		return h, fmt.Errorf("create host: %w", err)
	}
	return h, nil
}

func (d *DB) UpdateHost(ctx context.Context, id int, domain string, isActive, forceHTTPS bool, trustedProxies []string) (Host, error) {
	if trustedProxies == nil {
		trustedProxies = []string{}
	}
	h, err := scanHost(d.Pool.QueryRow(ctx,
		`UPDATE hosts SET domain=$2, is_active=$3, force_https=$4, trusted_proxies=$5, updated_at=now()
		 WHERE id=$1 RETURNING `+hostSelectCols,
		id, domain, isActive, forceHTTPS, trustedProxies,
	).Scan)
	if err != nil {
		return h, fmt.Errorf("update host: %w", err)
	}
	return h, nil
}

func (d *DB) DeleteHost(ctx context.Context, id int) error {
	ct, err := d.Pool.Exec(ctx, `DELETE FROM hosts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// --- Route Queries ---

type Route struct {
	ID                 int               `json:"id"`
	HostID             int               `json:"host_id"`
	PathPrefix         string            `json:"path_prefix"`
	RouteType          string            `json:"route_type"`
	BackendURL         *string           `json:"backend_url,omitempty"`
	BackendURLs        []string          `json:"backend_urls"`
	ManagedComponentID *int              `json:"managed_component_id,omitempty"`
	StaticRoot         *string           `json:"static_root,omitempty"`
	StaticSPA          bool              `json:"static_spa"`
	RedirectURL        *string           `json:"redirect_url,omitempty"`
	StripPrefix        bool              `json:"strip_prefix"`
	RewritePattern     *string           `json:"rewrite_pattern,omitempty"`
	RewriteTo          *string           `json:"rewrite_to,omitempty"`
	Priority           int               `json:"priority"`
	IsActive           bool              `json:"is_active"`
	LogEnabled         bool              `json:"log_enabled"`
	WafEnabled         bool              `json:"waf_enabled"`
	WafExcludePaths    []string          `json:"waf_exclude_paths"`
	WafDetectionOnly   bool              `json:"waf_detection_only"`
	RateLimitRPS       int               `json:"rate_limit_rps"`
	RateLimitBurst     int               `json:"rate_limit_burst"`
	ReqHeadersAdd      map[string]string `json:"req_headers_add"`
	ReqHeadersDel      []string          `json:"req_headers_del"`
	RespHeadersAdd     map[string]string `json:"resp_headers_add"`
	RespHeadersDel     []string          `json:"resp_headers_del"`
	AccelRoot          *string           `json:"accel_root,omitempty"`
	AccelSignedSecret  *string           `json:"accel_signed_secret,omitempty"`
	MaxBodyBytes       int64             `json:"max_body_bytes"`
	TimeoutSeconds     int               `json:"timeout_seconds"`
	CORSEnabled        bool              `json:"cors_enabled"`
	CORSOrigins        string            `json:"cors_origins"`
	CORSMethods        string            `json:"cors_methods"`
	CORSHeaders        string            `json:"cors_headers"`
	CORSMaxAge         int               `json:"cors_max_age"`
	CORSCredentials    bool              `json:"cors_credentials"`
	ErrorPage4xx       *string           `json:"error_page_4xx,omitempty"`
	ErrorPage5xx       *string           `json:"error_page_5xx,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

const routeSelectCols = `id, host_id, path_prefix, route_type, backend_url, backend_urls, managed_component_id, static_root, static_spa, redirect_url,
	strip_prefix, rewrite_pattern, rewrite_to, priority, is_active, log_enabled, waf_enabled,
	waf_exclude_paths, waf_detection_only, rate_limit_rps, rate_limit_burst,
	req_headers_add, req_headers_del, resp_headers_add, resp_headers_del,
	accel_root, accel_signed_secret,
	max_body_bytes, timeout_seconds,
	cors_enabled, cors_origins, cors_methods, cors_headers, cors_max_age, cors_credentials,
	error_page_4xx, error_page_5xx,
	created_at, updated_at`

func scanRoute(scan func(...any) error) (Route, error) {
	var r Route
	var reqAdd, respAdd []byte
	var reqDel, respDel, backendURLs, wafExclude []string
	err := scan(
		&r.ID, &r.HostID, &r.PathPrefix, &r.RouteType,
		&r.BackendURL, &backendURLs, &r.ManagedComponentID, &r.StaticRoot, &r.StaticSPA, &r.RedirectURL,
		&r.StripPrefix, &r.RewritePattern, &r.RewriteTo,
		&r.Priority, &r.IsActive, &r.LogEnabled, &r.WafEnabled,
		&wafExclude, &r.WafDetectionOnly, &r.RateLimitRPS, &r.RateLimitBurst,
		&reqAdd, &reqDel, &respAdd, &respDel,
		&r.AccelRoot, &r.AccelSignedSecret,
		&r.MaxBodyBytes, &r.TimeoutSeconds,
		&r.CORSEnabled, &r.CORSOrigins, &r.CORSMethods, &r.CORSHeaders, &r.CORSMaxAge, &r.CORSCredentials,
		&r.ErrorPage4xx, &r.ErrorPage5xx,
		&r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return r, err
	}
	r.BackendURLs = backendURLs
	r.WafExcludePaths = wafExclude
	r.ReqHeadersDel = reqDel
	r.RespHeadersDel = respDel
	if len(reqAdd) > 0 {
		_ = json.Unmarshal(reqAdd, &r.ReqHeadersAdd)
	}
	if len(respAdd) > 0 {
		_ = json.Unmarshal(respAdd, &r.RespHeadersAdd)
	}
	if r.ReqHeadersAdd == nil {
		r.ReqHeadersAdd = map[string]string{}
	}
	if r.RespHeadersAdd == nil {
		r.RespHeadersAdd = map[string]string{}
	}
	return r, nil
}

func (d *DB) ListRoutesByHost(ctx context.Context, hostID int) ([]Route, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT `+routeSelectCols+` FROM muvon.routes WHERE host_id = $1 ORDER BY priority DESC, path_prefix`, hostID)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	defer rows.Close()

	var routes []Route
	for rows.Next() {
		r, err := scanRoute(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list routes scan: %w", err)
		}
		routes = append(routes, r)
	}
	return routes, rows.Err()
}

func (d *DB) GetRoute(ctx context.Context, id int) (Route, error) {
	row := d.Pool.QueryRow(ctx,
		`SELECT `+routeSelectCols+` FROM routes WHERE id = $1`, id)
	r, err := scanRoute(row.Scan)
	if err != nil {
		return r, fmt.Errorf("get route: %w", err)
	}
	return r, nil
}

func (d *DB) CreateRoute(ctx context.Context, r Route) (Route, error) {
	if r.BackendURLs == nil {
		r.BackendURLs = []string{}
	}
	if r.WafExcludePaths == nil {
		r.WafExcludePaths = []string{}
	}
	if r.ReqHeadersDel == nil {
		r.ReqHeadersDel = []string{}
	}
	if r.RespHeadersDel == nil {
		r.RespHeadersDel = []string{}
	}
	reqAdd, _ := json.Marshal(r.ReqHeadersAdd)
	respAdd, _ := json.Marshal(r.RespHeadersAdd)
	row := d.Pool.QueryRow(ctx,
		`INSERT INTO routes (host_id, path_prefix, route_type, backend_url, backend_urls, managed_component_id, static_root, static_spa, redirect_url,
		                     strip_prefix, rewrite_pattern, rewrite_to, priority, is_active, log_enabled, waf_enabled,
		                     waf_exclude_paths, waf_detection_only, rate_limit_rps, rate_limit_burst,
		                     req_headers_add, req_headers_del, resp_headers_add, resp_headers_del,
		                     accel_root, accel_signed_secret,
		                     max_body_bytes, timeout_seconds,
		                     cors_enabled, cors_origins, cors_methods, cors_headers, cors_max_age, cors_credentials,
		                     error_page_4xx, error_page_5xx)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36)
		 RETURNING `+routeSelectCols,
		r.HostID, r.PathPrefix, r.RouteType, r.BackendURL, r.BackendURLs, r.ManagedComponentID, r.StaticRoot, r.StaticSPA, r.RedirectURL,
		r.StripPrefix, r.RewritePattern, r.RewriteTo, r.Priority, r.IsActive, r.LogEnabled, r.WafEnabled,
		r.WafExcludePaths, r.WafDetectionOnly, r.RateLimitRPS, r.RateLimitBurst,
		reqAdd, r.ReqHeadersDel, respAdd, r.RespHeadersDel,
		r.AccelRoot, r.AccelSignedSecret,
		r.MaxBodyBytes, r.TimeoutSeconds,
		r.CORSEnabled, r.CORSOrigins, r.CORSMethods, r.CORSHeaders, r.CORSMaxAge, r.CORSCredentials,
		r.ErrorPage4xx, r.ErrorPage5xx,
	)
	out, err := scanRoute(row.Scan)
	if err != nil {
		return out, fmt.Errorf("create route: %w", err)
	}
	return out, nil
}

func (d *DB) UpdateRoute(ctx context.Context, r Route) (Route, error) {
	if r.BackendURLs == nil {
		r.BackendURLs = []string{}
	}
	if r.WafExcludePaths == nil {
		r.WafExcludePaths = []string{}
	}
	if r.ReqHeadersDel == nil {
		r.ReqHeadersDel = []string{}
	}
	if r.RespHeadersDel == nil {
		r.RespHeadersDel = []string{}
	}
	reqAdd, _ := json.Marshal(r.ReqHeadersAdd)
	respAdd, _ := json.Marshal(r.RespHeadersAdd)
	row := d.Pool.QueryRow(ctx,
		`UPDATE routes SET host_id=$2, path_prefix=$3, route_type=$4, backend_url=$5, backend_urls=$6,
		        managed_component_id=$7, static_root=$8, static_spa=$9, redirect_url=$10, strip_prefix=$11, rewrite_pattern=$12, rewrite_to=$13,
		        priority=$14, is_active=$15, log_enabled=$16, waf_enabled=$17,
		        waf_exclude_paths=$18, waf_detection_only=$19, rate_limit_rps=$20, rate_limit_burst=$21,
		        req_headers_add=$22, req_headers_del=$23, resp_headers_add=$24, resp_headers_del=$25,
		        accel_root=$26, accel_signed_secret=$27,
		        max_body_bytes=$28, timeout_seconds=$29,
		        cors_enabled=$30, cors_origins=$31, cors_methods=$32, cors_headers=$33, cors_max_age=$34, cors_credentials=$35,
		        error_page_4xx=$36, error_page_5xx=$37,
		        updated_at=now()
		 WHERE id=$1
		 RETURNING `+routeSelectCols,
		r.ID, r.HostID, r.PathPrefix, r.RouteType, r.BackendURL, r.BackendURLs, r.ManagedComponentID, r.StaticRoot, r.StaticSPA, r.RedirectURL,
		r.StripPrefix, r.RewritePattern, r.RewriteTo, r.Priority, r.IsActive, r.LogEnabled, r.WafEnabled,
		r.WafExcludePaths, r.WafDetectionOnly, r.RateLimitRPS, r.RateLimitBurst,
		reqAdd, r.ReqHeadersDel, respAdd, r.RespHeadersDel,
		r.AccelRoot, r.AccelSignedSecret,
		r.MaxBodyBytes, r.TimeoutSeconds,
		r.CORSEnabled, r.CORSOrigins, r.CORSMethods, r.CORSHeaders, r.CORSMaxAge, r.CORSCredentials,
		r.ErrorPage4xx, r.ErrorPage5xx,
	)
	out, err := scanRoute(row.Scan)
	if err != nil {
		return out, fmt.Errorf("update route: %w", err)
	}
	return out, nil
}

func (d *DB) DeleteRoute(ctx context.Context, id int) error {
	ct, err := d.Pool.Exec(ctx, `DELETE FROM routes WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete route: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// --- All active hosts+routes for router config ---

func (d *DB) LoadActiveRoutes(ctx context.Context) ([]Host, map[int][]Route, error) {
	hosts, err := d.Pool.Query(ctx, `SELECT id, domain, is_active, force_https, created_at, updated_at FROM muvon.hosts WHERE is_active = true ORDER BY domain`)
	if err != nil {
		return nil, nil, fmt.Errorf("load active hosts: %w", err)
	}
	defer hosts.Close()

	var hostList []Host
	for hosts.Next() {
		var h Host
		if err := hosts.Scan(&h.ID, &h.Domain, &h.IsActive, &h.ForceHTTPS, &h.CreatedAt, &h.UpdatedAt); err != nil {
			return nil, nil, fmt.Errorf("load active hosts scan: %w", err)
		}
		hostList = append(hostList, h)
	}
	if err := hosts.Err(); err != nil {
		return nil, nil, err
	}

	routeMap := make(map[int][]Route)
	for _, h := range hostList {
		routes, err := d.ListRoutesByHost(ctx, h.ID)
		if err != nil {
			return nil, nil, err
		}
		var active []Route
		for _, r := range routes {
			if r.IsActive {
				active = append(active, r)
			}
		}
		routeMap[h.ID] = active
	}

	return hostList, routeMap, nil
}

// --- Settings ---

func (d *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var val string
	err := d.Pool.QueryRow(ctx, `SELECT value FROM muvon.settings WHERE key = $1`, key).Scan(&val)
	if err != nil {
		return "", fmt.Errorf("get setting %s: %w", key, err)
	}
	return val, nil
}

func (d *DB) GetAllSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := d.Pool.Query(ctx, `SELECT key, value FROM muvon.settings ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("get all settings: %w", err)
	}
	defer rows.Close()

	settings := make(map[string]json.RawMessage)
	for rows.Next() {
		var key string
		var val json.RawMessage
		if err := rows.Scan(&key, &val); err != nil {
			return nil, fmt.Errorf("get all settings scan: %w", err)
		}
		settings[key] = val
	}
	return settings, rows.Err()
}

func (d *DB) SetSetting(ctx context.Context, key string, value json.RawMessage) error {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO muvon.settings (key, value, updated_at) VALUES ($1, $2, now())
		 ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = now()`,
		key, value)
	if err != nil {
		return fmt.Errorf("set setting %s: %w", key, err)
	}
	return nil
}

// --- TLS Certificates ---

type TLSCert struct {
	ID        int       `json:"id"`
	Domain    string    `json:"domain"`
	CertPEM   []byte    `json:"-"`
	KeyPEM    []byte    `json:"-"`
	Issuer    string    `json:"issuer"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

const tlsCertificatePreferenceOrder = `
CASE WHEN expires_at > NOW() THEN 0 ELSE 1 END,
CASE WHEN issuer = 'manual' THEN 0 ELSE 1 END,
expires_at DESC,
created_at DESC,
id DESC`

func (d *DB) GetCertByDomain(ctx context.Context, domain string) (TLSCert, error) {
	var c TLSCert
	domain = strings.ToLower(strings.TrimSpace(domain))
	err := d.Pool.QueryRow(ctx,
		`SELECT id, domain, cert_pem, key_pem, issuer, expires_at, created_at
		 FROM tls_certificates
		 WHERE lower(domain) = $1
		 ORDER BY `+tlsCertificatePreferenceOrder+`
		 LIMIT 1`, domain,
	).Scan(&c.ID, &c.Domain, &c.CertPEM, &c.KeyPEM, &c.Issuer, &c.ExpiresAt, &c.CreatedAt)
	if err != nil {
		return c, fmt.Errorf("get cert: %w", err)
	}
	return c, nil
}

func (d *DB) UpsertCert(ctx context.Context, domain string, certPEM, keyPEM []byte, issuer string, expiresAt time.Time) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO tls_certificates (domain, cert_pem, key_pem, issuer, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (domain, issuer) DO UPDATE
		 SET cert_pem = EXCLUDED.cert_pem,
		     key_pem = EXCLUDED.key_pem,
		     expires_at = EXCLUDED.expires_at`,
		domain, certPEM, keyPEM, issuer, expiresAt)
	if err != nil {
		return fmt.Errorf("upsert cert: %w", err)
	}
	return nil
}

func (d *DB) ListCerts(ctx context.Context) ([]TLSCert, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT DISTINCT ON (domain) id, domain, issuer, expires_at, created_at
		 FROM tls_certificates
		 ORDER BY domain, `+tlsCertificatePreferenceOrder)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	defer rows.Close()

	var certs []TLSCert
	for rows.Next() {
		var c TLSCert
		if err := rows.Scan(&c.ID, &c.Domain, &c.Issuer, &c.ExpiresAt, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("list certs scan: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

func (d *DB) DeleteCert(ctx context.Context, id int) (string, error) {
	var domain string
	err := d.Pool.QueryRow(ctx, `DELETE FROM tls_certificates WHERE id = $1 RETURNING domain`, id).Scan(&domain)
	if err != nil {
		return "", fmt.Errorf("delete cert: %w", err)
	}
	return domain, nil
}

// --- ACME Cache ---

func (d *DB) AcmeCacheGet(ctx context.Context, key string) ([]byte, error) {
	var data []byte
	err := d.Pool.QueryRow(ctx, `SELECT data FROM acme_cache WHERE key = $1`, key).Scan(&data)
	if err != nil {
		return nil, fmt.Errorf("acme cache get %s: %w", key, err)
	}
	return data, nil
}

func (d *DB) AcmeCachePut(ctx context.Context, key string, data []byte) error {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO acme_cache (key, data, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
		key, data,
	)
	return err
}

func (d *DB) AcmeCacheDelete(ctx context.Context, key string) error {
	_, err := d.Pool.Exec(ctx, `DELETE FROM acme_cache WHERE key = $1`, key)
	return err
}

// --- Admin Users ---

type AdminUser struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	IsActive     bool      `json:"is_active"`
	TokenVersion int       `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

const adminUserCols = `id, username, password_hash, is_active, token_version, created_at`

func scanAdminUser(scan func(...any) error) (AdminUser, error) {
	var u AdminUser
	err := scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsActive, &u.TokenVersion, &u.CreatedAt)
	return u, err
}

func (d *DB) GetAdminByUsername(ctx context.Context, username string) (AdminUser, error) {
	u, err := scanAdminUser(d.Pool.QueryRow(ctx,
		`SELECT `+adminUserCols+` FROM admin_users WHERE username = $1`, username).Scan)
	if err != nil {
		return u, fmt.Errorf("get admin user: %w", err)
	}
	return u, nil
}

func (d *DB) GetAdminByID(ctx context.Context, id int) (AdminUser, error) {
	u, err := scanAdminUser(d.Pool.QueryRow(ctx,
		`SELECT `+adminUserCols+` FROM admin_users WHERE id = $1`, id).Scan)
	if err != nil {
		return u, fmt.Errorf("get admin user: %w", err)
	}
	return u, nil
}

func (d *DB) CreateAdmin(ctx context.Context, username, passwordHash string) (AdminUser, error) {
	u, err := scanAdminUser(d.Pool.QueryRow(ctx,
		`INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)
		 RETURNING `+adminUserCols,
		username, passwordHash).Scan)
	if err != nil {
		return u, fmt.Errorf("create admin: %w", err)
	}
	return u, nil
}

func (d *DB) AdminExists(ctx context.Context) (bool, error) {
	var count int
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM admin_users WHERE is_active = true`).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("admin exists: %w", err)
	}
	return count > 0, nil
}

// --- Log Queries ---

type LogSearchParams struct {
	Host            string
	Path            string
	Method          string
	StatusMin       int
	StatusMax       int
	ClientIP        string
	Query           string
	From            time.Time
	To              time.Time
	WafBlocked      *bool
	ResponseTimeMin int
	ResponseTimeMax int
	Starred         *bool
	// UserQuery matches against JWT identity claims. A request matches when
	// any of its enriched claims (email, sub, name) equals UserQuery — so
	// the admin can type "alice@foo.com" or a raw user id and get every
	// request attributed to that actor, regardless of which claim key the
	// upstream app happens to populate.
	UserQuery       string
	Limit           int
	Offset          int
}

type LogEntry struct {
	ID              string          `json:"id"`
	Timestamp       time.Time       `json:"timestamp"`
	Host            string          `json:"host"`
	ClientIP        string          `json:"client_ip"`
	Method          string          `json:"method"`
	Path            string          `json:"path"`
	QueryString     *string         `json:"query_string,omitempty"`
	RequestHeaders  json.RawMessage `json:"request_headers,omitempty"`
	ResponseStatus  int             `json:"response_status"`
	ResponseHeaders json.RawMessage `json:"response_headers,omitempty"`
	ResponseTimeMs  *int            `json:"response_time_ms,omitempty"`
	RequestSize     *int            `json:"request_size,omitempty"`
	ResponseSize    *int            `json:"response_size,omitempty"`
	UserAgent       *string         `json:"user_agent,omitempty"`
	Error           *string         `json:"error,omitempty"`
	WafBlocked      bool            `json:"waf_blocked"`
	WafBlockReason  *string         `json:"waf_block_reason,omitempty"`
	IsStarred       bool            `json:"is_starred"`
	Note            *string         `json:"note,omitempty"`
	Country         *string         `json:"country,omitempty"`
	City            *string         `json:"city,omitempty"`
	// JSONB column populated by the log pipeline's identity enricher.
	// Kept as RawMessage so the admin panel receives the exact shape the
	// enricher produced (claims, verified, source, exp_expired).
	UserIdentity    json.RawMessage `json:"user_identity,omitempty"`
}

type LogBody struct {
	RequestBody         *string `json:"request_body,omitempty"`
	ResponseBody        *string `json:"response_body,omitempty"`
	IsRequestTruncated  bool    `json:"is_request_truncated"`
	IsResponseTruncated bool    `json:"is_response_truncated"`
}

func (d *DB) SearchLogs(ctx context.Context, p LogSearchParams) ([]LogEntry, int, error) {
	if p.Limit <= 0 || p.Limit > 500 {
		p.Limit = 100
	}

	baseWhere := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if p.Host != "" {
		baseWhere += fmt.Sprintf(" AND l.host = $%d", argIdx)
		args = append(args, p.Host)
		argIdx++
	}
	if p.Path != "" {
		baseWhere += fmt.Sprintf(" AND l.path ILIKE $%d", argIdx)
		args = append(args, "%"+p.Path+"%")
		argIdx++
	}
	if p.Method != "" {
		baseWhere += fmt.Sprintf(" AND l.method = $%d", argIdx)
		args = append(args, p.Method)
		argIdx++
	}
	if p.StatusMin > 0 {
		baseWhere += fmt.Sprintf(" AND l.response_status >= $%d", argIdx)
		args = append(args, p.StatusMin)
		argIdx++
	}
	if p.StatusMax > 0 {
		baseWhere += fmt.Sprintf(" AND l.response_status <= $%d", argIdx)
		args = append(args, p.StatusMax)
		argIdx++
	}
	if p.ClientIP != "" {
		baseWhere += fmt.Sprintf(" AND l.client_ip ILIKE $%d", argIdx)
		args = append(args, "%"+p.ClientIP+"%")
		argIdx++
	}
	if p.Query != "" {
		baseWhere += fmt.Sprintf(" AND l.id @@@ paradedb.parse($%d)", argIdx)
		args = append(args, p.Query)
		argIdx++
	}
	if !p.From.IsZero() {
		baseWhere += fmt.Sprintf(" AND l.timestamp >= $%d", argIdx)
		args = append(args, p.From)
		argIdx++
	}
	if !p.To.IsZero() {
		baseWhere += fmt.Sprintf(" AND l.timestamp <= $%d", argIdx)
		args = append(args, p.To)
		argIdx++
	}
	if p.WafBlocked != nil {
		baseWhere += fmt.Sprintf(" AND l.waf_blocked = $%d", argIdx)
		args = append(args, *p.WafBlocked)
		argIdx++
	}
	if p.ResponseTimeMin > 0 {
		baseWhere += fmt.Sprintf(" AND l.response_time_ms >= $%d", argIdx)
		args = append(args, p.ResponseTimeMin)
		argIdx++
	}
	if p.ResponseTimeMax > 0 {
		baseWhere += fmt.Sprintf(" AND l.response_time_ms <= $%d", argIdx)
		args = append(args, p.ResponseTimeMax)
		argIdx++
	}
	if p.Starred != nil {
		baseWhere += fmt.Sprintf(" AND l.is_starred = $%d", argIdx)
		args = append(args, *p.Starred)
		argIdx++
	}
	if p.UserQuery != "" {
		// Match claims via JSONB containment. We OR across the three keys
		// admins typically type (email, sub, name) so the same search box
		// finds a user regardless of whether the upstream app signs the
		// token with "sub":"alice" or "email":"alice@foo.com".
		//
		// Each @> uses the GIN index from add_http_logs_user_identity_gin,
		// and the user value is JSON-encoded via json.Marshal so injected
		// quotes or backslashes cannot break out of the literal.
		email, _ := json.Marshal(map[string]string{"email": p.UserQuery})
		sub, _ := json.Marshal(map[string]string{"sub": p.UserQuery})
		name, _ := json.Marshal(map[string]string{"name": p.UserQuery})
		baseWhere += fmt.Sprintf(
			` AND ((l.user_identity->'claims') @> $%d::jsonb
			    OR (l.user_identity->'claims') @> $%d::jsonb
			    OR (l.user_identity->'claims') @> $%d::jsonb)`,
			argIdx, argIdx+1, argIdx+2,
		)
		args = append(args, string(email), string(sub), string(name))
		argIdx += 3
	}

	// Count query uses http_logs aliased as l
	var total int
	countQuery := "SELECT COUNT(*) FROM http_logs l " + baseWhere
	if err := d.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("search logs count: %w", err)
	}

	query := fmt.Sprintf(
		`SELECT l.id::text, l.timestamp, l.host, l.client_ip, l.method, l.path, l.query_string,
		        l.request_headers, l.response_status, l.response_headers, l.response_time_ms,
		        l.request_size, l.response_size, l.user_agent, l.error, l.waf_blocked, l.waf_block_reason,
		        l.is_starred, n.note, l.country, l.city, l.user_identity
		 FROM http_logs l
		 LEFT JOIN log_notes n ON n.log_id = l.id
		 %s ORDER BY l.timestamp DESC LIMIT $%d OFFSET $%d`,
		baseWhere, argIdx, argIdx+1)
	args = append(args, p.Limit, p.Offset)

	rows, err := d.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search logs: %w", err)
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Host, &e.ClientIP, &e.Method, &e.Path,
			&e.QueryString, &e.RequestHeaders, &e.ResponseStatus, &e.ResponseHeaders,
			&e.ResponseTimeMs, &e.RequestSize, &e.ResponseSize, &e.UserAgent, &e.Error,
			&e.WafBlocked, &e.WafBlockReason, &e.IsStarred, &e.Note, &e.Country, &e.City,
			&e.UserIdentity); err != nil {
			return nil, 0, fmt.Errorf("search logs scan: %w", err)
		}
		entries = append(entries, e)
	}

	return entries, total, rows.Err()
}

func (d *DB) GetLogDetail(ctx context.Context, id string) (LogEntry, LogBody, error) {
	var e LogEntry
	err := d.Pool.QueryRow(ctx,
		`SELECT l.id::text, l.timestamp, l.host, l.client_ip, l.method, l.path, l.query_string,
		        l.request_headers, l.response_status, l.response_headers, l.response_time_ms,
		        l.request_size, l.response_size, l.user_agent, l.error, l.waf_blocked, l.waf_block_reason,
		        l.is_starred, n.note, l.country, l.city, l.user_identity
		 FROM http_logs l
		 LEFT JOIN log_notes n ON n.log_id = l.id
		 WHERE l.id = $1`, id,
	).Scan(&e.ID, &e.Timestamp, &e.Host, &e.ClientIP, &e.Method, &e.Path,
		&e.QueryString, &e.RequestHeaders, &e.ResponseStatus, &e.ResponseHeaders,
		&e.ResponseTimeMs, &e.RequestSize, &e.ResponseSize, &e.UserAgent, &e.Error,
		&e.WafBlocked, &e.WafBlockReason, &e.IsStarred, &e.Note, &e.Country, &e.City,
		&e.UserIdentity)
	if err != nil {
		return e, LogBody{}, fmt.Errorf("get log detail: %w", err)
	}

	var b LogBody
	_ = d.Pool.QueryRow(ctx,
		`SELECT request_body, response_body, is_request_truncated, is_response_truncated
		 FROM http_log_bodies WHERE log_id = $1 LIMIT 1`, id,
	).Scan(&b.RequestBody, &b.ResponseBody, &b.IsRequestTruncated, &b.IsResponseTruncated)

	return e, b, nil
}

// --- Log Notes ---

func (d *DB) UpsertLogNote(ctx context.Context, logID string, note, updatedBy string) error {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO log_notes (log_id, note, updated_by, updated_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (log_id) DO UPDATE SET note = $2, updated_by = $3, updated_at = now()`,
		logID, note, updatedBy)
	if err != nil {
		return fmt.Errorf("upsert log note: %w", err)
	}
	return nil
}

// --- Log Star ---

func (d *DB) ToggleLogStar(ctx context.Context, logID string) (bool, error) {
	var starred bool
	err := d.Pool.QueryRow(ctx,
		`UPDATE http_logs SET is_starred = NOT is_starred WHERE id = $1 RETURNING is_starred`,
		logID,
	).Scan(&starred)
	if err != nil {
		return false, fmt.Errorf("toggle log star: %w", err)
	}
	return starred, nil
}

// --- Audit Log ---

type AuditEntry struct {
	ID         int64           `json:"id"`
	Timestamp  time.Time       `json:"timestamp"`
	AdminUser  string          `json:"admin_user"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Detail     json.RawMessage `json:"detail,omitempty"`
	IP         string          `json:"ip"`
}

func (d *DB) WriteAuditLog(ctx context.Context, adminUser, action, targetType, targetID, ip string, detail any) {
	var detailJSON json.RawMessage
	if detail != nil {
		detailJSON, _ = json.Marshal(detail)
	}
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO admin_audit_log (admin_user, action, target_type, target_id, detail, ip)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		adminUser, action, targetType, targetID, detailJSON, ip)
	if err != nil {
		slog.Error("write audit log", "error", err)
	}
}

type AuditSearchParams struct {
	Action string
	From   time.Time
	To     time.Time
	Limit  int
	Offset int
}

func (d *DB) ListAuditLog(ctx context.Context, p AuditSearchParams) ([]AuditEntry, int, error) {
	if p.Limit <= 0 || p.Limit > 500 {
		p.Limit = 100
	}
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1
	if p.Action != "" {
		where += fmt.Sprintf(" AND action ILIKE $%d", argIdx)
		args = append(args, "%"+p.Action+"%")
		argIdx++
	}
	if !p.From.IsZero() {
		where += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		args = append(args, p.From)
		argIdx++
	}
	if !p.To.IsZero() {
		where += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		args = append(args, p.To)
		argIdx++
	}

	var total int
	if err := d.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM admin_audit_log "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("list audit count: %w", err)
	}

	q := fmt.Sprintf(
		`SELECT id, timestamp, admin_user, action, target_type, target_id, detail, ip
		 FROM admin_audit_log %s ORDER BY timestamp DESC LIMIT $%d OFFSET $%d`,
		where, argIdx, argIdx+1)
	args = append(args, p.Limit, p.Offset)

	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.AdminUser, &e.Action,
			&e.TargetType, &e.TargetID, &e.Detail, &e.IP); err != nil {
			return nil, 0, fmt.Errorf("list audit scan: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

type LogStats struct {
	TotalRequests  int64            `json:"total_requests"`
	StatusCounts   map[string]int64 `json:"status_counts"`
	TopHosts       []HostCount      `json:"top_hosts"`
	TopPaths       []PathCount      `json:"top_paths"`
	TopCountries   []CountryCount   `json:"top_countries"`
	TopUsers       []UserCount      `json:"top_users"`
	AvgResponseMs  float64          `json:"avg_response_ms"`
	RequestsPerMin float64          `json:"requests_per_min"`
}

type CountryCount struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

type HostCount struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

type PathCount struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// UserCount summarises request volume per identified user.
// Display is the human-friendly label (email > name > sub) the admin sees in
// lists; Query is the raw value that SearchLogs' UserQuery will match on so
// the UI can link "Top Users" row → filtered /logs?user=<query>.
type UserCount struct {
	Display string `json:"display"`
	Query   string `json:"query"`
	Count   int64  `json:"count"`
}

func (d *DB) GetLogStats(ctx context.Context, from, to time.Time) (LogStats, error) {
	var stats LogStats
	stats.StatusCounts = make(map[string]int64)

	timeFilter := ""
	args := []any{}
	argIdx := 1
	if !from.IsZero() {
		timeFilter += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		args = append(args, from)
		argIdx++
	}
	if !to.IsZero() {
		timeFilter += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		args = append(args, to)
		argIdx++
	}

	where := "WHERE 1=1" + timeFilter

	// Total requests + avg response time
	err := d.Pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT COALESCE(COUNT(*),0), COALESCE(AVG(response_time_ms),0) FROM http_logs %s`, where),
		args...,
	).Scan(&stats.TotalRequests, &stats.AvgResponseMs)
	if err != nil {
		return stats, fmt.Errorf("log stats total: %w", err)
	}

	// Status code distribution
	rows, err := d.Pool.Query(ctx,
		fmt.Sprintf(`SELECT CONCAT(FLOOR(response_status/100)::int, 'xx') as status_group, COUNT(*)
		 FROM http_logs %s GROUP BY status_group ORDER BY status_group`, where),
		args...)
	if err != nil {
		return stats, fmt.Errorf("log stats status: %w", err)
	}
	for rows.Next() {
		var group string
		var count int64
		if err := rows.Scan(&group, &count); err != nil {
			rows.Close()
			return stats, err
		}
		stats.StatusCounts[group] = count
	}
	rows.Close()

	// Top hosts
	rows, err = d.Pool.Query(ctx,
		fmt.Sprintf(`SELECT host, COUNT(*) as cnt FROM http_logs %s GROUP BY host ORDER BY cnt DESC LIMIT 10`, where),
		args...)
	if err != nil {
		return stats, fmt.Errorf("log stats hosts: %w", err)
	}
	for rows.Next() {
		var hc HostCount
		if err := rows.Scan(&hc.Host, &hc.Count); err != nil {
			rows.Close()
			return stats, err
		}
		stats.TopHosts = append(stats.TopHosts, hc)
	}
	rows.Close()

	// Top paths
	rows, err = d.Pool.Query(ctx,
		fmt.Sprintf(`SELECT path, COUNT(*) as cnt FROM http_logs %s GROUP BY path ORDER BY cnt DESC LIMIT 10`, where),
		args...)
	if err != nil {
		return stats, fmt.Errorf("log stats paths: %w", err)
	}
	for rows.Next() {
		var pc PathCount
		if err := rows.Scan(&pc.Path, &pc.Count); err != nil {
			rows.Close()
			return stats, err
		}
		stats.TopPaths = append(stats.TopPaths, pc)
	}
	rows.Close()

	// Requests per minute (last hour)
	err = d.Pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*)::float / GREATEST(EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp)))/60, 1), 0)
		 FROM http_logs WHERE timestamp >= now() - interval '1 hour'`,
	).Scan(&stats.RequestsPerMin)
	if err != nil {
		return stats, fmt.Errorf("log stats rpm: %w", err)
	}

	// Top countries
	rows, err = d.Pool.Query(ctx,
		fmt.Sprintf(`SELECT COALESCE(country, 'Unknown'), COUNT(*) as cnt FROM http_logs %s
		 AND country IS NOT NULL AND country != ''
		 GROUP BY country ORDER BY cnt DESC LIMIT 10`, where),
		args...)
	if err != nil {
		return stats, fmt.Errorf("log stats countries: %w", err)
	}
	for rows.Next() {
		var cc CountryCount
		if err := rows.Scan(&cc.Country, &cc.Count); err != nil {
			rows.Close()
			return stats, err
		}
		stats.TopCountries = append(stats.TopCountries, cc)
	}
	rows.Close()

	// Top users. Display value is email > name > sub (whichever is first
	// present) so the admin recognises who a row belongs to without
	// cross-referencing a user DB. Subquery keeps the SELECT expression
	// and the NOT NULL filter in one place instead of repeating the
	// COALESCE inside HAVING.
	rows, err = d.Pool.Query(ctx,
		fmt.Sprintf(`SELECT user_key, cnt FROM (
			SELECT
				COALESCE(
					NULLIF(user_identity->'claims'->>'email', ''),
					NULLIF(user_identity->'claims'->>'name', ''),
					NULLIF(user_identity->'claims'->>'sub', '')
				) AS user_key,
				COUNT(*) AS cnt
			FROM http_logs %s
			AND user_identity IS NOT NULL
			GROUP BY 1
		) u
		WHERE user_key IS NOT NULL
		ORDER BY cnt DESC
		LIMIT 10`, where),
		args...)
	if err != nil {
		return stats, fmt.Errorf("log stats users: %w", err)
	}
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			rows.Close()
			return stats, err
		}
		stats.TopUsers = append(stats.TopUsers, UserCount{Display: key, Query: key, Count: count})
	}
	rows.Close()

	return stats, nil
}

// --- Alert Queries ---

type AlertRecord struct {
	Rule        string
	Severity    string
	Title       string
	Detail      json.RawMessage
	SourceIP    string
	Host        string
	Fingerprint string
	Notified    bool
}

func (d *DB) InsertAlert(ctx context.Context, a AlertRecord) error {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO alerts (rule, severity, title, detail, source_ip, host, fingerprint, notified, notified_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CASE WHEN $8 THEN now() ELSE NULL END)`,
		a.Rule, a.Severity, a.Title, a.Detail, a.SourceIP, a.Host, a.Fingerprint, a.Notified,
	)
	if err != nil {
		return fmt.Errorf("insert alert: %w", err)
	}
	return nil
}

// UpsertAlertResult reports how UpsertAlert resolved the event.
//
// ShouldNotify is the single source of truth for "did this call dispatch
// Slack / email?" — the alert manager must treat it as authoritative, even
// across nodes. Grouped=true means an existing alert row inside the
// cooldown window was extended instead of a new row being written; in that
// case ShouldNotify is always false (cooldown suppressed notification) but
// occurrences was bumped so the UI still reflects the event.
type UpsertAlertResult struct {
	ShouldNotify bool
	Grouped      bool
	Occurrences  int
}

// UpsertAlert implements multi-node alert cooldown + occurrence grouping in
// a single transaction. The decision tree:
//
//  1. Find the most recent row for this fingerprint whose notified_at is
//     within the cooldown window. FOR UPDATE locks it so concurrent
//     workers on any node serialize behind us.
//  2. If one exists: bump occurrences, slide last_seen_at forward. Return
//     Grouped=true, ShouldNotify=false. Slack will NOT fire — another node
//     already notified inside the window.
//  3. If none exists: insert a fresh row with notified=notifyRequested and
//     notified_at=now() (iff notifyRequested). Return ShouldNotify equal to
//     notifyRequested. The caller then tries the notifiers; if they succeed
//     the DB already reflects it, if they fail we leave the row as
//     "notified=true but dispatch erroneous" — acceptable, we would rather
//     over-report a failure than duplicate a Slack message.
//
// cooldown=0 disables DB grouping entirely and always inserts.
func (d *DB) UpsertAlert(ctx context.Context, a AlertRecord, cooldown time.Duration, notifyRequested bool) (UpsertAlertResult, error) {
	var res UpsertAlertResult

	if cooldown <= 0 {
		// No cooldown → every event is a new row. Preserve the old behaviour.
		if err := d.InsertAlert(ctx, AlertRecord{
			Rule: a.Rule, Severity: a.Severity, Title: a.Title, Detail: a.Detail,
			SourceIP: a.SourceIP, Host: a.Host, Fingerprint: a.Fingerprint,
			Notified: notifyRequested,
		}); err != nil {
			return res, err
		}
		res.ShouldNotify = notifyRequested
		res.Occurrences = 1
		return res, nil
	}

	err := pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		cutoff := time.Now().Add(-cooldown)

		var (
			id          string
			occurrences int
		)
		row := tx.QueryRow(ctx, `
			SELECT id::text, occurrences
			FROM alerts
			WHERE fingerprint = $1 AND notified_at IS NOT NULL AND notified_at >= $2
			ORDER BY notified_at DESC
			LIMIT 1
			FOR UPDATE`, a.Fingerprint, cutoff)

		err := row.Scan(&id, &occurrences)
		switch {
		case err == nil:
			// Existing alert inside cooldown — bump occurrences, slide last_seen_at.
			if _, err := tx.Exec(ctx, `
				UPDATE alerts
				SET occurrences = occurrences + 1,
				    last_seen_at = now()
				WHERE id = $1::uuid`, id); err != nil {
				return fmt.Errorf("upsert alert: bump occurrences: %w", err)
			}
			res.Grouped = true
			res.Occurrences = occurrences + 1
			res.ShouldNotify = false
			return nil

		case errors.Is(err, pgx.ErrNoRows):
			// No active alert — insert a fresh row.
			if _, err := tx.Exec(ctx, `
				INSERT INTO alerts
					(rule, severity, title, detail, source_ip, host, fingerprint,
					 notified, notified_at, last_seen_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
					CASE WHEN $8 THEN now() ELSE NULL END,
					now())`,
				a.Rule, a.Severity, a.Title, a.Detail, a.SourceIP, a.Host, a.Fingerprint,
				notifyRequested); err != nil {
				return fmt.Errorf("upsert alert: insert: %w", err)
			}
			res.Occurrences = 1
			res.ShouldNotify = notifyRequested
			return nil

		default:
			return fmt.Errorf("upsert alert: lookup: %w", err)
		}
	})
	if err != nil {
		return res, err
	}
	return res, nil
}
