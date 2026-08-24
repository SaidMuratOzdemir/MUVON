package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"muvon/internal/alerting"
	"muvon/internal/config"
	"muvon/internal/correlation"
	"muvon/internal/db"
	"muvon/internal/identity"
	"muvon/internal/logger"
	loggrpc "muvon/internal/logger/grpcserver"
	"muvon/internal/secret"
	"muvon/internal/version"
	pb "muvon/proto/logpb"
)

func main() {
	var (
		dsn        = flag.String("dsn", envOr("DIALOG_DSN", "postgres://dialog:dialog@localhost:5432/dialog?sslmode=disable"), "PostgreSQL connection string")
		socketPath = flag.String("socket", envOr("DIALOG_SOCKET", "/tmp/dialog.sock"), "Unix socket path for gRPC")
		tcpAddr    = flag.String("tcp-addr", envOr("DIALOG_TCP_ADDR", ""), "TCP listen address for agent log ingestion (e.g. :9001)")
		bufSize    = flag.Int("buffer", intEnvOr("DIALOG_BUFFER", 10000), "Log pipeline buffer size")
		workers    = flag.Int("workers", intEnvOr("DIALOG_WORKERS", 4), "Log pipeline worker count")
		batchSize  = flag.Int("batch", intEnvOr("DIALOG_BATCH", 1000), "Log pipeline batch size")
		flushMs    = flag.Int("flush-ms", intEnvOr("DIALOG_FLUSH_MS", 2000), "Log pipeline flush interval (ms)")
		// Container log pipeline — parallel to the http path; lower
		// defaults because container stdout volume is typically a
		// fraction of HTTP traffic (and we'd rather pay an extra worker
		// later than burn DB connections for nothing).
		cBufSize               = flag.Int("container-buffer", intEnvOr("DIALOG_CONTAINER_BUFFER", 10000), "Container log pipeline buffer size")
		cWorkers               = flag.Int("container-workers", intEnvOr("DIALOG_CONTAINER_WORKERS", 2), "Container log pipeline worker count")
		cBatch                 = flag.Int("container-batch", intEnvOr("DIALOG_CONTAINER_BATCH", 1000), "Container log pipeline batch size")
		cFlushMs               = flag.Int("container-flush-ms", intEnvOr("DIALOG_CONTAINER_FLUSH_MS", 2000), "Container log pipeline flush interval (ms)")
		containerIngestEnabled = flag.Bool("container-ingest", boolEnvOr("DIALOG_CONTAINER_INGEST", true), "Enable container log ingest pipeline")

		ceBufSize                = flag.Int("client-event-buffer", intEnvOr("DIALOG_CLIENT_EVENT_BUFFER", 10000), "Client event pipeline buffer size")
		ceWorkers                = flag.Int("client-event-workers", intEnvOr("DIALOG_CLIENT_EVENT_WORKERS", 2), "Client event pipeline worker count")
		ceBatch                  = flag.Int("client-event-batch", intEnvOr("DIALOG_CLIENT_EVENT_BATCH", 1000), "Client event pipeline batch size")
		ceFlushMs                = flag.Int("client-event-flush-ms", intEnvOr("DIALOG_CLIENT_EVENT_FLUSH_MS", 2000), "Client event pipeline flush interval (ms)")
		clientEventIngestEnabled = flag.Bool("client-event-ingest", boolEnvOr("DIALOG_CLIENT_EVENT_INGEST", true), "Enable client event (RUM) ingest pipeline")
		logLevel                 = flag.String("log-level", envOr("DIALOG_LOG_LEVEL", "info"), "Log level")
		encryptionKey            = flag.String("encryption-key", envOr("MUVON_ENCRYPTION_KEY", ""), "AES-256-GCM encryption key for secrets in DB")
		showVersion              = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println("dialog-siem " + version.String())
		return
	}
	setupLogger(*logLevel)

	slog.Info("diaLOG SIEM starting", "version", version.String(), "socket", *socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database — dialog is the primary schema for reads/writes, but config
	// also pulls from the muvon schema (hosts, routes, deploy_*) so we add
	// it to search_path rather than qualifying every config query.
	database, err := db.New(ctx, *dsn, "dialog", "muvon")
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := database.RunMigrations(ctx); err != nil {
		slog.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	// Config holder — for alerting settings
	box, err := secret.NewBox(*encryptionKey)
	if err != nil {
		slog.Error("MUVON_ENCRYPTION_KEY is required: alerting settings such as the SMTP password are stored encrypted", "error", err)
		os.Exit(1)
	}
	dbSrc := config.NewDBSource(database, box)
	ch := config.NewHolder(dbSrc, box)
	if err := ch.Init(ctx); err != nil {
		slog.Warn("config init failed, alerting may be unavailable", "error", err)
	}

	// Background config reload. Without this the snapshot loaded at
	// startup is frozen — admin-panel changes to JWT identity,
	// correlation thresholds, and alerting config never reach this
	// process. MUVON runs an equivalent loop in its own main; matching
	// the cadence here keeps the two services in sync within ~5s.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := ch.Reload(ctx); err != nil {
					slog.Warn("background config reload failed", "error", err)
				}
			}
		}
	}()

	// Retention reconciler. The admin panel's retention_days setting is the
	// only place an operator states how long diaLOG keeps log data, but
	// Timescale enforces it from its own job catalog, so the two drift apart
	// silently unless something writes the setting through. Migrations only
	// install the initial policy (if_not_exists), so without this loop the
	// panel value is decoration.
	go runRetentionReconciler(ctx, database, ch)
	go runCompressionReconciler(ctx, database, ch)

	// Pipeline sizing. log_pipeline_buffer, log_worker_count, log_batch_size
	// and log_flush_interval_ms are seeded into the settings table and parsed
	// into GlobalConfig, but nothing ever read them: the pipelines were built
	// purely from flags, so an operator tuning them through the API changed
	// nothing. They apply now, at startup only — resizing a running pipeline
	// would mean dropping whatever it is holding — and an explicitly passed
	// flag or environment variable still wins, because that is the one the
	// person at the host chose deliberately.
	if cfg := ch.Get(); cfg != nil {
		g := cfg.Global
		*bufSize = settingOrFlag("buffer", "DIALOG_BUFFER", *bufSize, g.LogPipelineBuffer)
		*workers = settingOrFlag("workers", "DIALOG_WORKERS", *workers, g.LogWorkerCount)
		*batchSize = settingOrFlag("batch", "DIALOG_BATCH", *batchSize, g.LogBatchSize)
		*flushMs = settingOrFlag("flush-ms", "DIALOG_FLUSH_MS", *flushMs, g.LogFlushIntervalMs)
	}
	slog.Info("http log pipeline sizing",
		"buffer", *bufSize, "workers", *workers, "batch", *batchSize, "flush_ms", *flushMs)

	// Log pipeline
	flushInterval := time.Duration(*flushMs) * time.Millisecond
	pipeline := logger.NewPipeline(database.Pool, *bufSize, *workers, *batchSize, flushInterval)

	// Container log pipeline — runs only when ingest is on. Producers
	// (deployer logship, agent dockerwatch) push batches via gRPC;
	// SendContainerLogBatch on the registered server fans them through
	// this pipeline to the container_logs hypertable.
	var containerPipeline *logger.ContainerPipeline
	if *containerIngestEnabled {
		containerFlushInterval := time.Duration(*cFlushMs) * time.Millisecond
		containerPipeline = logger.NewContainerPipeline(database.Pool, *cBufSize, *cWorkers, *cBatch, containerFlushInterval)
	} else {
		slog.Info("container log ingest disabled (DIALOG_CONTAINER_INGEST=false)")
	}

	// Client event (RUM) pipeline — fed by the edge's /__muvon/rum handler
	// via SendClientEventBatch. Location arrives already stamped by the edge
	// from Cloudflare, like the client IP.
	var clientEventPipeline *logger.ClientEventPipeline
	if *clientEventIngestEnabled {
		clientEventFlushInterval := time.Duration(*ceFlushMs) * time.Millisecond
		clientEventPipeline = logger.NewClientEventPipeline(database.Pool, *ceBufSize, *ceWorkers, *ceBatch, clientEventFlushInterval)
	} else {
		slog.Info("client event ingest disabled (DIALOG_CLIENT_EVENT_INGEST=false)")
	}

	// JWT identity enrichment — extracts claims from Authorization header
	// centrally. Host-scoped override wins when that host's override is
	// enabled; otherwise we fall back to the global config. This lets a
	// single MUVON front multiple tenant apps that sign with different
	// secrets.
	pipeline.SetIdentityHeaderResolver(func(host string) string {
		cfg := ch.Get()
		if hc, ok := cfg.Hosts[host]; ok && hc.IdentityHeaderName != "" {
			return hc.IdentityHeaderName
		}
		return "Authorization"
	})
	pipeline.SetRawTokenPolicy(func(host string) bool {
		cfg := ch.Get()
		hc, ok := cfg.Hosts[host]
		return ok && hc.StoreRawJWT
	})
	idExtractor := &identity.Extractor{}
	pipeline.SetIdentityEnricher(func(host, authHeader string) *logger.UserIdentity {
		cfg := ch.Get()
		if host != "" {
			if hc, ok := cfg.Hosts[host]; ok && hc.JWTIdentityEnabled {
				claims := hc.JWTClaims
				if len(claims) == 0 {
					claims = cfg.Global.JWTClaims
				}
				return idExtractor.ExtractFromBearer(authHeader, identity.Config{
					Enabled: true,
					Secret:  hc.JWTSecret,
					Claims:  claims,
				})
			}
		}
		return idExtractor.ExtractFromBearer(authHeader, identity.Config{
			Enabled: cfg.Global.JWTIdentityEnabled,
			Secret:  cfg.Global.JWTSecret,
			Claims:  cfg.Global.JWTClaims,
		})
	})

	// Alerting manager
	alertMgr := alerting.NewManager(database, func() alerting.Config {
		cfg := ch.Get()
		return alerting.Config{
			Enabled:         cfg.Global.AlertingEnabled,
			SlackWebhook:    cfg.Global.AlertingSlackWebhook,
			SMTPHost:        cfg.Global.AlertingSMTPHost,
			SMTPPort:        cfg.Global.AlertingSMTPPort,
			SMTPUsername:    cfg.Global.AlertingSMTPUsername,
			SMTPPassword:    cfg.Global.AlertingSMTPPassword,
			SMTPFrom:        cfg.Global.AlertingSMTPFrom,
			SMTPTo:          cfg.Global.AlertingSMTPTo,
			CooldownSeconds: cfg.Global.AlertingCooldownSeconds,
		}
	})
	alertMgr.AddNotifier(alerting.NewSlackNotifier(func() string {
		return ch.Get().Global.AlertingSlackWebhook
	}))
	alertMgr.AddNotifier(alerting.NewEmailNotifier(func() alerting.Config {
		cfg := ch.Get()
		return alerting.Config{
			SMTPHost:     cfg.Global.AlertingSMTPHost,
			SMTPPort:     cfg.Global.AlertingSMTPPort,
			SMTPUsername: cfg.Global.AlertingSMTPUsername,
			SMTPPassword: cfg.Global.AlertingSMTPPassword,
			SMTPFrom:     cfg.Global.AlertingSMTPFrom,
			SMTPTo:       cfg.Global.AlertingSMTPTo,
		}
	}))
	alertMgr.Start()

	// Correlation engine — subscribes to pipeline, produces alerts.
	// The config func is read on every event so admin-panel changes to
	// thresholds / paths take effect immediately after a config reload.
	corrEngine := correlation.New(alertMgr, func() config.CorrelationConfig {
		return ch.Get().Global.Correlation
	})
	corrEngine.Run(pipeline)

	// Certificate expiry watch. Days-left is visible in the panel, but only
	// to someone who goes looking; renewal is due at 30 days, so a
	// certificate still inside 14 means renewal is broken rather than merely
	// approaching. This raises that through the normal alerting path.
	go runCertExpiryWatch(ctx, database, alertMgr)

	// gRPC server on Unix socket
	os.Remove(*socketPath)
	lis, err := net.Listen("unix", *socketPath)
	if err != nil {
		slog.Error("unix socket listen failed", "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	// Pass the config holder's Get so read handlers (SearchLogs / GetLog /
	// GetLogStats) can resolve JWT display claim priority per-host from
	// live config, with the global list as fallback. No hard-coded claim
	// vocabulary in the server itself.
	logSrv := loggrpc.New(pipeline, database, ch.Get)
	if containerPipeline != nil {
		logSrv.SetContainerPipeline(containerPipeline)
	}
	if clientEventPipeline != nil {
		logSrv.SetClientEventPipeline(clientEventPipeline)
	}
	logSrv.SetEnrichmentStatusFn(func() *pb.EnrichmentStatusResponse {
		resp := &pb.EnrichmentStatusResponse{}
		cfg := ch.Get()
		if cfg.Global.JWTIdentityEnabled || hasHostJWTOverride(cfg) {
			resp.JwtIdentityState = "ok"
		} else {
			resp.JwtIdentityState = "disabled"
		}
		resp.JwtIdentityHostOverrides = int32(countHostJWTOverrides(cfg))
		return resp
	})
	pb.RegisterLogServiceServer(grpcServer, logSrv)

	// TCP gRPC server — for agents sending logs over the network
	var tcpServer *grpc.Server

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		grpcServer.GracefulStop()
		if tcpServer != nil {
			tcpServer.GracefulStop()
		}
		corrEngine.Stop()
		pipeline.Stop()
		if containerPipeline != nil {
			containerPipeline.Stop()
		}
		if clientEventPipeline != nil {
			clientEventPipeline.Stop()
		}
		alertMgr.Stop()
		cancel()
	}()
	if *tcpAddr != "" {
		tcpLis, err := net.Listen("tcp", *tcpAddr)
		if err != nil {
			slog.Error("tcp listen failed", "addr", *tcpAddr, "error", err)
			os.Exit(1)
		}
		tcpServer = grpc.NewServer(
			grpc.UnaryInterceptor(agentKeyUnaryInterceptor(database)),
			grpc.StreamInterceptor(agentKeyStreamInterceptor(database)),
		)
		pb.RegisterLogServiceServer(tcpServer, logSrv)
		go func() {
			slog.Info("diaLOG TCP gRPC listening", "addr", *tcpAddr)
			if err := tcpServer.Serve(tcpLis); err != nil {
				slog.Error("TCP gRPC server error", "error", err)
			}
		}()
	}

	slog.Info("diaLOG gRPC server listening", "socket", *socketPath)
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("gRPC server error", "error", err)
		os.Exit(1)
	}

	slog.Info("diaLOG shutdown complete")
}

func agentKeyUnaryInterceptor(database *db.DB) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := validateAgentKey(ctx, database); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func agentKeyStreamInterceptor(database *db.DB) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := validateAgentKey(ss.Context(), database); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func validateAgentKey(ctx context.Context, database *db.DB) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	keys := md.Get("x-api-key")
	if len(keys) == 0 {
		return status.Error(codes.Unauthenticated, "missing x-api-key")
	}
	valid, err := database.ValidateAgentKey(ctx, keys[0])
	if err != nil || !valid {
		return status.Error(codes.Unauthenticated, "invalid api key")
	}
	return nil
}

func setupLogger(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// hasHostJWTOverride returns true when at least one host has its own JWT
// identity config turned on. The overall enrichment state is still "ok" in
// that case even when the global toggle is off, because the SIEM will pick
// up identities for those hosts.
func hasHostJWTOverride(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, hc := range cfg.Hosts {
		if hc.JWTIdentityEnabled {
			return true
		}
	}
	return false
}

func countHostJWTOverrides(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	n := 0
	for _, hc := range cfg.Hosts {
		if hc.JWTIdentityEnabled {
			n++
		}
	}
	return n
}

// certExpiryAlertWindow is when a certificate becomes newsworthy. ACME renews
// 30 days out, so anything still standing at 14 days is not "due for renewal",
// it is evidence that renewal is not happening. Alerting at 30 would fire on
// every healthy certificate and teach the operator to ignore it.
const certExpiryAlertWindow = 14 * 24 * time.Hour

// certExpiryCheckInterval is how often the fleet is swept. Certificates move
// slowly; a few hours of delay costs nothing and keeps the query rare.
const certExpiryCheckInterval = 6 * time.Hour

// runCertExpiryWatch raises an alert for certificates that are close to expiry
// despite renewal being automatic. Cooldown, storage and fan-out are the
// alerting manager's job, keyed by the fingerprint below, so a domain does not
// re-notify on every sweep.
func runCertExpiryWatch(ctx context.Context, database *db.DB, sink *alerting.Manager) {
	check := func() {
		certs, err := database.ListExpiringCerts(ctx, certExpiryAlertWindow)
		if err != nil {
			slog.Warn("certificate expiry check failed", "error", err)
			return
		}
		for _, c := range certs {
			severity := "warning"
			title := fmt.Sprintf("TLS sertifikası %d gün sonra doluyor: %s", c.DaysLeft, c.Domain)
			switch {
			case c.DaysLeft < 0:
				severity = "critical"
				title = fmt.Sprintf("TLS sertifikasının süresi doldu: %s", c.Domain)
			case c.DaysLeft <= 3:
				severity = "critical"
			}
			sink.HandleAlert(ctx, correlation.Alert{
				Rule:     "tls_cert_expiring",
				Severity: severity,
				Title:    title,
				Host:     c.Domain,
				Detail: map[string]any{
					"domain":     c.Domain,
					"days_left":  c.DaysLeft,
					"expires_at": c.ExpiresAt.UTC().Format(time.RFC3339),
					"issuer":     c.Issuer,
					"tls_mode":   c.TLSMode,
					"terminator": c.Terminator,
					"note":       "Otomatik yenileme 30 gün kala çalışır; bu noktaya gelmiş olması yenilemenin yapılmadığını gösterir.",
				},
				// One fingerprint per domain: the cooldown then decides how
				// often it repeats, rather than every sweep re-notifying.
				Fingerprint: "tls_cert_expiring:" + c.Domain,
			})
			slog.Warn("certificate nearing expiry",
				"domain", c.Domain, "days_left", c.DaysLeft, "issuer", c.Issuer, "terminator", c.Terminator)
		}
	}

	// A first pass shortly after boot, then on the slow cadence.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			check()
			timer.Reset(certExpiryCheckInterval)
		}
	}
}

// settingOrFlag decides which value a pipeline knob takes. Anything the
// operator set explicitly at the host, as a flag or an environment variable,
// stays untouched; otherwise the value from the settings table applies, and a
// missing or nonsensical setting falls back to what the flag already held.
func settingOrFlag(flagName, envName string, fromFlag, fromSettings int) int {
	if flagWasSet(flagName) || os.Getenv(envName) != "" {
		return fromFlag
	}
	if fromSettings > 0 {
		return fromSettings
	}
	return fromFlag
}

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func intEnvOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

func boolEnvOr(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES":
		return true
	case "0", "false", "FALSE", "False", "no", "NO":
		return false
	}
	return fallback
}

// runRetentionReconciler keeps the Timescale retention policies in step with
// the retention_days setting. It applies on change rather than on every tick,
// and re-checks the catalog periodically so drift introduced elsewhere (a new
// hypertable arriving with the migration default, a policy edited by hand) is
// healed without a restart.
func runRetentionReconciler(ctx context.Context, database *db.DB, ch *config.Holder) {
	const (
		pollInterval = 5 * time.Second
		fullInterval = 5 * time.Minute
	)

	applied := -1
	// warned remembers the last out-of-range value we complained about, so a
	// typo in the panel produces one line instead of one every five seconds.
	warned := -1
	var lastFull time.Time

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if cfg := ch.Get(); cfg != nil {
			desired := cfg.Global.RetentionDays
			switch {
			case desired < 0 || desired > db.MaxRetentionDays:
				// Refuse rather than clamp: silently enforcing a different
				// window than the one on screen is the bug we are fixing.
				if desired != warned {
					slog.Warn("retention_days out of range, leaving policies untouched",
						"days", desired, "max", db.MaxRetentionDays)
					warned = desired
				}
			case desired != applied || time.Since(lastFull) >= fullInterval:
				changed, err := database.ApplyRetention(ctx, desired)
				if err != nil {
					// Leave `applied` alone so the next tick retries.
					slog.Error("retention policy apply failed", "days", desired, "error", err)
					break
				}
				applied = desired
				lastFull = time.Now()
				if len(changed) > 0 {
					slog.Info("retention policy updated", "days", desired, "tables", changed)
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runCompressionReconciler keeps the Timescale compression policies in step
// with the settings, the same way retention is reconciled: the panel value is
// the truth and the job catalog is made to match it.
//
// The window matters beyond disk. A compressed chunk cannot use the trigram
// indexes, so the uncompressed window is also the window where searching paths
// and bodies stays indexed. That is why bodies carry their own value.
func runCompressionReconciler(ctx context.Context, database *db.DB, ch *config.Holder) {
	const (
		pollInterval = 5 * time.Second
		fullInterval = 5 * time.Minute
	)

	applied := map[string]int{}
	warned := ""
	var lastFull time.Time

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if cfg := ch.Get(); cfg != nil {
			want := desiredCompression(cfg.Global.CompressionDays, cfg.Global.CompressionBodiesDays)
			bad := outOfRangeCompression(want)
			switch {
			case bad != "":
				// Refuse rather than clamp, for the reason retention does:
				// enforcing a window other than the one on screen is the bug.
				if bad != warned {
					slog.Warn("compression setting out of range, leaving policies untouched",
						"detail", bad, "max", db.MaxCompressionDays)
					warned = bad
				}
			case !sameCompression(want, applied) || time.Since(lastFull) >= fullInterval:
				changed, err := database.ApplyCompression(ctx, want)
				if err != nil {
					slog.Error("compression policy apply failed", "error", err)
					break
				}
				applied = want
				warned = ""
				lastFull = time.Now()
				if len(changed) > 0 {
					slog.Info("compression policy updated",
						"days", cfg.Global.CompressionDays,
						"bodies_days", cfg.Global.CompressionBodiesDays,
						"tables", changed)
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// desiredCompression maps the two settings onto the tables they govern.
func desiredCompression(days, bodiesDays int) map[string]int {
	want := make(map[string]int, len(db.CompressionTables))
	for _, t := range db.CompressionTables {
		if t == db.BodiesTable {
			want[t] = bodiesDays
			continue
		}
		want[t] = days
	}
	return want
}

func outOfRangeCompression(want map[string]int) string {
	tables := make([]string, 0, len(want))
	for t := range want {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, t := range tables {
		if d := want[t]; d < 0 || d > db.MaxCompressionDays {
			return fmt.Sprintf("%s=%d", t, d)
		}
	}
	return ""
}

func sameCompression(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
