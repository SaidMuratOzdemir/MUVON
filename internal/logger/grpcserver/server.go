package grpcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"muvon/internal/config"
	"muvon/internal/db"
	"muvon/internal/logger"
	pb "muvon/proto/logpb"
)

// ConfigFunc returns the current config snapshot so query handlers can
// resolve host-scoped JWT claim priority without baking it in here.
type ConfigFunc func() *config.Config

// EnrichmentStatusFunc returns a snapshot of GeoIP/JWT enrichment health for
// the admin panel. Optional — a nil func means GetEnrichmentStatus reports
// "disabled" for both signals, which is the correct behaviour when the host
// process has not wired up enrichment at all (e.g. minimal builds).
type EnrichmentStatusFunc func() *pb.EnrichmentStatusResponse

// Server implements logpb.LogServiceServer by writing to the log pipeline.
type Server struct {
	pb.UnimplementedLogServiceServer
	pipeline       *logger.Pipeline
	database       *db.DB
	configFn       ConfigFunc
	enrichStatusFn EnrichmentStatusFunc
}

// New wires the gRPC server. configFn may be nil — when absent, user-display
// enrichment on reads falls back to an empty priority list (no Top Users,
// no pivot column), which is the correct behaviour for callers that have
// not provisioned any JWT config.
func New(pipeline *logger.Pipeline, database *db.DB, configFn ConfigFunc) *Server {
	return &Server{pipeline: pipeline, database: database, configFn: configFn}
}

// SetEnrichmentStatusFn registers the callback used to answer
// GetEnrichmentStatus. Setter pattern keeps the New() signature stable while
// the optional dependency is passed in from the binary that owns the
// enrichment lifecycle (cmd/dialog-siem).
func (s *Server) SetEnrichmentStatusFn(fn EnrichmentStatusFunc) {
	s.enrichStatusFn = fn
}

// --- Log Ingest ---

func (s *Server) SendEntry(_ context.Context, req *pb.LogEntry) (*pb.Ack, error) {
	s.pipeline.Send(protoToEntry(req))
	return &pb.Ack{}, nil
}

func (s *Server) SendBatch(_ context.Context, req *pb.LogBatch) (*pb.Ack, error) {
	for _, e := range req.Entries {
		s.pipeline.Send(protoToEntry(e))
	}
	return &pb.Ack{}, nil
}

// --- Search ---

func (s *Server) SearchLogs(ctx context.Context, req *pb.SearchLogsRequest) (*pb.SearchLogsResponse, error) {
	params := db.LogSearchParams{
		Host:     req.Host,
		Path:     req.Path,
		Method:   req.Method,
		ClientIP: req.ClientIp,
		Limit:    int(req.Limit),
		Offset:   int(req.Offset),
	}
	if req.StatusMin > 0 {
		params.StatusMin = int(req.StatusMin)
	}
	if req.StatusMax > 0 {
		params.StatusMax = int(req.StatusMax)
	}
	if req.From != "" {
		params.From, _ = time.Parse(time.RFC3339, req.From)
	}
	if req.To != "" {
		params.To, _ = time.Parse(time.RFC3339, req.To)
	}
	if req.Search != "" {
		params.Query = req.Search
	}
	if req.Starred {
		starred := true
		params.Starred = &starred
	}
	if req.RespTimeMin > 0 {
		params.ResponseTimeMin = int(req.RespTimeMin)
	}
	if req.RespTimeMax > 0 {
		params.ResponseTimeMax = int(req.RespTimeMax)
	}
	if req.User != "" {
		params.UserQuery = req.User
	}

	logs, total, err := s.database.SearchLogs(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("search logs: %w", err)
	}

	resp := &pb.SearchLogsResponse{Total: int32(total)}
	for _, l := range logs {
		summary := &pb.LogSummary{
			RequestId:      l.ID,
			Timestamp:      l.Timestamp.Format(time.RFC3339Nano),
			Host:           l.Host,
			ClientIp:       l.ClientIP,
			Method:         l.Method,
			Path:           l.Path,
			ResponseStatus: int32(l.ResponseStatus),
			WafBlocked:     l.WafBlocked,
			Starred:        l.IsStarred,
		}
		if l.ResponseTimeMs != nil {
			summary.ResponseTimeMs = int32(*l.ResponseTimeMs)
		}
		if l.UserAgent != nil {
			summary.UserAgent = *l.UserAgent
		}
		if l.Country != nil {
			summary.Country = *l.Country
		}
		if l.City != nil {
			summary.City = *l.City
		}
		priority := s.displayClaimsForHost(l.Host)
		if display, query := extractUserDisplay(l.UserIdentity, priority); display != "" {
			summary.UserDisplay = display
			summary.UserQuery = query
		}
		resp.Logs = append(resp.Logs, summary)
	}
	return resp, nil
}

// displayClaimsForHost returns the ordered list of JWT claim keys to treat
// as "user display" candidates.
//
//   - host == "" means "across all hosts" (e.g. the dashboard with no host
//     filter). We return the deduplicated union of every host's claim list,
//     preserving each host's priority order, with the global list appended
//     last. This is what makes Top Users panel work in a multi-tenant front
//     where each tenant signs tokens with its own claim vocabulary
//     (user_id for cevik, sub for vize360, ...). The previous fallback to
//     the global list silently dropped every cevik claim.
//   - host != "" returns that host's override when present, otherwise the
//     global list.
//
// Returning nil means "no JWT config at all" — callers then skip user
// enrichment for reads.
func (s *Server) displayClaimsForHost(host string) []string {
	if s.configFn == nil {
		return nil
	}
	cfg := s.configFn()
	if cfg == nil {
		return nil
	}
	if host != "" {
		if hc, ok := cfg.Hosts[host]; ok && len(hc.JWTClaims) > 0 {
			return hc.JWTClaims
		}
		return cfg.Global.JWTClaims
	}

	// host == "" — union across hosts. Stable ordering for COALESCE: host
	// claims first (so a tenant-specific claim like user_id wins for that
	// tenant's rows), global claims last as the catch-all.
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)
	add := func(keys []string) {
		for _, k := range keys {
			if k == "" {
				continue
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	for _, hc := range cfg.Hosts {
		if hc != nil && hc.JWTIdentityEnabled {
			add(hc.JWTClaims)
		}
	}
	add(cfg.Global.JWTClaims)
	return out
}

// extractUserDisplay picks the first non-empty claim from priorityKeys.
// The caller supplies the priority so every tenant app's own JWT schema
// drives which claim identifies a user — no claim vocabulary lives in
// this package.
func extractUserDisplay(raw json.RawMessage, priorityKeys []string) (display, query string) {
	if len(raw) == 0 || len(priorityKeys) == 0 {
		return "", ""
	}
	var wrapper struct {
		Claims map[string]string `json:"claims"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return "", ""
	}
	for _, key := range priorityKeys {
		if v := wrapper.Claims[key]; v != "" {
			return v, v
		}
	}
	return "", ""
}

func (s *Server) GetLog(ctx context.Context, req *pb.GetLogRequest) (*pb.LogDetail, error) {
	entry, body, err := s.database.GetLogDetail(ctx, req.RequestId)
	if err != nil {
		return nil, fmt.Errorf("get log detail: %w", err)
	}

	detail := &pb.LogDetail{
		Entry:   dbEntryToProto(entry, body),
		Starred: entry.IsStarred,
	}
	if entry.Note != nil {
		detail.Note = *entry.Note
	}
	return detail, nil
}

func (s *Server) GetLogStats(ctx context.Context, req *pb.GetLogStatsRequest) (*pb.LogStatsResponse, error) {
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()
	if req.From != "" {
		from, _ = time.Parse(time.RFC3339, req.From)
	}
	if req.To != "" {
		to, _ = time.Parse(time.RFC3339, req.To)
	}

	stats, err := s.database.GetLogStats(ctx, from, to, s.displayClaimsForHost(req.Host))
	if err != nil {
		return nil, fmt.Errorf("get log stats: %w", err)
	}

	resp := &pb.LogStatsResponse{
		TotalRequests:      stats.TotalRequests,
		AvgResponseMs:      stats.AvgResponseMs,
		RequestsPerMin:     stats.RequestsPerMin,
		StatusDistribution: make(map[string]int64),
	}
	for k, v := range stats.StatusCounts {
		resp.StatusDistribution[k] = v
		if len(k) > 0 && (k[0] == '4' || k[0] == '5') {
			resp.TotalErrors += v
		}
	}
	// Top-N panels ride as opaque JSON so adding new breakdowns later
	// (e.g. top_user_agents) does not require another rpc schema bump.
	if b, err := json.Marshal(stats.TopCountries); err == nil && len(stats.TopCountries) > 0 {
		resp.TopCountriesJson = string(b)
	}
	if b, err := json.Marshal(stats.TopHosts); err == nil && len(stats.TopHosts) > 0 {
		resp.TopHostsJson = string(b)
	}
	if b, err := json.Marshal(stats.TopPaths); err == nil && len(stats.TopPaths) > 0 {
		resp.TopPathsJson = string(b)
	}
	if b, err := json.Marshal(stats.TopUsers); err == nil && len(stats.TopUsers) > 0 {
		resp.TopUsersJson = string(b)
	}
	return resp, nil
}

// --- Reveal raw JWT ---

// GetLogRawJWT returns the raw bearer token captured for a log row. Audit
// logging happens on the MUVON admin side, where the requesting user is
// known; this RPC is unauthenticated for callers inside the trust zone
// (Unix socket) and authenticated by api key on the agent TCP listener.
func (s *Server) GetLogRawJWT(ctx context.Context, req *pb.GetLogRawJWTRequest) (*pb.GetLogRawJWTResponse, error) {
	if req.RequestId == "" {
		return nil, fmt.Errorf("request_id is required")
	}
	token, host, err := s.database.GetLogRawJWT(ctx, req.RequestId)
	if err != nil {
		return nil, fmt.Errorf("get log raw jwt: %w", err)
	}
	return &pb.GetLogRawJWTResponse{Token: token, Host: host}, nil
}

// --- Enrichment health ---

// GetEnrichmentStatus reports whether GeoIP / JWT identity enrichment are
// actually loaded. The admin panel uses this to surface "GeoIP enabled but
// failing to load" as a visible warning instead of empty country columns.
func (s *Server) GetEnrichmentStatus(_ context.Context, _ *pb.EnrichmentStatusRequest) (*pb.EnrichmentStatusResponse, error) {
	if s.enrichStatusFn == nil {
		return &pb.EnrichmentStatusResponse{
			GeoipState:        "disabled",
			JwtIdentityState:  "disabled",
		}, nil
	}
	if resp := s.enrichStatusFn(); resp != nil {
		return resp, nil
	}
	return &pb.EnrichmentStatusResponse{
		GeoipState:        "disabled",
		JwtIdentityState:  "disabled",
	}, nil
}

// --- Stream ---

func (s *Server) StreamLogs(req *pb.StreamLogsRequest, stream pb.LogService_StreamLogsServer) error {
	ch := s.pipeline.Subscribe()
	defer s.pipeline.Unsubscribe(ch)

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return nil
			}
			if req.Host != "" && entry.Host != req.Host {
				continue
			}
			if err := stream.Send(entryToProto(entry)); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// --- Notes / Stars ---

func (s *Server) UpsertNote(ctx context.Context, req *pb.UpsertNoteRequest) (*pb.Ack, error) {
	if err := s.database.UpsertLogNote(ctx, req.RequestId, req.Note, "api"); err != nil {
		return nil, fmt.Errorf("upsert note: %w", err)
	}
	return &pb.Ack{}, nil
}

func (s *Server) ToggleStar(ctx context.Context, req *pb.ToggleStarRequest) (*pb.Ack, error) {
	if _, err := s.database.ToggleLogStar(ctx, req.RequestId); err != nil {
		return nil, fmt.Errorf("toggle star: %w", err)
	}
	return &pb.Ack{}, nil
}

// --- Converters ---

func protoToEntry(p *pb.LogEntry) logger.Entry {
	ts, _ := time.Parse(time.RFC3339Nano, p.Timestamp)
	e := logger.Entry{
		RequestID:           p.RequestId,
		Timestamp:           ts,
		Host:                p.Host,
		ClientIP:            p.ClientIp,
		Method:              p.Method,
		Path:                p.Path,
		QueryString:         p.QueryString,
		ResponseStatus:      int(p.ResponseStatus),
		ResponseTimeMs:      int(p.ResponseTimeMs),
		RequestSize:         int(p.RequestSize),
		ResponseSize:        int(p.ResponseSize),
		UserAgent:           p.UserAgent,
		Error:               p.Error,
		RequestBody:         p.RequestBody,
		ResponseBody:        p.ResponseBody,
		IsRequestTruncated:  p.IsRequestTruncated,
		IsResponseTruncated: p.IsResponseTruncated,
		WafBlocked:          p.WafBlocked,
		WafBlockReason:      p.WafBlockReason,
		WafScore:            int(p.WafScore),
		WafAction:           p.WafAction,
		Country:             p.Country,
		City:                p.City,
	}
	if len(p.RequestHeaders) > 0 {
		e.RequestHeaders = p.RequestHeaders
	}
	if len(p.ResponseHeaders) > 0 {
		e.ResponseHeaders = p.ResponseHeaders
	}
	if p.UserIdentity != nil {
		e.UserIdentity = &logger.UserIdentity{
			Claims:   p.UserIdentity.Claims,
			Verified: p.UserIdentity.Verified,
			Source:   p.UserIdentity.Source,
		}
	}
	return e
}

func entryToProto(e logger.Entry) *pb.LogEntry {
	p := &pb.LogEntry{
		RequestId:           e.RequestID,
		Timestamp:           e.Timestamp.Format(time.RFC3339Nano),
		Host:                e.Host,
		ClientIp:            e.ClientIP,
		Method:              e.Method,
		Path:                e.Path,
		QueryString:         e.QueryString,
		ResponseStatus:      int32(e.ResponseStatus),
		ResponseTimeMs:      int32(e.ResponseTimeMs),
		RequestSize:         int32(e.RequestSize),
		ResponseSize:        int32(e.ResponseSize),
		UserAgent:           e.UserAgent,
		Error:               e.Error,
		RequestBody:         e.RequestBody,
		ResponseBody:        e.ResponseBody,
		IsRequestTruncated:  e.IsRequestTruncated,
		IsResponseTruncated: e.IsResponseTruncated,
		WafBlocked:          e.WafBlocked,
		WafBlockReason:      e.WafBlockReason,
		WafScore:            int32(e.WafScore),
		WafAction:           e.WafAction,
		RequestHeaders:      e.RequestHeaders,
		ResponseHeaders:     e.ResponseHeaders,
		Country:             e.Country,
		City:                e.City,
	}
	if e.UserIdentity != nil {
		p.UserIdentity = &pb.UserIdentity{
			Claims:   e.UserIdentity.Claims,
			Verified: e.UserIdentity.Verified,
			Source:   e.UserIdentity.Source,
		}
	}
	return p
}

func dbEntryToProto(l db.LogEntry, body db.LogBody) *pb.LogEntry {
	p := &pb.LogEntry{
		RequestId:       l.ID,
		Timestamp:       l.Timestamp.Format(time.RFC3339Nano),
		Host:            l.Host,
		ClientIp:        l.ClientIP,
		Method:          l.Method,
		Path:            l.Path,
		RequestHeaders:  rawJSONToStringMap(l.RequestHeaders),
		ResponseStatus:  int32(l.ResponseStatus),
		ResponseHeaders: rawJSONToStringMap(l.ResponseHeaders),
		WafBlocked:      l.WafBlocked,
	}
	if l.QueryString != nil {
		p.QueryString = *l.QueryString
	}
	if l.ResponseTimeMs != nil {
		p.ResponseTimeMs = int32(*l.ResponseTimeMs)
	}
	if l.RequestSize != nil {
		p.RequestSize = int32(*l.RequestSize)
	}
	if l.ResponseSize != nil {
		p.ResponseSize = int32(*l.ResponseSize)
	}
	if l.UserAgent != nil {
		p.UserAgent = *l.UserAgent
	}
	if l.Error != nil {
		p.Error = *l.Error
	}
	if l.WafBlockReason != nil {
		p.WafBlockReason = *l.WafBlockReason
	}
	if l.Country != nil {
		p.Country = *l.Country
	}
	if l.City != nil {
		p.City = *l.City
	}
	if body.RequestBody != nil {
		p.RequestBody = []byte(*body.RequestBody)
	}
	if body.ResponseBody != nil {
		p.ResponseBody = []byte(*body.ResponseBody)
	}
	p.IsRequestTruncated = body.IsRequestTruncated
	p.IsResponseTruncated = body.IsResponseTruncated

	// Decode the JSONB user_identity payload into the proto shape so the
	// admin panel's log detail view actually receives claims/verified/source.
	// Without this the column is read from DB but dropped on the floor; the
	// UI then shows its "identity enrichment is disabled" hint even though
	// the SIEM enriched the row correctly.
	if len(l.UserIdentity) > 0 {
		var ui struct {
			Claims   map[string]string `json:"claims,omitempty"`
			Verified bool              `json:"verified"`
			Source   string            `json:"source"`
		}
		if err := json.Unmarshal(l.UserIdentity, &ui); err == nil && (len(ui.Claims) > 0 || ui.Source != "") {
			p.UserIdentity = &pb.UserIdentity{
				Claims:   ui.Claims,
				Verified: ui.Verified,
				Source:   ui.Source,
			}
		}
	}
	return p
}

func rawJSONToStringMap(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
