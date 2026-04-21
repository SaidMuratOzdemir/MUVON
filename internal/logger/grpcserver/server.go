package grpcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"muvon/internal/db"
	"muvon/internal/logger"
	pb "muvon/proto/logpb"
)

// Server implements logpb.LogServiceServer by writing to the log pipeline.
type Server struct {
	pb.UnimplementedLogServiceServer
	pipeline *logger.Pipeline
	database *db.DB
}

func New(pipeline *logger.Pipeline, database *db.DB) *Server {
	return &Server{pipeline: pipeline, database: database}
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
		if display, query := extractUserDisplay(l.UserIdentity); display != "" {
			summary.UserDisplay = display
			summary.UserQuery = query
		}
		resp.Logs = append(resp.Logs, summary)
	}
	return resp, nil
}

// extractUserDisplay picks the human-friendly claim (email > name > sub)
// from a JSONB user_identity payload. Returns both the display label and
// the verbatim value so the admin UI can link "alice@foo.com" back to the
// same user across its other rows.
func extractUserDisplay(raw json.RawMessage) (display, query string) {
	if len(raw) == 0 {
		return "", ""
	}
	var wrapper struct {
		Claims map[string]string `json:"claims"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return "", ""
	}
	for _, key := range []string{"email", "name", "sub"} {
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

	stats, err := s.database.GetLogStats(ctx, from, to)
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
