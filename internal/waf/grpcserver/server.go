package grpcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"muvon/internal/db"
	"muvon/internal/waf"
	pb "muvon/proto/wafpb"
)

// Server implements wafpb.WafServiceServer by delegating to the WAF engine.
type Server struct {
	pb.UnimplementedWafServiceServer
	engine   *waf.Engine
	database *db.DB
}

func New(engine *waf.Engine, database *db.DB) *Server {
	return &Server{engine: engine, database: database}
}

// --- Inspect ---

func (s *Server) Inspect(ctx context.Context, req *pb.InspectRequest) (*pb.InspectResponse, error) {
	headers := make(map[string][]string, len(req.Headers))
	for k, v := range req.Headers {
		headers[k] = []string{v}
	}

	result := s.engine.Inspect(ctx, waf.InspectRequest{
		RequestID:     req.RequestId,
		ClientIP:      req.ClientIp,
		Host:          req.Host,
		Method:        req.Method,
		Path:          req.Path,
		RawQuery:      req.RawQuery,
		Headers:       headers,
		Body:          req.Body,
		ContentType:   req.ContentType,
		RouteID:       int(req.RouteId),
		DetectionOnly: req.DetectionOnly,
	})

	resp := &pb.InspectResponse{
		Action:        string(result.Action),
		RequestScore:  int32(result.RequestScore),
		IpScore:       result.IPScore,
		BlockReason:   result.BlockReason,
		DetectionOnly: result.DetectionOnly,
		ProcessingUs:  result.ProcessingUs,
	}
	for _, m := range result.Matches {
		resp.Matches = append(resp.Matches, &pb.RuleMatch{
			RuleId:   int32(m.RuleID),
			Category: string(m.Category),
			Severity: int32(m.Severity),
			Location: string(m.Location),
			Field:    m.Field,
			Snippet:  m.Snippet,
		})
	}
	return resp, nil
}

// --- IP Management ---

func (s *Server) BanIP(ctx context.Context, req *pb.BanIPRequest) (*pb.BanIPResponse, error) {
	dur := time.Duration(req.DurationMinutes) * time.Minute
	s.engine.IPState.ManualBan(req.Ip, req.Reason, dur)
	return &pb.BanIPResponse{}, nil
}

func (s *Server) UnbanIP(ctx context.Context, req *pb.UnbanIPRequest) (*pb.UnbanIPResponse, error) {
	s.engine.IPState.ManualUnban(req.Ip)
	return &pb.UnbanIPResponse{}, nil
}

func (s *Server) WhitelistIP(ctx context.Context, req *pb.WhitelistIPRequest) (*pb.WhitelistIPResponse, error) {
	s.engine.IPState.SetWhitelisted(req.Ip)
	return &pb.WhitelistIPResponse{}, nil
}

func (s *Server) RemoveWhitelist(ctx context.Context, req *pb.RemoveWhitelistRequest) (*pb.RemoveWhitelistResponse, error) {
	s.engine.IPState.RemoveWhitelist(req.Ip)
	return &pb.RemoveWhitelistResponse{}, nil
}

func (s *Server) ListIPStates(ctx context.Context, _ *pb.ListIPStatesRequest) (*pb.ListIPStatesResponse, error) {
	states, err := s.database.ListWafIPStates(ctx)
	if err != nil {
		return nil, fmt.Errorf("list ip states: %w", err)
	}
	resp := &pb.ListIPStatesResponse{}
	for _, st := range states {
		resp.States = append(resp.States, &pb.IPStateEntry{
			Ip:              st.IP,
			Banned:          st.Status == "ban" || st.Status == "temp_ban",
			Whitelisted:     st.Status == "whitelisted",
			CumulativeScore: st.CumulativeScore,
			BanReason:       st.BanReason,
			LastSeen:        st.LastSeen.Format(time.RFC3339),
		})
	}
	return resp, nil
}

// --- Rule Management ---

func (s *Server) ListRules(ctx context.Context, req *pb.ListRulesRequest) (*pb.ListRulesResponse, error) {
	var rules []db.WafRule
	var err error
	if req.ActiveOnly {
		rules, err = s.database.ListActiveWafRules(ctx)
	} else {
		rules, err = s.database.ListWafRules(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	resp := &pb.ListRulesResponse{}
	for _, r := range rules {
		if req.Category != "" && r.Category != req.Category {
			continue
		}
		resp.Rules = append(resp.Rules, ruleToProto(r))
	}
	return resp, nil
}

func (s *Server) CreateRule(ctx context.Context, req *pb.CreateRuleRequest) (*pb.Rule, error) {
	r, err := s.database.CreateWafRule(ctx, req.Pattern, req.Category, req.IsRegex, int(req.Severity), req.Description)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	go s.engine.RuleCache.Refresh(context.Background())
	return ruleToProto(r), nil
}

func (s *Server) UpdateRule(ctx context.Context, req *pb.UpdateRuleRequest) (*pb.Rule, error) {
	r, err := s.database.UpdateWafRule(ctx, int(req.Id), req.Pattern, req.Category, req.IsRegex, int(req.Severity), req.Description, req.IsActive)
	if err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}
	go s.engine.RuleCache.Refresh(context.Background())
	return ruleToProto(r), nil
}

func (s *Server) DeleteRule(ctx context.Context, req *pb.DeleteRuleRequest) (*pb.DeleteRuleResponse, error) {
	if err := s.database.DeleteWafRule(ctx, int(req.Id)); err != nil {
		return nil, fmt.Errorf("delete rule: %w", err)
	}
	go s.engine.RuleCache.Refresh(context.Background())
	return &pb.DeleteRuleResponse{}, nil
}

func (s *Server) ImportRules(ctx context.Context, req *pb.ImportRulesRequest) (*pb.ImportRulesResponse, error) {
	var count int32
	for _, cr := range req.Rules {
		if _, err := s.database.CreateWafRule(ctx, cr.Pattern, cr.Category, cr.IsRegex, int(cr.Severity), cr.Description); err == nil {
			count++
		}
	}
	go s.engine.RuleCache.Refresh(context.Background())
	return &pb.ImportRulesResponse{Imported: count}, nil
}

// --- Exclusions ---

func (s *Server) ListExclusions(ctx context.Context, _ *pb.ListExclusionsRequest) (*pb.ListExclusionsResponse, error) {
	exclusions, err := s.database.ListWafExclusions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list exclusions: %w", err)
	}
	resp := &pb.ListExclusionsResponse{}
	for _, e := range exclusions {
		resp.Exclusions = append(resp.Exclusions, &pb.Exclusion{
			Id:        int32(e.ID),
			RuleId:    int32(e.RuleID),
			RouteId:   int32(e.RouteID),
			Location:  e.Location,
			Parameter: e.Parameter,
		})
	}
	return resp, nil
}

func (s *Server) CreateExclusion(ctx context.Context, req *pb.CreateExclusionRequest) (*pb.Exclusion, error) {
	e, err := s.database.CreateWafExclusion(ctx, int(req.RouteId), int(req.RuleId), req.Parameter, req.Location, "")
	if err != nil {
		return nil, fmt.Errorf("create exclusion: %w", err)
	}
	go s.engine.RuleCache.Refresh(context.Background())
	return &pb.Exclusion{
		Id:        int32(e.ID),
		RuleId:    int32(e.RuleID),
		RouteId:   int32(e.RouteID),
		Location:  e.Location,
		Parameter: e.Parameter,
	}, nil
}

func (s *Server) DeleteExclusion(ctx context.Context, req *pb.DeleteExclusionRequest) (*pb.DeleteExclusionResponse, error) {
	if err := s.database.DeleteWafExclusion(ctx, int(req.Id)); err != nil {
		return nil, fmt.Errorf("delete exclusion: %w", err)
	}
	go s.engine.RuleCache.Refresh(context.Background())
	return &pb.DeleteExclusionResponse{}, nil
}

// --- Events / Stats ---

func (s *Server) SearchEvents(ctx context.Context, req *pb.SearchEventsRequest) (*pb.SearchEventsResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 50
	}

	events, total, err := s.database.SearchWafEvents(ctx, req.ClientIp, req.Action, req.Host, limit, int(req.Offset))
	if err != nil {
		return nil, fmt.Errorf("search events: %w", err)
	}

	resp := &pb.SearchEventsResponse{Total: int32(total)}
	for _, ev := range events {
		resp.Events = append(resp.Events, &pb.WafEvent{
			Id:           ev.ID,
			RequestId:    ev.RequestID,
			ClientIp:     ev.ClientIP,
			Host:         ev.Host,
			Method:       ev.Method,
			Path:         ev.Path,
			RequestScore: int32(ev.RequestScore),
			IpScore:      ev.IPScore,
			Action:       ev.Action,
			MatchedRules: string(ev.MatchedRules),
			CreatedAt:    ev.Timestamp.Format(time.RFC3339),
		})
	}
	return resp, nil
}

func (s *Server) GetStats(ctx context.Context, req *pb.GetStatsRequest) (*pb.GetStatsResponse, error) {
	events, total, err := s.database.SearchWafEvents(ctx, "", "", "", 10000, 0)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}

	resp := &pb.GetStatsResponse{TotalEvents: int32(total)}
	catMap := make(map[string]int32)
	ipMap := make(map[string]int32)
	uniqueIPs := make(map[string]struct{})
	for _, ev := range events {
		if ev.Action == "block" || ev.Action == "temp_ban" || ev.Action == "ban" {
			resp.TotalBlocked++
		}
		uniqueIPs[ev.ClientIP] = struct{}{}
		ipMap[ev.ClientIP]++
		var matches []struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal(ev.MatchedRules, &matches)
		for _, m := range matches {
			catMap[m.Category]++
		}
	}
	resp.UniqueIps = int32(len(uniqueIPs))

	for cat, cnt := range catMap {
		resp.TopCategories = append(resp.TopCategories, &pb.CategoryCount{Category: cat, Count: cnt})
	}
	for ip, cnt := range ipMap {
		resp.TopIps = append(resp.TopIps, &pb.IPCount{Ip: ip, Count: cnt})
	}
	return resp, nil
}

// --- Helpers ---

func ruleToProto(r db.WafRule) *pb.Rule {
	return &pb.Rule{
		Id:          int32(r.ID),
		Pattern:     r.Pattern,
		IsRegex:     r.IsRegex,
		Category:    r.Category,
		Severity:    int32(r.Severity),
		Description: r.Description,
		IsActive:    r.IsActive,
		CreatedAt:   r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   r.UpdatedAt.Format(time.RFC3339),
	}
}
