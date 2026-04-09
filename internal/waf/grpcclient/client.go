package grpcclient

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"muvon/internal/waf"
	pb "muvon/proto/wafpb"
)

const maxWafBodyBytes = 65536 // 64KB — max body payload sent to muWAF over gRPC

// RemoteInspector calls muWAF via gRPC over Unix socket.
// Implements both WAF inspection and admin operations for the gateway.
type RemoteInspector struct {
	conn   *grpc.ClientConn
	client pb.WafServiceClient
}

// Dial connects to muWAF's Unix socket.
func Dial(socketPath string) (*RemoteInspector, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &RemoteInspector{
		conn:   conn,
		client: pb.NewWafServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection.
func (r *RemoteInspector) Close() error {
	return r.conn.Close()
}

// Inspect sends the request to muWAF for inspection.
func (r *RemoteInspector) Inspect(ctx context.Context, req waf.InspectRequest) waf.InspectResult {
	// Flatten headers: http.Header → map[string]string
	flatHeaders := make(map[string]string, len(req.Headers))
	for k, vals := range req.Headers {
		flatHeaders[k] = strings.Join(vals, ", ")
	}

	body := req.Body
	if len(body) > maxWafBodyBytes {
		body = body[:maxWafBodyBytes]
	}

	pbReq := &pb.InspectRequest{
		RequestId:     req.RequestID,
		ClientIp:      req.ClientIP,
		Host:          req.Host,
		Method:        req.Method,
		Path:          req.Path,
		RawQuery:      req.RawQuery,
		Headers:       flatHeaders,
		Body:          body,
		ContentType:   req.ContentType,
		RouteId:       int32(req.RouteID),
		DetectionOnly: req.DetectionOnly,
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := r.client.Inspect(ctx, pbReq)
	if err != nil {
		slog.Warn("muWAF inspect failed, allowing request", "error", err)
		return waf.InspectResult{Action: waf.ActionAllow}
	}

	result := waf.InspectResult{
		Action:        waf.Action(resp.Action),
		RequestScore:  int(resp.RequestScore),
		IPScore:       resp.IpScore,
		BlockReason:   resp.BlockReason,
		DetectionOnly: resp.DetectionOnly,
		ProcessingUs:  resp.ProcessingUs,
	}
	for _, m := range resp.Matches {
		result.Matches = append(result.Matches, waf.RuleMatch{
			RuleID:   int(m.RuleId),
			Category: waf.Category(m.Category),
			Severity: int(m.Severity),
			Location: waf.Location(m.Location),
			Field:    m.Field,
			Snippet:  m.Snippet,
		})
	}
	return result
}

// Healthy checks if the gRPC connection to muWAF is alive.
func (r *RemoteInspector) Healthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err := r.client.Inspect(ctx, &pb.InspectRequest{})
	return err == nil
}

// ==================== Admin RPC Methods ====================

// ListRules returns all WAF rules from muWAF.
func (r *RemoteInspector) ListRules(ctx context.Context) ([]*pb.Rule, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := r.client.ListRules(ctx, &pb.ListRulesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Rules, nil
}

// GetRule returns a single WAF rule by ID (client-side filter).
func (r *RemoteInspector) GetRule(ctx context.Context, id int) (*pb.Rule, error) {
	rules, err := r.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if int(rule.Id) == id {
			return rule, nil
		}
	}
	return nil, fmt.Errorf("rule %d not found", id)
}

// CreateRule creates a new WAF rule on muWAF.
func (r *RemoteInspector) CreateRule(ctx context.Context, pattern, category string, isRegex bool, severity int, description string) (*pb.Rule, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.CreateRule(ctx, &pb.CreateRuleRequest{
		Pattern:     pattern,
		IsRegex:     isRegex,
		Category:    category,
		Severity:    int32(severity),
		Description: description,
	})
}

// UpdateRule updates a WAF rule on muWAF.
func (r *RemoteInspector) UpdateRule(ctx context.Context, id int, pattern, category string, isRegex bool, severity int, description string, isActive bool) (*pb.Rule, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.UpdateRule(ctx, &pb.UpdateRuleRequest{
		Id:          int32(id),
		Pattern:     pattern,
		IsRegex:     isRegex,
		Category:    category,
		Severity:    int32(severity),
		Description: description,
		IsActive:    isActive,
	})
}

// DeleteRule deletes a WAF rule on muWAF.
func (r *RemoteInspector) DeleteRule(ctx context.Context, id int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.client.DeleteRule(ctx, &pb.DeleteRuleRequest{Id: int32(id)})
	return err
}

// ImportRules bulk-imports rules into muWAF. Returns imported count.
func (r *RemoteInspector) ImportRules(ctx context.Context, rules []*pb.CreateRuleRequest) (int32, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := r.client.ImportRules(ctx, &pb.ImportRulesRequest{Rules: rules})
	if err != nil {
		return 0, err
	}
	return resp.Imported, nil
}

// BanIP bans an IP via muWAF.
func (r *RemoteInspector) BanIP(ctx context.Context, ip, reason string, durationMinutes int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.client.BanIP(ctx, &pb.BanIPRequest{
		Ip:              ip,
		Reason:          reason,
		DurationMinutes: int32(durationMinutes),
	})
	return err
}

// UnbanIP unbans an IP via muWAF.
func (r *RemoteInspector) UnbanIP(ctx context.Context, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.client.UnbanIP(ctx, &pb.UnbanIPRequest{Ip: ip})
	return err
}

// WhitelistIP whitelists an IP via muWAF.
func (r *RemoteInspector) WhitelistIP(ctx context.Context, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.client.WhitelistIP(ctx, &pb.WhitelistIPRequest{Ip: ip})
	return err
}

// RemoveWhitelist removes an IP from muWAF whitelist.
func (r *RemoteInspector) RemoveWhitelist(ctx context.Context, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.client.RemoveWhitelist(ctx, &pb.RemoveWhitelistRequest{Ip: ip})
	return err
}

// ListIPStates returns all IP states from muWAF.
func (r *RemoteInspector) ListIPStates(ctx context.Context) ([]*pb.IPStateEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := r.client.ListIPStates(ctx, &pb.ListIPStatesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.States, nil
}

// ListExclusions returns all WAF exclusions from muWAF.
func (r *RemoteInspector) ListExclusions(ctx context.Context) ([]*pb.Exclusion, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := r.client.ListExclusions(ctx, &pb.ListExclusionsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Exclusions, nil
}

// CreateExclusion creates a WAF rule exclusion on muWAF.
func (r *RemoteInspector) CreateExclusion(ctx context.Context, ruleID, routeID int, location, parameter string) (*pb.Exclusion, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.CreateExclusion(ctx, &pb.CreateExclusionRequest{
		RuleId:    int32(ruleID),
		RouteId:   int32(routeID),
		Location:  location,
		Parameter: parameter,
	})
}

// DeleteExclusion deletes a WAF exclusion on muWAF.
func (r *RemoteInspector) DeleteExclusion(ctx context.Context, id int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.client.DeleteExclusion(ctx, &pb.DeleteExclusionRequest{Id: int32(id)})
	return err
}

// SearchEvents searches WAF events on muWAF.
func (r *RemoteInspector) SearchEvents(ctx context.Context, clientIP, action, host string, limit, offset int) (*pb.SearchEventsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.SearchEvents(ctx, &pb.SearchEventsRequest{
		ClientIp: clientIP,
		Action:   action,
		Host:     host,
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
}

// GetStats returns WAF statistics from muWAF.
func (r *RemoteInspector) GetStats(ctx context.Context) (*pb.GetStatsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.GetStats(ctx, &pb.GetStatsRequest{})
}
