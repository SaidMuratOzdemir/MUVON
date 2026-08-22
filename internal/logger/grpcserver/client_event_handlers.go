package grpcserver

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"muvon/internal/db"
	"muvon/internal/logger"
	pb "muvon/proto/logpb"
)

// SetClientEventPipeline registers the client-event (RUM) pipeline. Called
// from cmd/dialog-siem after NewClientEventPipeline returns. Leaving it nil
// disables ingest — SendClientEventBatch then returns Unimplemented, which
// keeps minimal builds clean.
func (s *Server) SetClientEventPipeline(p *logger.ClientEventPipeline) {
	s.clientEventPipeline = p
}

// SendClientEventBatch flattens an edge-enriched batch into per-row events and
// fans them through the pipeline. Best-effort: the edge already replied 204 to
// the browser, so a write hiccup must not surface as an error the edge would
// have to handle — we ack and let the pipeline's drop counters record loss.
func (s *Server) SendClientEventBatch(ctx context.Context, req *pb.ClientEventBatch) (*pb.Ack, error) {
	if s.clientEventPipeline == nil {
		return nil, status.Error(codes.Unimplemented, "client event ingest disabled")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "batch is required")
	}
	if len(req.Events) == 0 {
		return &pb.Ack{}, nil
	}

	receivedAt := parseRFC3339(req.ReceivedAt)
	events := make([]logger.ClientEvent, 0, len(req.Events))
	for _, ev := range req.Events {
		events = append(events, logger.ClientEvent{
			App:        req.App,
			Release:    req.Release,
			SDK:        req.Sdk,
			SessionID:  req.SessionId,
			ViewID:     req.ViewId,
			Route:      req.Route,
			URLPath:    req.UrlPath,
			Host:       req.Host,
			HostID:     req.HostId,
			ClientIP:   req.ClientIp,
			UserAgent:  req.UserAgent,
			Country:    req.Country,
			City:       req.City,
			ReceivedAt: receivedAt,
			EventName:  ev.EventName,
			ClientTS:   parseRFC3339(ev.ClientTs),
			TraceID:    ev.TraceId,
			SpanID:     ev.SpanId,
			Attrs:      ev.Attrs,
		})
	}
	s.clientEventPipeline.SendBatch(events)
	return &pb.Ack{}, nil
}

// SearchClientEvents proxies the DB search for the admin UI. Available
// whenever the SIEM has a DB (independent of the ingest pipeline being on),
// so client_events can still be browsed after ingest is disabled.
func (s *Server) SearchClientEvents(ctx context.Context, req *pb.SearchClientEventsRequest) (*pb.SearchClientEventsResponse, error) {
	from, _ := time.Parse(time.RFC3339, req.From)
	to, _ := time.Parse(time.RFC3339, req.To)
	rows, err := s.database.SearchClientEvents(ctx, db.ClientEventSearchParams{
		TraceID:   req.TraceId,
		SessionID: req.SessionId,
		App:       req.App,
		HostID:    req.HostId,
		EventName: req.EventName,
		From:      from,
		To:        to,
		Limit:     int(req.Limit),
		Before:    req.Before,
	})
	if err != nil {
		return nil, fmt.Errorf("search client_events: %w", err)
	}
	resp := &pb.SearchClientEventsResponse{Rows: make([]*pb.ClientEventRow, 0, len(rows))}
	for _, r := range rows {
		resp.Rows = append(resp.Rows, clientEventRowToProto(r))
	}
	if len(rows) > 0 {
		resp.NextBeforeCursor = rows[len(rows)-1].ID
	}
	return resp, nil
}

func clientEventRowToProto(r db.ClientEventRow) *pb.ClientEventRow {
	pr := &pb.ClientEventRow{
		Id:        r.ID,
		Time:      r.Time.UTC().Format(time.RFC3339Nano),
		App:       r.App,
		HostId:    r.HostID,
		SessionId: r.SessionID,
		EventName: r.EventName,
		ClientIp:  r.ClientIP,
	}
	if r.ClientTS != nil {
		pr.ClientTs = r.ClientTS.UTC().Format(time.RFC3339Nano)
	}
	if r.Release != nil {
		pr.Release = *r.Release
	}
	if r.Host != nil {
		pr.Host = *r.Host
	}
	if r.ViewID != nil {
		pr.ViewId = *r.ViewID
	}
	if r.Route != nil {
		pr.Route = *r.Route
	}
	if r.URLPath != nil {
		pr.UrlPath = *r.URLPath
	}
	if r.TraceID != nil {
		pr.TraceId = *r.TraceID
	}
	if r.SpanID != nil {
		pr.SpanId = *r.SpanID
	}
	if r.Country != nil {
		pr.Country = *r.Country
	}
	if r.City != nil {
		pr.City = *r.City
	}
	if r.UserAgent != nil {
		pr.UserAgent = *r.UserAgent
	}
	if len(r.Attrs) > 0 {
		pr.AttrsJson = string(r.Attrs)
	}
	return pr
}
