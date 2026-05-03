package grpcserver

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"muvon/internal/db"
	"muvon/internal/logger"
	pb "muvon/proto/logpb"
)

// SetContainerPipeline registers the container log pipeline. Called from
// cmd/dialog-siem after NewContainerPipeline returns. Leaving it nil
// disables container ingest — SendContainerLogBatch then returns
// Unimplemented, which keeps minimal builds clean.
func (s *Server) SetContainerPipeline(p *logger.ContainerPipeline) {
	s.containerPipeline = p
}

// SendContainerLogBatch persists a batch of container log lines plus an
// upsert into the dimension table so the SIEM can reconstruct the
// container's history later. Both directions are best-effort: an error
// here must not block the producer (deployer / agent) from making
// progress, so we log and ack — the producer's retry/spool logic catches
// real failures via timeouts.
func (s *Server) SendContainerLogBatch(ctx context.Context, req *pb.ContainerLogBatch) (*pb.Ack, error) {
	if s.containerPipeline == nil {
		return nil, status.Error(codes.Unimplemented, "container ingest disabled")
	}
	if req == nil || req.Meta == nil {
		return nil, status.Error(codes.InvalidArgument, "batch.meta is required")
	}
	meta := req.Meta
	if meta.ContainerId == "" {
		return nil, status.Error(codes.InvalidArgument, "container_id is required")
	}

	// Upsert dimension row (cheap, even when nothing changes — the
	// labels/last_log_at fields keep the row fresh). Failure here is
	// logged but does not fail the batch — the row may have been
	// upserted on a previous batch and the line writes are still useful.
	startedAt := parseRFC3339(meta.StartedAt)
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	var finishedAt *time.Time
	if t := parseRFC3339(meta.FinishedAt); !t.IsZero() {
		finishedAt = &t
	}
	var exitCode *int
	if meta.ExitCode != 0 || finishedAt != nil {
		v := int(meta.ExitCode)
		exitCode = &v
	}

	// last_log_at = max timestamp in the batch — keeps the dimension
	// row fresh enough for shipper resume after restart.
	var lastTS *time.Time
	for _, e := range req.Entries {
		ts := parseRFC3339(e.Timestamp)
		if ts.IsZero() {
			continue
		}
		if lastTS == nil || ts.After(*lastTS) {
			t := ts
			lastTS = &t
		}
	}

	if err := s.database.UpsertContainer(ctx, db.UpsertContainerInput{
		ContainerID:   meta.ContainerId,
		ContainerName: meta.ContainerName,
		Image:         meta.Image,
		ImageDigest:   meta.ImageDigest,
		Project:       meta.Project,
		Component:     meta.Component,
		ReleaseID:     meta.ReleaseId,
		DeploymentID:  meta.DeploymentId,
		HostID:        meta.HostId,
		Labels:        meta.Labels,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
		ExitCode:      exitCode,
		LastLogAt:     lastTS,
	}); err != nil {
		// Log + carry on — flushing line rows is more valuable than
		// blocking the batch on a dimension hiccup.
		s.logf("upsert container failed: %v", err)
	}

	if len(req.Entries) == 0 {
		return &pb.Ack{}, nil
	}

	entries := make([]logger.ContainerEntry, 0, len(req.Entries))
	for _, e := range req.Entries {
		ts := parseRFC3339(e.Timestamp)
		entry := logger.ContainerEntry{
			HostID:        meta.HostId,
			ContainerID:   meta.ContainerId,
			ContainerName: meta.ContainerName,
			Image:         meta.Image,
			Project:       meta.Project,
			Component:     meta.Component,
			ReleaseID:     meta.ReleaseId,
			DeploymentID:  meta.DeploymentId,
			Timestamp:     ts,
			Stream:        e.Stream,
			Line:          e.Line,
			Truncated:     e.Truncated,
			Seq:           e.Seq,
			Attrs:         e.Attrs,
		}
		entries = append(entries, entry)
	}
	s.containerPipeline.SendBatch(entries, 0)
	return &pb.Ack{}, nil
}

// SearchContainerLogs proxies the DB search. UUIDv7 cursors give the UI
// next/prev paging without a separate sort key.
func (s *Server) SearchContainerLogs(ctx context.Context, req *pb.SearchContainerLogsRequest) (*pb.SearchContainerLogsResponse, error) {
	from, _ := time.Parse(time.RFC3339, req.From)
	to, _ := time.Parse(time.RFC3339, req.To)
	rows, err := s.database.SearchContainerLogs(ctx, db.ContainerSearchParams{
		ContainerID:   req.ContainerId,
		ContainerName: req.ContainerName,
		Project:       req.Project,
		Component:     req.Component,
		ReleaseID:     req.ReleaseId,
		DeploymentID:  req.DeploymentId,
		HostID:        req.HostId,
		Stream:        req.Stream,
		From:          from,
		To:            to,
		Query:         req.Q,
		Regex:         req.Regex,
		Attrs:         req.Attrs,
		Limit:         int(req.Limit),
		Before:        req.Before,
		After:         req.After,
	})
	if err != nil {
		return nil, fmt.Errorf("search container_logs: %w", err)
	}
	resp := &pb.SearchContainerLogsResponse{Rows: make([]*pb.ContainerLogRow, 0, len(rows))}
	for _, r := range rows {
		resp.Rows = append(resp.Rows, containerRowToProto(r))
	}
	if len(rows) > 0 {
		// Cursors: next page (older) starts at the oldest row id; previous
		// page (newer) starts at the newest. Both directions use the same
		// row ordering since we always re-emit DESC.
		resp.NextBeforeCursor = rows[len(rows)-1].ID
		resp.NextAfterCursor = rows[0].ID
	}
	return resp, nil
}

// ListContainers returns dimension-table rows.
func (s *Server) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	rows, err := s.database.ListContainers(ctx, db.ContainerListParams{
		Project:   req.Project,
		Component: req.Component,
		HostID:    req.HostId,
		State:     req.State,
		Limit:     int(req.Limit),
		Before:    req.Before,
	})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	resp := &pb.ListContainersResponse{Containers: make([]*pb.Container, 0, len(rows))}
	for _, r := range rows {
		resp.Containers = append(resp.Containers, dimensionToProto(r))
	}
	if len(rows) > 0 {
		resp.NextBeforeCursor = rows[len(rows)-1].ID
	}
	return resp, nil
}

// GetContainerLogContext returns ±N lines around the anchor id.
func (s *Server) GetContainerLogContext(ctx context.Context, req *pb.GetContainerLogContextRequest) (*pb.SearchContainerLogsResponse, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	n := int(req.N)
	rows, err := s.database.GetContainerLogContext(ctx, req.Id, n)
	if err != nil {
		return nil, fmt.Errorf("context: %w", err)
	}
	resp := &pb.SearchContainerLogsResponse{Rows: make([]*pb.ContainerLogRow, 0, len(rows))}
	for _, r := range rows {
		resp.Rows = append(resp.Rows, containerRowToProto(r))
	}
	return resp, nil
}

// GetIngestStatus reports container-log shipper health. Read by the admin
// /api/system/health/ingest handler so the UI can show a banner.
func (s *Server) GetIngestStatus(_ context.Context, _ *pb.IngestStatusRequest) (*pb.IngestStatusResponse, error) {
	if s.containerPipeline == nil {
		return &pb.IngestStatusResponse{Degraded: true}, nil
	}
	enq, dropped, queueLen, lastBatchAt, active, spoolBytes, spoolOldestSec, degraded :=
		s.containerPipeline.IngestStats(60 * time.Second)
	resp := &pb.IngestStatusResponse{
		EnqueuedTotal:      enq,
		DroppedTotal:       dropped,
		QueueLen:           int32(queueLen),
		SpoolBytes:         spoolBytes,
		SpoolOldestSeconds: spoolOldestSec,
		Degraded:           degraded,
		ContainersActive:   active,
	}
	if !lastBatchAt.IsZero() {
		resp.LastBatchAt = lastBatchAt.UTC().Format(time.RFC3339Nano)
	}
	return resp, nil
}

// --- helpers ---

func parseRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

func containerRowToProto(r db.ContainerLogRow) *pb.ContainerLogRow {
	out := &pb.ContainerLogRow{
		Id:            r.ID,
		Timestamp:     r.Timestamp.UTC().Format(time.RFC3339Nano),
		ReceivedAt:    r.ReceivedAt.UTC().Format(time.RFC3339Nano),
		HostId:        r.HostID,
		ContainerId:   r.ContainerID,
		ContainerName: r.ContainerName,
		Stream:        r.Stream,
		Line:          r.Line,
		Truncated:     r.Truncated,
		Seq:           r.Seq,
	}
	if r.Image != nil {
		out.Image = *r.Image
	}
	if r.Project != nil {
		out.Project = *r.Project
	}
	if r.Component != nil {
		out.Component = *r.Component
	}
	if r.ReleaseID != nil {
		out.ReleaseId = *r.ReleaseID
	}
	if r.DeploymentID != nil {
		out.DeploymentId = *r.DeploymentID
	}
	if len(r.Attrs) > 0 {
		out.AttrsJson = string(r.Attrs)
	}
	return out
}

func dimensionToProto(r db.ContainerRow) *pb.Container {
	out := &pb.Container{
		Id:            r.ID,
		ContainerId:   r.ContainerID,
		ContainerName: r.ContainerName,
		Image:         r.Image,
		ImageDigest:   r.ImageDigest,
		HostId:        r.HostID,
		StartedAt:     r.StartedAt.UTC().Format(time.RFC3339),
	}
	if r.Project != nil {
		out.Project = *r.Project
	}
	if r.Component != nil {
		out.Component = *r.Component
	}
	if r.ReleaseID != nil {
		out.ReleaseId = *r.ReleaseID
	}
	if r.DeploymentID != nil {
		out.DeploymentId = *r.DeploymentID
	}
	if len(r.Labels) > 0 {
		out.LabelsJson = string(r.Labels)
	}
	if r.FinishedAt != nil {
		out.FinishedAt = r.FinishedAt.UTC().Format(time.RFC3339)
	}
	if r.ExitCode != nil {
		out.ExitCode = int32(*r.ExitCode)
	}
	if r.LastLogAt != nil {
		out.LastLogAt = r.LastLogAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

// logf is a tiny indirection for non-fatal handler errors. Goes through
// slog's default handler (wired in cmd/dialog-siem). Container log path
// is intentionally low-fidelity — operators read the dialog-siem
// container's stdout to debug ingest issues.
func (s *Server) logf(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...))
}
