package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	deployerpb "muvon/proto/deployerpb"
	pb "muvon/proto/logpb"
)

// requireDeployer returns true when the deployer gRPC client is wired.
// Live tail + live container picker need the deployer; history search
// does not.
func (s *Server) requireDeployer(w http.ResponseWriter) bool {
	if s.deployerClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "muvon-deployer service unavailable"})
		return false
	}
	return true
}

// handleListContainers merges:
//   - live state from muvon-deployer (running containers right now)
//   - historical dimension rows from diaLOG (containers we have ever
//     ingested logs for, including ones already destroyed)
//
// keyed by container_id. Live state wins for any field both sides
// provide; historical fills in the rest. The merged shape is what the
// UI's container picker renders.
func (s *Server) handleListContainers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")     // "" | "running" | "exited"
	project := q.Get("project")
	component := q.Get("component")
	hostID := q.Get("host_id")
	limit, _ := strconv.Atoi(q.Get("limit"))

	type mergedContainer struct {
		ContainerID   string            `json:"container_id"`
		ContainerName string            `json:"container_name"`
		Image         string            `json:"image,omitempty"`
		ImageDigest   string            `json:"image_digest,omitempty"`
		Project       string            `json:"project,omitempty"`
		Component     string            `json:"component,omitempty"`
		ReleaseID     string            `json:"release_id,omitempty"`
		DeploymentID  string            `json:"deployment_id,omitempty"`
		HostID        string            `json:"host_id"`
		State         string            `json:"state"`           // running, exited, ...
		Status        string            `json:"status,omitempty"`// human readable docker status
		Live          bool              `json:"live"`            // true: visible in deployer
		StartedAt     string            `json:"started_at,omitempty"`
		FinishedAt    string            `json:"finished_at,omitempty"`
		ExitCode      *int32            `json:"exit_code,omitempty"`
		LastLogAt     string            `json:"last_log_at,omitempty"`
		Labels        map[string]string `json:"labels,omitempty"`
	}

	merged := make(map[string]*mergedContainer)

	// Live containers — only when deployer is up. Filtering by host_id
	// here means "central" only (the local deployer never reports
	// agent containers). When the request asks for a specific agent
	// host_id we skip the live call.
	if s.deployerClient != nil && (hostID == "" || hostID == "central") {
		req := &deployerpb.ListContainersRequest{
			Project:   project,
			Component: component,
			State:     state,
		}
		if ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second); cancel != nil {
			defer cancel()
			if resp, err := s.deployerClient.ListContainers(ctx, req); err == nil && resp != nil {
				for _, c := range resp.Containers {
					m := &mergedContainer{
						ContainerID:   c.ContainerId,
						ContainerName: c.ContainerName,
						Image:         c.Image,
						ImageDigest:   c.ImageDigest,
						Project:       c.Project,
						Component:     c.Component,
						ReleaseID:     c.ReleaseId,
						HostID:        "central",
						State:         c.State,
						Status:        c.Status,
						Live:          true,
						StartedAt:     c.StartedAt,
						FinishedAt:    c.FinishedAt,
						Labels:        c.Labels,
					}
					if c.ExitCode != 0 || c.FinishedAt != "" {
						v := c.ExitCode
						m.ExitCode = &v
					}
					merged[c.ContainerId] = m
				}
			}
		}
	}

	// Historical from dialog. Always queried so containers that are
	// gone (the user's incident scenario) still appear.
	if s.logClient != nil {
		dialReq := &pb.ListContainersRequest{
			Project:   project,
			Component: component,
			HostId:    hostID,
			State:     state,
			Limit:     int32(limit),
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if resp, err := s.logClient.ListContainersFromDialog(ctx, dialReq); err == nil && resp != nil {
			for _, c := range resp.Containers {
				m, ok := merged[c.ContainerId]
				if !ok {
					m = &mergedContainer{
						ContainerID:   c.ContainerId,
						ContainerName: c.ContainerName,
						HostID:        c.HostId,
					}
					merged[c.ContainerId] = m
				}
				if m.Image == "" {
					m.Image = c.Image
				}
				if m.ImageDigest == "" {
					m.ImageDigest = c.ImageDigest
				}
				if m.Project == "" {
					m.Project = c.Project
				}
				if m.Component == "" {
					m.Component = c.Component
				}
				if m.ReleaseID == "" {
					m.ReleaseID = c.ReleaseId
				}
				if m.DeploymentID == "" {
					m.DeploymentID = c.DeploymentId
				}
				if m.HostID == "" {
					m.HostID = c.HostId
				}
				if m.StartedAt == "" {
					m.StartedAt = c.StartedAt
				}
				if c.FinishedAt != "" {
					m.FinishedAt = c.FinishedAt
					if m.State == "" || !m.Live {
						m.State = "exited"
					}
				}
				if c.ExitCode != 0 || c.FinishedAt != "" {
					if m.ExitCode == nil {
						v := c.ExitCode
						m.ExitCode = &v
					}
				}
				if c.LastLogAt != "" {
					m.LastLogAt = c.LastLogAt
				}
				if !m.Live && m.State == "" {
					if c.FinishedAt != "" {
						m.State = "exited"
					} else {
						m.State = "unknown"
					}
				}
			}
		}
	}

	out := make([]*mergedContainer, 0, len(merged))
	for _, m := range merged {
		// Final state filter — applied here because dialog/deployer
		// each apply their own and we want a unified view.
		switch state {
		case "running":
			if !m.Live {
				continue
			}
		case "exited":
			if m.Live {
				continue
			}
		}
		out = append(out, m)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data":  out,
		"count": len(out),
	})
}

// handleGetContainer returns deployer detail when the container is
// alive; otherwise falls back to dialog's dimension row. Allows the UI
// to show a unified detail view regardless of liveness.
func (s *Server) handleGetContainer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	if s.deployerClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if d, err := s.deployerClient.GetContainer(ctx, id); err == nil && d != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"live":      true,
				"container": d,
			})
			return
		}
	}

	if s.logClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "container detail unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp, err := s.logClient.ListContainersFromDialog(ctx, &pb.ListContainersRequest{Limit: 1})
	if err != nil || resp == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "container not found"})
		return
	}
	for _, c := range resp.Containers {
		if c.ContainerId == id {
			writeJSON(w, http.StatusOK, map[string]any{
				"live":      false,
				"container": c,
			})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "container not found"})
}

// handleStreamContainerLogs is the SSE bridge to the deployer's gRPC
// StreamContainerLogs. Mirrors handleStreamLogs's headers and ping
// cadence so reverse-proxy chains stay friendly.
func (s *Server) handleStreamContainerLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireDeployer(w) {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
		return
	}

	q := r.URL.Query()
	tail := int32(200)
	if v := q.Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			tail = int32(n)
		}
	}
	follow := q.Get("follow") != "false" // default true
	streams := []string{}
	for _, s := range []string{"stdout", "stderr"} {
		if q.Get(s) == "true" || q.Get("streams") == "" {
			streams = append(streams, s)
		}
	}
	since := q.Get("since")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")

	// Audit so the access trail is in place from day 1 — RBAC may
	// later restrict the read but the audit log already records who
	// pulled which container.
	s.auditLog(r, "container.log_tail", "container", id, map[string]any{"tail": tail, "follow": follow})

	ch, err := s.deployerClient.StreamContainerLogs(r.Context(), &deployerpb.StreamContainerLogsRequest{
		ContainerId: id,
		Tail:        tail,
		Follow:      follow,
		Streams:     streams,
		Since:       since,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-pingTicker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case chunk, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(chunk)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// handleSearchContainerLogs proxies the dialog SearchContainerLogs RPC.
// Cursor pagination uses UUIDv7 row ids; the UI passes ?before=<id> /
// ?after=<id> for next/previous pages.
func (s *Server) handleSearchContainerLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}

	q := r.URL.Query()
	req := &pb.SearchContainerLogsRequest{
		ContainerId:   q.Get("container_id"),
		ContainerName: q.Get("container_name"),
		Project:       q.Get("project"),
		Component:     q.Get("component"),
		ReleaseId:     q.Get("release_id"),
		DeploymentId:  q.Get("deployment_id"),
		HostId:        q.Get("host_id"),
		Stream:        q.Get("stream"),
		From:          q.Get("from"),
		To:            q.Get("to"),
		Q:             q.Get("q"),
		Regex:         q.Get("regex") == "true" || q.Get("regex") == "1",
		Before:        q.Get("before"),
		After:         q.Get("after"),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			req.Limit = int32(n)
		}
	}
	// attrs.<key>=<value> filter — keep it shallow on purpose so the
	// query stays cheap. Repeated keys overwrite.
	if attrs := r.URL.Query()["attr"]; len(attrs) > 0 {
		req.Attrs = make(map[string]string, len(attrs))
		for _, kv := range attrs {
			for i := 0; i < len(kv); i++ {
				if kv[i] == '=' {
					req.Attrs[kv[:i]] = kv[i+1:]
					break
				}
			}
		}
	}

	resp, err := s.logClient.SearchContainerLogs(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rows := resp.Rows
	if rows == nil {
		rows = []*pb.ContainerLogRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":               rows,
		"next_before_cursor": resp.NextBeforeCursor,
		"next_after_cursor":  resp.NextAfterCursor,
	})
}

// handleContainerLogContext returns ±N lines around an anchor row.
func (s *Server) handleContainerLogContext(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}
	id := r.PathValue("id")
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 50
	}
	resp, err := s.logClient.GetContainerLogContext(r.Context(), id, n)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rows := resp.Rows
	if rows == nil {
		rows = []*pb.ContainerLogRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

// handleIngestHealth surfaces dialog-siem's GetIngestStatus + the
// deployer's Health (active tails, shipper container count). UI reads
// this for the ingestion-degraded banner.
func (s *Server) handleIngestHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"dialog_available":   s.logClient != nil,
		"deployer_available": s.deployerClient != nil,
	}
	if s.logClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if st, err := s.logClient.GetIngestStatus(ctx); err == nil && st != nil {
			resp["dialog"] = st
		}
	}
	if s.deployerClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if h, err := s.deployerClient.Health(ctx); err == nil && h != nil {
			resp["deployer"] = h
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
