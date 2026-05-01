package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"muvon/internal/db"
	pb "muvon/proto/logpb"
)

func (s *Server) handleSearchLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}

	q := r.URL.Query()
	// `search` is the SPA's param name and also the most natural label.
	// `q` stays as a fallback so anything hand-crafting URLs against the
	// old name keeps working.
	searchTerm := q.Get("search")
	if searchTerm == "" {
		searchTerm = q.Get("q")
	}
	req := &pb.SearchLogsRequest{
		Host:     q.Get("host"),
		Path:     q.Get("path"),
		Method:   q.Get("method"),
		ClientIp: q.Get("client_ip"),
		Search:   searchTerm,
		User:     q.Get("user"),
	}

	if v := q.Get("status_min"); v != "" {
		n, _ := strconv.Atoi(v)
		req.StatusMin = int32(n)
	}
	if v := q.Get("status_max"); v != "" {
		n, _ := strconv.Atoi(v)
		req.StatusMax = int32(n)
	}
	if v := q.Get("from"); v != "" {
		req.From = v
	}
	if v := q.Get("to"); v != "" {
		req.To = v
	}
	if v := q.Get("limit"); v != "" {
		n, _ := strconv.Atoi(v)
		req.Limit = int32(n)
	}
	if v := q.Get("offset"); v != "" {
		n, _ := strconv.Atoi(v)
		req.Offset = int32(n)
	}
	if v := q.Get("starred"); v == "true" || v == "1" {
		req.Starred = true
	}
	if v := q.Get("response_time_min"); v != "" {
		n, _ := strconv.Atoi(v)
		req.RespTimeMin = int32(n)
	}
	if v := q.Get("response_time_max"); v != "" {
		n, _ := strconv.Atoi(v)
		req.RespTimeMax = int32(n)
	}

	resp, err := s.logClient.SearchLogs(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	logs := resp.Logs
	if logs == nil {
		logs = []*pb.LogSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":   logs,
		"total":  resp.Total,
		"limit":  req.Limit,
		"offset": req.Offset,
	})
}

func (s *Server) handleGetLog(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}

	requestID := r.PathValue("id")
	if requestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	detail, err := s.logClient.GetLog(r.Context(), requestID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "log not found"})
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// logStatsResp is the JSON shape the frontend LogStats interface expects.
type logStatsResp struct {
	TotalRequests  int64             `json:"total_requests"`
	TotalErrors    int64             `json:"total_errors"`
	StatusCounts   map[string]int64  `json:"status_counts"`
	AvgResponseMs  float64           `json:"avg_response_ms"`
	P95ResponseMs  float64           `json:"p95_response_ms"`
	P99ResponseMs  float64           `json:"p99_response_ms"`
	TopHosts       []db.HostCount    `json:"top_hosts"`
	TopPaths       []db.PathCount    `json:"top_paths"`
	TopCountries   []db.CountryCount `json:"top_countries"`
	TopUsers       []db.UserCount    `json:"top_users"`
	RequestsPerMin float64           `json:"requests_per_min"`
}

func (s *Server) handleLogStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}

	q := r.URL.Query()
	from := q.Get("from")
	to := q.Get("to")
	if from == "" {
		from = time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	}
	if to == "" {
		to = time.Now().Format(time.RFC3339)
	}

	proto, err := s.logClient.GetLogStats(r.Context(), q.Get("host"), from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	statusCounts := proto.GetStatusDistribution()
	if statusCounts == nil {
		statusCounts = map[string]int64{}
	}

	decodeOpaque := func(j string, out any) {
		if j == "" {
			return
		}
		_ = json.Unmarshal([]byte(j), out)
	}
	var topCountries []db.CountryCount
	var topHosts []db.HostCount
	var topPaths []db.PathCount
	var topUsers []db.UserCount
	decodeOpaque(proto.GetTopCountriesJson(), &topCountries)
	decodeOpaque(proto.GetTopHostsJson(), &topHosts)
	decodeOpaque(proto.GetTopPathsJson(), &topPaths)
	decodeOpaque(proto.GetTopUsersJson(), &topUsers)

	if topCountries == nil {
		topCountries = []db.CountryCount{}
	}
	if topHosts == nil {
		topHosts = []db.HostCount{}
	}
	if topPaths == nil {
		topPaths = []db.PathCount{}
	}
	if topUsers == nil {
		topUsers = []db.UserCount{}
	}

	resp := logStatsResp{
		TotalRequests:  proto.GetTotalRequests(),
		TotalErrors:    proto.GetTotalErrors(),
		StatusCounts:   statusCounts,
		AvgResponseMs:  proto.GetAvgResponseMs(),
		P95ResponseMs:  proto.GetP95ResponseMs(),
		P99ResponseMs:  proto.GetP99ResponseMs(),
		TopHosts:       topHosts,
		TopPaths:       topPaths,
		TopCountries:   topCountries,
		TopUsers:       topUsers,
		RequestsPerMin: proto.GetRequestsPerMin(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleStreamLogs streams log entries from diaLOG via gRPC→SSE bridge.
func (s *Server) handleStreamLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")

	host := r.URL.Query().Get("host")

	ch, err := s.logClient.StreamLogs(r.Context(), host)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleUpsertLogNote(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}

	requestID := r.PathValue("id")
	if requestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if err := s.logClient.UpsertNote(r.Context(), requestID, req.Note); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRevealLogJWT returns the raw bearer token captured for a single log
// row when the host opted into store_raw_jwt. Every successful reveal lands
// in the audit log so a token leak via this surface can always be traced
// back to a specific admin user. Returns 404 when no token was captured
// for that row (host opted out, request had no Authorization, or the row
// pre-dates the column).
func (s *Server) handleRevealLogJWT(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}
	requestID := r.PathValue("id")
	if requestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	resp, err := s.logClient.GetLogRawJWT(r.Context(), requestID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if resp.Token == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no captured token for this log entry",
		})
		return
	}

	// Audit before serving — if the write fails we still serve, since the
	// admin has already authenticated and the request is loggable elsewhere
	// in the access log; we just record the failure.
	s.auditLog(r, "log.reveal_jwt", "log", requestID, map[string]string{
		"host": resp.Host,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"request_id": requestID,
		"host":       resp.Host,
		"token":      resp.Token,
	})
}

func (s *Server) handleToggleLogStar(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}

	requestID := r.PathValue("id")
	if requestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	if err := s.logClient.ToggleStar(r.Context(), requestID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
