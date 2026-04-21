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
	req := &pb.SearchLogsRequest{
		Host:     q.Get("host"),
		Path:     q.Get("path"),
		Method:   q.Get("method"),
		ClientIp: q.Get("client_ip"),
		Search:   q.Get("q"),
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
