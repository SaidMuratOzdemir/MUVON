package admin

import (
	"net/http"
	"strconv"

	pb "muvon/proto/logpb"
)

// handleSearchClientEvents proxies the dialog SearchClientEvents RPC. The
// headline filter is ?trace_id=<hex>, which joins a browser event to the
// http_logs row (and, transitively, container_logs) that share the trace.
// Cursor pagination: ?before=<id> walks older rows.
func (s *Server) handleSearchClientEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireLog(w) {
		return
	}

	q := r.URL.Query()
	req := &pb.SearchClientEventsRequest{
		TraceId:   q.Get("trace_id"),
		SessionId: q.Get("session_id"),
		App:       q.Get("app"),
		HostId:    q.Get("host_id"),
		EventName: q.Get("event_name"),
		From:      q.Get("from"),
		To:        q.Get("to"),
		Before:    q.Get("before"),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			req.Limit = int32(n)
		}
	}

	resp, err := s.logClient.SearchClientEvents(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rows := resp.Rows
	if rows == nil {
		rows = []*pb.ClientEventRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":               rows,
		"next_before_cursor": resp.NextBeforeCursor,
	})
}
