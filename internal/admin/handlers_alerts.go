package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"muvon/internal/db"
)

// --- Alerts ------------------------------------------------------------------
//
// The admin panel reads the alerts hypertable produced by diaLOG's
// correlation engine. MUVON and diaLOG share a Postgres instance so the
// query goes through the same *db.DB handle — no extra service or gRPC hop.
// Any row-level acknowledgement is attributed to the signed-in admin so the
// audit trail survives even after the cooldown row is archived.

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := db.AlertSearchParams{
		Rule:        q.Get("rule"),
		Severity:    q.Get("severity"),
		Host:        q.Get("host"),
		SourceIP:    q.Get("source_ip"),
		Project:     q.Get("project"),
		Fingerprint: q.Get("fingerprint"),
	}
	if v := q.Get("rule_id"); v != "" {
		if _, err := uuid.Parse(v); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule_id must be a UUID"})
			return
		}
		params.RuleID = v
	}
	for key, dst := range map[string]**bool{"acknowledged": &params.Acknowledged, "is_test": &params.IsTest} {
		v := q.Get(key)
		if v == "" {
			continue
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": key + " must be true or false"})
			return
		}
		*dst = &b
	}
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from must be RFC3339"})
			return
		}
		params.From = t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to must be RFC3339"})
			return
		}
		params.To = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			params.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			params.Offset = n
		}
	}

	alerts, total, err := s.db.SearchAlerts(r.Context(), params)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list alerts"})
		return
	}
	if alerts == nil {
		alerts = []db.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":   alerts,
		"total":  total,
		"limit":  params.Limit,
		"offset": params.Offset,
	})
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	alert, err := s.db.GetAlert(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, _ := r.Context().Value(usernameKey).(string)
	if user == "" {
		user = "unknown"
	}
	alert, err := s.db.AcknowledgeAlert(r.Context(), id, user)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	s.auditLog(r, "alert.acknowledge", "alert", id, map[string]any{"rule": alert.Rule, "severity": alert.Severity})
	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetAlertStats(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch alert stats"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
