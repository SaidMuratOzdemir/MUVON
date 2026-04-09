package agentsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"muvon/internal/config"
	"muvon/internal/db"
)

// Service handles HTTP endpoints used by remote agents.
// It runs on the central server and is registered inside the admin HTTP mux.
type Service struct {
	db          *db.DB
	holder      *config.Holder
	broadcaster *Broadcaster
}

func NewService(database *db.DB, holder *config.Holder, broadcaster *Broadcaster) *Service {
	return &Service{
		db:          database,
		holder:      holder,
		broadcaster: broadcaster,
	}
}

// BroadcastUpdate signals all connected agents to reload their config.
// Call this whenever the central config changes (e.g. inside Holder.OnReload).
func (s *Service) BroadcastUpdate() {
	s.broadcaster.Broadcast()
}

type contextKey int

const agentIDKey contextKey = 0

// AuthMiddleware validates the X-Api-Key header against the agents table.
func (s *Service) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Api-Key")
		if key == "" {
			http.Error(w, `{"error":"missing api key"}`, http.StatusUnauthorized)
			return
		}
		agent, err := s.db.GetAgentByKey(r.Context(), key)
		if err != nil || !agent.IsActive {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), agentIDKey, agent.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HandleConfig serves the current config as an AgentPayload JSON.
// GET /api/v1/agent/config
func (s *Service) HandleConfig(w http.ResponseWriter, r *http.Request) {
	if id, ok := r.Context().Value(agentIDKey).(string); ok && id != "" {
		go s.db.TouchAgentLastSeen(context.Background(), id)
	}
	cfg := s.holder.Get()
	payload := config.AgentPayloadFromConfig(cfg)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

// HandleWatch opens an SSE stream. The central pushes "config_updated" events
// whenever the config changes. Agents keep this connection open.
// GET /api/v1/agent/watch
func (s *Service) HandleWatch(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.broadcaster.Subscribe()
	defer s.broadcaster.Unsubscribe(ch)

	// Initial ping to confirm connection
	fmt.Fprint(w, ": ping\n\n")
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ch:
			fmt.Fprint(w, "event: config_updated\ndata: {}\n\n")
			flusher.Flush()
			slog.Debug("config_updated pushed to agent", "remote", r.RemoteAddr)
		case <-ticker.C:
			// Keep-alive ping
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			slog.Debug("agent watch stream closed", "remote", r.RemoteAddr)
			return
		}
	}
}
