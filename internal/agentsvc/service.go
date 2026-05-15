package agentsvc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"muvon/internal/config"
	"muvon/internal/db"
	tlspkg "muvon/internal/tls"
)

// Service handles HTTP endpoints used by remote agents.
// It runs on the central server and is registered inside the admin HTTP mux.
type Service struct {
	db          *db.DB
	holder      *config.Holder
	broadcaster *Broadcaster
	tlsManager  *tlspkg.Manager // optional — used to invalidate cache on cert push
	// commandBus dispatches "wake up, new command" signals to the agent
	// long-poll handler. The actual command payload lives in
	// muvon.agent_commands (Postgres); the bus is just a signal channel
	// so polling agents react in milliseconds instead of waiting for
	// the next tick.
	commandBus *CommandBus
	// signingKey is the HMAC key for command signatures (derived from
	// MUVON_ENCRYPTION_KEY via HKDF). Empty key = command channel
	// disabled — admin endpoint returns 503.
	signingKey []byte
}

func NewService(database *db.DB, holder *config.Holder, broadcaster *Broadcaster) *Service {
	return &Service{
		db:          database,
		holder:      holder,
		broadcaster: broadcaster,
		commandBus:  NewCommandBus(),
	}
}

// SetCommandSigningKey wires the HMAC key for the agent command
// channel. Called at startup from cmd/muvon/main.go after deriving the
// key from MUVON_ENCRYPTION_KEY. When the key is empty (operator never
// set MUVON_ENCRYPTION_KEY) command endpoints refuse to enqueue.
func (s *Service) SetCommandSigningKey(key []byte) {
	s.signingKey = key
}

// CommandBus exposes the in-memory wake bus so the admin handler can
// notify agents after enqueuing a command in the same request.
func (s *Service) CommandBus() *CommandBus { return s.commandBus }

// HasCommandSigning reports whether the command channel is usable —
// admin handlers gate POST /api/agents/:id/commands on this so we
// don't enqueue rows the agent will never accept (signature verify
// fails when key is empty).
func (s *Service) HasCommandSigning() bool { return len(s.signingKey) > 0 }

// SigningKey returns a copy of the HMAC key. Avoid leaking — only
// the admin enqueue handler should call this.
func (s *Service) SigningKey() []byte {
	k := make([]byte, len(s.signingKey))
	copy(k, s.signingKey)
	return k
}

// SetTLSManager attaches the central TLS manager so a cert upload from an
// agent invalidates central's in-memory cache too. Optional.
func (s *Service) SetTLSManager(m *tlspkg.Manager) {
	s.tlsManager = m
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
	cfg := s.holder.Get()
	// AgentID lives in request context (the auth middleware put it there).
	// Filtering the payload by that ID is what makes ownership enforcement
	// work: an agent only ever learns about the hosts it is supposed to
	// terminate, so it physically cannot serve traffic for anything else.
	agentID, _ := r.Context().Value(agentIDKey).(string)
	payload := config.AgentPayloadFromConfig(cfg, agentID)
	payload.Version = s.holder.Version()
	// Operator-managed extra bind mounts live on the agent row, not in
	// the global config snapshot. Read the row inline so the payload is
	// self-contained and the agent never has to make a second request
	// to learn what to mount.
	if agentID != "" {
		if ag, err := s.db.GetAgent(r.Context(), agentID); err == nil {
			payload.ExtraMounts = ag.ExtraMounts
		}
	}

	if agentID != "" {
		// Stamp the agent row with the version they just pulled, plus the
		// HTTP context that produced the request. We run it on a fresh
		// context so the request lifecycle never gates the DB write.
		remote := remoteAddrOf(r)
		ua := truncate(r.UserAgent(), 200)
		// Agent self-reports its public IP via this header so DNS
		// verification has the right target even when source IP is the
		// agent's private interface (Hetzner private network, etc).
		publicIP := strings.TrimSpace(r.Header.Get("X-Agent-Public-IP"))
		go s.db.RecordAgentConfigPull(context.Background(), agentID, payload.Version, remote, ua, publicIP)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Config-Version", payload.Version)
	json.NewEncoder(w).Encode(payload)
}

// remoteAddrOf prefers the X-Forwarded-For client when an admin-side proxy
// fronts central. Falls back to RemoteAddr.
func remoteAddrOf(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF is a comma-separated chain; the leftmost entry is the
		// original client per RFC 7239.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	return r.RemoteAddr
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// HandleGetCert returns a TLS certificate for the requested domain, if one
// exists in cert_store. The agent calls this on startup (and after a
// config_updated SSE event) so a manually-uploaded cert beats whatever the
// agent has in autocert. Returns 404 when no cert is on file — the agent
// then falls back to its local ACME issuer.
func (s *Service) HandleGetCert(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		http.Error(w, `{"error":"domain required"}`, http.StatusBadRequest)
		return
	}

	cert, err := s.db.GetCertByDomain(r.Context(), domain)
	if err != nil {
		// Treat "no row" as 404 so the agent can distinguish "central has no
		// cert for this host, please ACME yourself" from a real error.
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	resp := map[string]any{
		"domain":     cert.Domain,
		"cert_pem":   string(cert.CertPEM),
		"key_pem":    string(cert.KeyPEM),
		"issuer":     cert.Issuer,
		"expires_at": cert.ExpiresAt.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleUploadCert accepts a freshly-issued certificate from an agent and
// upserts it into cert_store with issuer="letsencrypt:agent:<id>". This is a
// one-way backup — central does not redistribute these to other agents (each
// agent runs ACME independently for the domains it actually serves).
func (s *Service) HandleUploadCert(w http.ResponseWriter, r *http.Request) {
	agentID, _ := r.Context().Value(agentIDKey).(string)
	if agentID == "" {
		http.Error(w, `{"error":"agent context missing"}`, http.StatusUnauthorized)
		return
	}

	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		http.Error(w, `{"error":"domain required"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		http.Error(w, `{"error":"cert_pem and key_pem required"}`, http.StatusBadRequest)
		return
	}

	expiresAt, err := parseCertExpiry([]byte(req.CertPEM))
	if err != nil {
		http.Error(w, `{"error":"invalid cert PEM: `+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	issuer := "letsencrypt:agent:" + agentID
	if err := s.db.UpsertCert(r.Context(), domain, []byte(req.CertPEM), []byte(req.KeyPEM), issuer, expiresAt); err != nil {
		slog.Error("agent cert upload failed", "agent", agentID, "domain", domain, "error", err)
		http.Error(w, `{"error":"upsert failed"}`, http.StatusInternalServerError)
		return
	}
	if s.tlsManager != nil {
		s.tlsManager.InvalidateCache(domain)
	}
	slog.Info("agent cert backup stored", "agent", agentID, "domain", domain, "expires", expiresAt)
	w.WriteHeader(http.StatusNoContent)
}

func parseCertExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
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
