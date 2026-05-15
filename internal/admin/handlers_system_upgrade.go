package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	pb "muvon/proto/deployerpb"
)

// SystemUpgrade flow — operator-facing self-update wired through
// muvon-deployer. Two-endpoint dance:
//
//   POST /api/system/upgrade            → enqueue (CSRF-protected)
//   GET  /api/system/upgrade/stream     → SSE drain (no CSRF needed)
//
// The split exists because browsers can't attach the X-CSRF-Token
// header on an EventSource — SSE has to be a GET. Caller pattern: POST,
// then connect EventSource to the stream URL.
//
// Concurrency: at most one upgrade may be in progress at a time. We
// guard with both an in-memory broker (this file) and a Postgres
// advisory lock (acquired from the deployer side, so multi-instance
// admin deployments — if anyone ever runs one — also serialise).

// upgradeBroker fans the deployer's gRPC stream out to many SSE
// listeners. Only one upgrade can be active at a time; concurrent
// POSTs return 409.
type upgradeBroker struct {
	mu        sync.Mutex
	active    bool
	events    []*pb.UpgradeEvent // history for late-joining listeners
	listeners []chan *pb.UpgradeEvent
	done      chan struct{}
}

func newUpgradeBroker() *upgradeBroker {
	return &upgradeBroker{}
}

// start marks an upgrade in progress; returns false if one is already
// running. Caller must drive the stream by feeding events via push().
func (b *upgradeBroker) start() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active {
		return false
	}
	b.active = true
	b.events = nil
	b.done = make(chan struct{})
	return true
}

// push fans an event out to every current listener and records it in
// the replay buffer. When ev.Done is true the broker also closes all
// listener channels and clears active state.
func (b *upgradeBroker) push(ev *pb.UpgradeEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, ev)
	for _, ch := range b.listeners {
		select {
		case ch <- ev:
		default:
		}
	}
	if ev.GetDone() {
		for _, ch := range b.listeners {
			close(ch)
		}
		b.listeners = nil
		b.active = false
		close(b.done)
	}
}

// subscribe registers a new SSE listener. The returned channel is
// closed when the upgrade finishes (Done=true). New listeners replay
// the full event history first so a late-arriving browser tab can
// catch up to the current step.
func (b *upgradeBroker) subscribe() (history []*pb.UpgradeEvent, ch <-chan *pb.UpgradeEvent, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.active {
		return nil, nil, false
	}
	history = append([]*pb.UpgradeEvent(nil), b.events...)
	c := make(chan *pb.UpgradeEvent, 32)
	b.listeners = append(b.listeners, c)
	return history, c, true
}

func (b *upgradeBroker) waitDone() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done == nil {
		// No upgrade running; closed channel signals "nothing to wait for".
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return b.done
}

// handleSystemUpgrade kicks off an upgrade. Returns immediately with
// 202 + the stream URL. The actual work runs in a background goroutine
// that talks to muvon-deployer over gRPC.
func (s *Server) handleSystemUpgrade(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetTag  string `json:"target_tag"`
		TakeBackup bool   `json:"take_backup"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if s.deployerClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "deployer is unavailable"})
		return
	}
	if !s.upgradeBroker.start() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an upgrade is already in progress"})
		return
	}

	s.auditLog(r, "system.upgrade", "system", "upgrade", map[string]any{
		"target_tag":  req.TargetTag,
		"take_backup": req.TakeBackup,
	})

	// Background driver — runs even if the operator closes the tab.
	go s.driveUpgrade(req.TargetTag, req.TakeBackup)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"stream_url": "/api/system/upgrade/stream",
		"target_tag": req.TargetTag,
	})
}

// driveUpgrade owns the gRPC stream lifecycle. Each deployer event is
// pushed into the broker; on completion (Done or error) the broker
// closes its listeners.
func (s *Server) driveUpgrade(targetTag string, takeBackup bool) {
	// Long but bounded — the helper container's `compose up --wait`
	// is itself capped at 120s, plus pull time and our pg_dump.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	stream, err := s.deployerClient.SystemUpgrade(ctx, &pb.SystemUpgradeRequest{
		TargetTag:  targetTag,
		TakeBackup: takeBackup,
	})
	if err != nil {
		s.upgradeBroker.push(&pb.UpgradeEvent{
			Step:      "failed",
			Level:     "error",
			Message:   fmt.Sprintf("deployer gRPC call failed: %v", err),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Done:      true,
		})
		return
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			// Stream EOF — deployer recreated as part of the upgrade.
			// This is EXPECTED, but does NOT mean the upgrade succeeded;
			// the helper container is still finishing. Poll local health
			// before declaring done so a half-finished compose-up doesn't
			// flash a green checkmark on the UI.
			s.upgradeBroker.push(&pb.UpgradeEvent{
				Step:      "post_check",
				Level:     "info",
				Message:   "deployer stream closed, waiting for muvon to come back healthy...",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Done:      false,
			})
			if healthy := s.waitLocalHealthy(60 * time.Second); healthy {
				s.upgradeBroker.push(&pb.UpgradeEvent{
					Step:      "done",
					Level:     "info",
					Message:   "upgrade verified — muvon healthy on new image",
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Done:      true,
				})
			} else {
				s.upgradeBroker.push(&pb.UpgradeEvent{
					Step:      "failed",
					Level:     "error",
					Message:   "muvon did not become healthy within 60s — upgrade likely failed (check `docker compose ps`)",
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Done:      true,
				})
			}
			return
		}
		s.upgradeBroker.push(ev)
		if ev.GetDone() {
			return
		}
	}
}

// waitLocalHealthy polls /health on the local admin port (auth-free,
// unlike /api/health which requires JWT) until it returns 200 or the
// timeout elapses. Loopback bind is always available even when the
// public HTTPS listener is restarting.
func (s *Server) waitLocalHealthy(timeout time.Duration) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	url := "http://127.0.0.1:9443/health"
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// handleSystemUpgradeStream is the SSE endpoint browsers connect to.
// Replays history first, then streams live events.
func (s *Server) handleSystemUpgradeStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Upgrade can run minutes; clear the 60s WriteTimeout for this conn.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Time{})
	}
	w.WriteHeader(http.StatusOK)

	history, ch, active := s.upgradeBroker.subscribe()
	if !active {
		fmt.Fprintf(w, "event: idle\ndata: {\"message\":\"no upgrade in progress\"}\n\n")
		flusher.Flush()
		return
	}
	emit := func(ev *pb.UpgradeEvent) {
		// Serialise selected fields only — proto's generated json
		// representation pulls in MessageState/sync.Mutex internals
		// which json/v1 silently embeds zero-values for. Map → exact
		// shape the UI expects.
		data, _ := json.Marshal(map[string]any{
			"step":      ev.GetStep(),
			"level":     ev.GetLevel(),
			"message":   ev.GetMessage(),
			"timestamp": ev.GetTimestamp(),
			"done":      ev.GetDone(),
		})
		fmt.Fprintf(w, "event: upgrade\ndata: %s\n\n", data)
		flusher.Flush()
	}
	for _, ev := range history {
		emit(ev)
	}
	for ev := range ch {
		emit(ev)
	}
	fmt.Fprintf(w, "event: end\ndata: {}\n\n")
	flusher.Flush()
}
