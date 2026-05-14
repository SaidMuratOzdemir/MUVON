package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"muvon/internal/agentctrl"
	"muvon/internal/deployer"
	tlspkg "muvon/internal/tls"
)

// buildCommandRegistry wires every CommandKind to its agent-side
// handler. Handler design rules:
//
//   - Idempotent. Receiving the same command twice (because of an
//     ack-then-crash sequence) must not double-apply.
//   - Bounded. Handlers respect ctx and return within a reasonable
//     time; long-running ops happen in a detached goroutine and the
//     handler returns "kicked off" success immediately.
//   - Defensive on payload. JSON parse errors surface as failed
//     Results, never as panics.
//
// Handlers that affect process state (restart, set log level, drain)
// must NOT count on the same agent process to report success — the
// process may exit before reportResult lands. Acceptable: dispatch
// state in the DB already records "delivered", which is the strongest
// guarantee we can give for self-restarting operations.

// agentCommandDeps groups everything a command handler may want to
// poke at. Passing it through closures keeps the registry construction
// tidy without inventing a new "agent runtime" type.
type agentCommandDeps struct {
	dockerCli  *deployer.DockerClient // nil if no docker socket
	tlsMgr     *tlspkg.Manager
	dockerSock string
	// logLevelSetter exposes the runtime log level switch so the
	// agent.set_log_level handler can flip it back when the TTL
	// fires.
	logLevelSetter func(level string)
	// drainState toggles the proxy's "refuse new connections" mode.
	// Set by main.go before passing deps in.
	drainState *atomic.Bool
}

func buildCommandRegistry(deps agentCommandDeps) *agentctrl.Registry {
	reg := agentctrl.NewRegistry(1000)

	reg.Register(agentctrl.KindAgentCacheFlush, handleCacheFlush(deps))
	reg.Register(agentctrl.KindAgentSetLogLevel, handleSetLogLevel(deps))
	reg.Register(agentctrl.KindAgentDrain, handleDrain(deps))
	reg.Register(agentctrl.KindAgentRestart, handleAgentRestart())
	reg.Register(agentctrl.KindAgentSelfUpgrade, handleSelfUpgrade(deps))
	reg.Register(agentctrl.KindAgentRevoke, handleRevoke())
	reg.Register(agentctrl.KindCertRenew, handleCertRenew(deps))
	reg.Register(agentctrl.KindContainerRestart, handleContainerRestart(deps))
	reg.Register(agentctrl.KindDeployAbort, handleDeployAbort(deps))

	return reg
}

// ── Handlers ─────────────────────────────────────────────────────────────

// handleCacheFlush invalidates the chosen local cache. The TLS
// manager exposes InvalidateCache; the config cache is reloaded by
// signalling the holder's reload trigger (handled by the watch loop).
func handleCacheFlush(deps agentCommandDeps) agentctrl.Handler {
	return func(_ context.Context, cmd agentctrl.Command) (agentctrl.Result, error) {
		var p struct {
			Target string `json:"target"`
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		if p.Target == "" {
			p.Target = "all"
		}
		switch p.Target {
		case "cert", "all":
			if deps.tlsMgr != nil {
				deps.tlsMgr.InvalidateCache("")
			}
		}
		return agentctrl.Result{Output: "cache flushed: " + p.Target}, nil
	}
}

// handleSetLogLevel flips slog's level. A TTL goroutine reverts to
// "info" so debug logs don't leak forever after an incident.
func handleSetLogLevel(deps agentCommandDeps) agentctrl.Handler {
	return func(ctx context.Context, cmd agentctrl.Command) (agentctrl.Result, error) {
		var p struct {
			Level       string `json:"level"`
			TTLSeconds  int    `json:"ttl_seconds"`
		}
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return agentctrl.Result{}, fmt.Errorf("invalid payload: %w", err)
		}
		if p.Level == "" {
			return agentctrl.Result{}, fmt.Errorf("level required")
		}
		if p.TTLSeconds <= 0 || p.TTLSeconds > 86_400 {
			p.TTLSeconds = 1800 // 30 min default
		}
		if deps.logLevelSetter != nil {
			deps.logLevelSetter(p.Level)
		}
		go func(after time.Duration) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(after):
				if deps.logLevelSetter != nil {
					deps.logLevelSetter("info")
				}
				slog.Info("agent log level auto-reverted to info")
			}
		}(time.Duration(p.TTLSeconds) * time.Second)
		return agentctrl.Result{Output: fmt.Sprintf("log level → %s for %ds", p.Level, p.TTLSeconds)}, nil
	}
}

// handleDrain toggles the proxy's drain bool. Router checks this flag
// per-request and 503's new traffic when set. Existing connections
// continue serving.
func handleDrain(deps agentCommandDeps) agentctrl.Handler {
	return func(_ context.Context, cmd agentctrl.Command) (agentctrl.Result, error) {
		var p struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		if deps.drainState != nil {
			deps.drainState.Store(p.Enabled)
		}
		if p.Enabled {
			return agentctrl.Result{Output: "drain enabled — new traffic rejected"}, nil
		}
		return agentctrl.Result{Output: "drain disabled — accepting traffic"}, nil
	}
}

// handleAgentRestart returns success immediately, then exits the
// process in a goroutine so Docker's restart policy bounces us. The
// result POST has a small window to land before exit; if it doesn't,
// the server sweeper will mark the row expired and the next admin
// page load still shows the new image digest, so observability
// degrades gracefully.
func handleAgentRestart() agentctrl.Handler {
	return func(_ context.Context, _ agentctrl.Command) (agentctrl.Result, error) {
		go func() {
			time.Sleep(500 * time.Millisecond) // give result POST a chance
			slog.Warn("agent restart requested by command — exiting")
			os.Exit(0)
		}()
		return agentctrl.Result{Output: "restart scheduled"}, nil
	}
}

// handleSelfUpgrade docker-pulls the target image and exits — Docker's
// restart policy with the new image tag (set in compose via VERSION
// env) brings us back. Operators trigger this via the central's
// system-upgrade flow; the agent-side equivalent uses a docker:cli
// helper container, same as muvon-deployer.
func handleSelfUpgrade(deps agentCommandDeps) agentctrl.Handler {
	return func(ctx context.Context, cmd agentctrl.Command) (agentctrl.Result, error) {
		var p struct {
			Image string `json:"image"` // optional override
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		if deps.dockerCli == nil {
			return agentctrl.Result{}, fmt.Errorf("docker socket unavailable")
		}
		if p.Image == "" {
			p.Image = "ghcr.io/saidmuratozdemir/muvon/agent:latest"
		}
		if err := deps.dockerCli.ImagePull(ctx, p.Image); err != nil {
			return agentctrl.Result{}, fmt.Errorf("image pull: %w", err)
		}
		go func() {
			time.Sleep(500 * time.Millisecond)
			slog.Warn("agent self-upgrade — exiting for image swap", "image", p.Image)
			os.Exit(0)
		}()
		return agentctrl.Result{Output: "pulled " + p.Image + " — restarting"}, nil
	}
}

// handleRevoke acknowledges, then exits with code 1. Restart policy
// SHOULD be "no" on a revoked agent (the operator removed it from
// the central agents table; central rejects the agent's next API
// call with 401, but local restart loop would still try to reconnect
// indefinitely). We exit; the operator's removal step in the central
// admin UI is the real revocation — this is just the agent's
// cooperative response.
func handleRevoke() agentctrl.Handler {
	return func(_ context.Context, _ agentctrl.Command) (agentctrl.Result, error) {
		go func() {
			time.Sleep(500 * time.Millisecond)
			slog.Warn("agent revoke acknowledged — exiting")
			os.Exit(1)
		}()
		return agentctrl.Result{Output: "revoke acknowledged"}, nil
	}
}

// handleCertRenew tells the TLS manager to drop its cache for the
// domain. autocert.Manager will fetch a fresh cert on the next TLS
// handshake. If the operator wants the cert proactively, they can
// follow up with a no-op HTTPS request from outside.
func handleCertRenew(deps agentCommandDeps) agentctrl.Handler {
	return func(_ context.Context, cmd agentctrl.Command) (agentctrl.Result, error) {
		var p struct {
			Domain string `json:"domain"`
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		if p.Domain == "" {
			return agentctrl.Result{}, fmt.Errorf("domain required")
		}
		if deps.tlsMgr != nil {
			deps.tlsMgr.InvalidateCache(p.Domain)
		}
		return agentctrl.Result{Output: "cert cache invalidated for " + p.Domain + " (next handshake will renew)"}, nil
	}
}

// handleContainerRestart restarts a managed container by ID. Used
// for edge-deployed components where the agent owns the Docker socket.
func handleContainerRestart(deps agentCommandDeps) agentctrl.Handler {
	return func(ctx context.Context, cmd agentctrl.Command) (agentctrl.Result, error) {
		var p struct {
			ContainerID string `json:"container_id"`
			Timeout     int    `json:"timeout"`
		}
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return agentctrl.Result{}, fmt.Errorf("invalid payload: %w", err)
		}
		if p.ContainerID == "" {
			return agentctrl.Result{}, fmt.Errorf("container_id required")
		}
		if deps.dockerCli == nil {
			return agentctrl.Result{}, fmt.Errorf("docker socket unavailable")
		}
		if p.Timeout <= 0 {
			p.Timeout = 10
		}
		if err := deps.dockerCli.ContainerRestart(ctx, p.ContainerID, p.Timeout); err != nil {
			return agentctrl.Result{}, fmt.Errorf("restart: %w", err)
		}
		return agentctrl.Result{Output: "container restarted: " + p.ContainerID}, nil
	}
}

// handleDeployAbort is a placeholder for v1: today the deployer state
// machine doesn't expose a cancel hook, so we just record the intent
// in the result. Future work: thread context cancellation through
// internal/deployer/service.go's processDeployment.
func handleDeployAbort(_ agentCommandDeps) agentctrl.Handler {
	return func(_ context.Context, cmd agentctrl.Command) (agentctrl.Result, error) {
		var p struct {
			DeploymentID string `json:"deployment_id"`
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		// TODO: implement once the deployer state machine accepts
		// per-deployment cancel signals. For now: signal the central
		// via a structured failure that the abort wasn't honoured.
		return agentctrl.Result{
			State:  agentctrl.StateFailed,
			Error:  "deploy abort not yet implemented in agent — pause the component instead",
			Output: "deployment_id=" + p.DeploymentID,
		}, nil
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────

// unusedExec keeps os/exec linkable for future handlers (e.g. running
// a diagnostic curl). Lints don't flag this when at least one handler
// references it directly; today none do. Kept here so the import
// doesn't churn when we add the first one.
var _ = exec.Command
