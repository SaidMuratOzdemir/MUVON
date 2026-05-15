package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
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

// handleSelfUpgrade swaps the agent image by spawning a docker:cli helper
// container that runs `docker compose pull && up -d --no-deps --wait
// agent` against the host's docker socket — the same pattern central's
// system-upgrade flow uses to recreate muvon-deployer.
//
// The previous implementation just docker-pulled the new image and exited,
// relying on the daemon's restart policy. That was broken by design:
// Docker's restart policy reuses the container's existing image ID and
// ignores newer tags pulled into the cache. The fix has to actually
// `compose up` to recreate the container with the freshly pulled image.
//
// MUVON_HOST_AGENT_DIR is the host path where install-agent.sh keeps
// docker-compose.agent.yml; the helper container bind-mounts that path
// so it can run compose against the same project the agent itself was
// installed from. Default is /opt/muvon-agent (the install-agent.sh
// default INSTALL_DIR).
func handleSelfUpgrade(deps agentCommandDeps) agentctrl.Handler {
	return func(ctx context.Context, cmd agentctrl.Command) (agentctrl.Result, error) {
		var p struct {
			Image string `json:"image"` // optional override, e.g. ".../agent:0.1.19"
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		if deps.dockerCli == nil {
			return agentctrl.Result{}, fmt.Errorf("docker socket unavailable")
		}

		hostDir := os.Getenv("MUVON_HOST_AGENT_DIR")
		if hostDir == "" {
			hostDir = "/opt/muvon-agent"
		}

		// If the operator pinned a specific tag, rewrite the compose file
		// before pulling so the recreate lands on it. Empty / "latest"
		// leaves compose untouched.
		targetTag := ""
		if i := strings.LastIndex(p.Image, ":"); i > 0 && i < len(p.Image)-1 {
			targetTag = p.Image[i+1:]
		}
		sedLine := ""
		if targetTag != "" && targetTag != "latest" {
			sedLine = fmt.Sprintf(`sed -i -E "s|(ghcr\\.io/[^:]+/agent):[^[:space:]\"]*|\\1:%s|g" docker-compose.agent.yml`, targetTag)
		}

		const helperHostMnt = "/host/agent"
		script := strings.Join([]string{
			"set -ex",
			"cd " + helperHostMnt,
			sedLine,
			"docker compose -f docker-compose.agent.yml pull agent",
			"docker compose -f docker-compose.agent.yml up -d --no-deps --wait --wait-timeout 90 agent",
		}, "\n")

		// helperCtx is rooted in Background so the helper survives this
		// agent process exiting — compose-up will kill us partway through.
		helperCtx, helperCancel := context.WithTimeout(context.Background(), 10*time.Minute)

		if err := deps.dockerCli.ImagePull(helperCtx, "docker:27-cli"); err != nil {
			helperCancel()
			return agentctrl.Result{}, fmt.Errorf("pull helper image: %w", err)
		}

		name := "muvon-agent-upgrader-" + time.Now().UTC().Format("20060102-150405")
		id, logs, wait, err := deps.dockerCli.RunHelperContainer(helperCtx, deployer.HelperContainerOpts{
			Image: "docker:27-cli",
			Name:  name,
			Cmd:   []string{"sh", "-c", script},
			Binds: []string{
				"/var/run/docker.sock:/var/run/docker.sock",
				hostDir + ":" + helperHostMnt,
			},
			Labels:     map[string]string{"muvon.role": "agent-upgrader"},
			AutoRemove: false,
			Init:       true,
		})
		if err != nil {
			helperCancel()
			return agentctrl.Result{}, fmt.Errorf("spawn helper: %w", err)
		}

		// Drain logs + wait in a detached goroutine. The agent process
		// itself will be killed as soon as compose recreates the
		// container; that's fine — the helper finishes the job from
		// Background context, and the freshly spawned agent picks up
		// where we left off.
		go func() {
			defer helperCancel()
			defer logs.Close()
			dem := deployer.NewLogDemuxer(logs, deployer.DemuxOptions{MaxLine: 32 * 1024})
			for chunk := range dem.Out() {
				line := strings.TrimRight(chunk.Line, "\r\n")
				if line != "" {
					slog.Info("agent-upgrader", "line", line)
				}
			}
			exit, werr := wait()
			slog.Info("agent-upgrader done", "name", name, "exit", exit, "error", werr, "container", id)
		}()

		out := "spawned " + name + " — agent will be recreated"
		if targetTag != "" && targetTag != "latest" {
			out += " (target tag: " + targetTag + ")"
		}
		return agentctrl.Result{Output: out}, nil
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
