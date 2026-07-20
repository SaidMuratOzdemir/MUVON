package deployer

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"muvon/internal/db"
	"muvon/internal/secret"
)

type Service struct {
	state        State
	docker       *DockerClient
	pollInterval time.Duration
	healthClient *http.Client
	// lastStaleReset throttles the periodic crash-recovery sweep in tick.
	// Only ever read/written from the single tick goroutine — no lock needed.
	lastStaleReset time.Time
	// secretBox decrypts the "enc:"-prefixed values in component env maps
	// before they reach the container. Operates as passthrough when no
	// MUVON_ENCRYPTION_KEY was configured (HasKey() == false).
	secretBox *secret.Box
	// onTick is called once per loop iteration. Optional — the binary
	// uses this to keep the gRPC Health response fresh ("deployer is up
	// but stuck" is otherwise invisible).
	onTick func()
	// jobSem bounds how many scheduled job runs execute concurrently.
	// Scheduled jobs run in background goroutines (a job may legitimately
	// run for up to its timeout_seconds, default 1h) so they never block the
	// deployment/drain loop. Buffered to maxConcurrentJobs.
	jobSem chan struct{}
	// inflightOneOff holds the container IDs of one-off runs (migration +
	// scheduled job) currently managed by a live runOneOff call. The orphan
	// reconciler must skip these: a scheduled job runs in a background
	// goroutine, so without this guard a subsequent tick's
	// reconcileOrphanContainers would see its still-running container (which
	// is muvon.managed=true but not a deploy_instance) as an orphan and
	// SIGKILL it (exit 137). After a crash the set starts empty, so genuine
	// leftover one-off carcasses are still reaped.
	inflightOneOff sync.Map // map[containerID]struct{}
}

// maxConcurrentJobs caps simultaneous scheduled-job containers per deployer
// host. Keeps a burst of due jobs from exhausting host resources while
// still letting independent jobs overlap.
const maxConcurrentJobs = 4

// SetOnTick registers a callback fired once per tick. Safe to call once
// at startup; the callback fires inline so it should be cheap.
func (s *Service) SetOnTick(fn func()) { s.onTick = fn }

// NewService wires the deployer lifecycle to a State backend. The central
// deployer passes NewDBState(*db.DB, "") — direct PostgreSQL access. The
// embedded edge deployer in cmd/agent passes an HTTP-backed state that
// talks to the central admin server.
func NewService(state State, docker *DockerClient, secretBox *secret.Box, pollInterval time.Duration) *Service {
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	if secretBox == nil {
		secretBox = secret.NewBox("")
	}
	return &Service{
		state:        state,
		docker:       docker,
		pollInterval: pollInterval,
		healthClient: defaultHTTPClient(),
		secretBox:    secretBox,
		jobSem:       make(chan struct{}, maxConcurrentJobs),
	}
}

func (s *Service) Run(ctx context.Context) error {
	// Crash recovery. Also re-run periodically from tick (not just here): a
	// fast crash+supervisor-restart leaves a stuck row's updated_at too fresh
	// for the age threshold to catch at boot, which would wedge that
	// deployment/job forever. A periodic sweep bounds recovery to the
	// threshold window instead. Safe against live work: tick is single-
	// threaded and blocks in processDeployment while a deployment is in
	// flight, and the job threshold exceeds job timeout_seconds.
	s.resetStale(ctx)

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		if err := s.tick(ctx); err != nil {
			slog.Error("deployer tick failed", "error", err)
		}
		if s.onTick != nil {
			s.onTick()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// staleResetInterval throttles the periodic crash-recovery sweep so it does
// not issue its two UPDATEs on every 5s tick.
const staleResetInterval = time.Minute

// resetStale flips deployments/job-runs stuck in "running" past their age
// threshold back to pending so a crashed process's work is retried. Age
// thresholds distinguish a truly-dead process from active work.
func (s *Service) resetStale(ctx context.Context) {
	if n, err := s.state.ResetStaleRunning(ctx, 10*time.Minute); err != nil {
		slog.Warn("failed to reset stale running deployments", "error", err)
	} else if n > 0 {
		slog.Info("reset stale running deployments to pending", "count", n)
	}
	if n, err := s.state.ResetStaleJobRuns(ctx, 90*time.Minute); err != nil {
		slog.Warn("failed to reset stale job runs", "error", err)
	} else if n > 0 {
		slog.Info("reset stale job runs to pending", "count", n)
	}
	s.lastStaleReset = time.Now()
}

func (s *Service) tick(ctx context.Context) error {
	if time.Since(s.lastStaleReset) >= staleResetInterval {
		s.resetStale(ctx)
	}
	if err := s.cleanupDraining(ctx); err != nil {
		slog.Warn("drain cleanup failed", "error", err)
	}
	if err := s.reconcileOrphanContainers(ctx); err != nil {
		slog.Warn("orphan container reconcile failed", "error", err)
	}
	if n, err := s.state.CleanupStaleWarming(ctx); err != nil {
		slog.Warn("stale warming instance cleanup failed", "error", err)
	} else if n > 0 {
		slog.Info("cleaned up stale warming instances", "count", n)
	}

	// Claim scheduled job runs into bounded background goroutines so a long
	// job (up to timeout_seconds) never blocks deployments or drain. One
	// claim per tick when a worker slot is free; SKIP LOCKED in the claim
	// guarantees concurrent workers get distinct runs.
	s.dispatchJobRun(ctx)

	// State filters by owner: central deployer picks NULL agent_id rows;
	// the embedded edge deployer in cmd/agent picks only its own.
	deployment, ok, err := s.state.Claim(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := s.processDeployment(ctx, deployment.ID); err != nil {
		slog.Error("deployment failed", "deployment_id", deployment.ID, "error", err)
		_ = s.state.Fail(context.Background(), deployment.ID, err.Error())
		return err
	}
	return nil
}

func (s *Service) processDeployment(ctx context.Context, deploymentID string) error {
	plan, err := s.state.LoadPlan(ctx, deploymentID)
	if err != nil {
		return err
	}
	// Roll components out in deploy_order (ascending) so the migration-
	// carrying component (e.g. web) completes before workers start against a
	// possibly un-migrated schema. Stable: equal orders keep input sequence.
	sort.SliceStable(plan.Components, func(i, j int) bool {
		return plan.Components[i].Component.DeployOrder < plan.Components[j].Component.DeployOrder
	})
	_ = s.state.AddEvent(ctx, deploymentID, "started", "Deployment started", nil)

	candidates := make([]string, 0, len(plan.Components))
	createdContainers := make([]string, 0, len(plan.Components))
	for _, item := range plan.Components {
		component := item.Component
		imageRef := item.Release.ImageRef
		if imageRef == "" {
			return fmt.Errorf("component %s has no image_ref", component.Slug)
		}
		if err := s.state.AddEvent(ctx, deploymentID, "pull", "Pulling image", map[string]string{"component": component.Slug, "image": imageRef}); err != nil {
			return err
		}
		if err := s.docker.ImagePull(ctx, imageRef); err != nil {
			return fmt.Errorf("pull %s: %w", imageRef, err)
		}

		env, err := s.loadComponentEnv(ctx, component)
		if err != nil {
			return fmt.Errorf("load env for %s: %w", component.Slug, err)
		}
		// Bail out before anything is touched: no migration run, no old
		// container stopped for a deployment that cannot succeed.
		cmd := applyEdgeIPToArgs(component.Command, env[edgeIPVar])
		if err := checkEdgeIPResolved(env, cmd); err != nil {
			return fmt.Errorf("component %s: %w", component.Slug, err)
		}
		if err := s.ensureNetworks(ctx, component.Networks); err != nil {
			return fmt.Errorf("ensure networks for %s: %w", component.Slug, err)
		}
		if len(component.MigrationCommand) > 0 {
			if err := s.runMigration(ctx, deploymentID, plan, component, imageRef, env); err != nil {
				return err
			}
		}

		// Recreate strategy: stop the previous active container(s) for this
		// component BEFORE the candidate starts, so a singleton (e.g.
		// celery-beat) never runs two instances at once. Trades a brief gap
		// for correctness; blue-green (default) keeps the zero-downtime overlap.
		if component.DeployStrategy == "recreate" {
			if err := s.stopOldForRecreate(ctx, deploymentID, plan, component); err != nil {
				return fmt.Errorf("recreate stop-old %s: %w", component.Slug, err)
			}
		}

		mounts, err := buildDockerMounts(component.Mounts)
		if err != nil {
			return fmt.Errorf("invalid mounts for %s: %w", component.Slug, err)
		}
		containerName := containerName(plan.Project.Slug, component.Slug, plan.Release.ReleaseID)
		createReq := containerCreateRequest{
			Image: imageRef,
			Cmd:   cmd,
			Env:   envList(env),
			Labels: map[string]string{
				"muvon.project":    plan.Project.Slug,
				"muvon.component":  component.Slug,
				"muvon.release_id": plan.Release.ReleaseID,
				"muvon.managed":    "true",
			},
			HostConfig: hostConfig{
				NetworkMode: firstNetwork(component.Networks),
				RestartPolicy: restartPolicy{
					Name: "unless-stopped",
				},
				Mounts: mounts,
			},
			NetworkingConfig: networkConfig(component.Networks, component.Slug),
		}
		containerID, err := s.docker.ContainerCreate(ctx, containerName, createReq)
		if err != nil {
			return fmt.Errorf("create candidate %s: %w", component.Slug, err)
		}
		createdContainers = append(createdContainers, containerID)
		if err := s.connectExtraNetworks(ctx, component.Networks, containerID, component.Slug); err != nil {
			return fmt.Errorf("connect networks for %s: %w", component.Slug, err)
		}
		if err := s.docker.ContainerStart(ctx, containerID); err != nil {
			return fmt.Errorf("start candidate %s: %w", component.Slug, err)
		}

		backendURL := fmt.Sprintf("http://%s:%d", containerName, component.InternalPort)
		instance, err := s.state.CreateInstance(ctx, component.ID, plan.Release.ID, containerID, containerName, backendURL)
		if err != nil {
			return err
		}
		if err := s.waitHealthyWithRestart(ctx, deploymentID, component, containerID, backendURL); err != nil {
			_ = s.state.MarkInstanceUnhealthy(context.Background(), instance.ID, err.Error())
			_ = s.docker.ContainerRemove(context.Background(), containerID, true)
			return err
		}
		candidates = append(candidates, instance.ID)
		_ = s.state.AddEvent(ctx, deploymentID, "candidate_healthy", "Candidate is healthy", map[string]string{"component": component.Slug, "url": backendURL})
	}

	if err := s.state.Promote(ctx, deploymentID, candidates); err != nil {
		for _, containerID := range createdContainers {
			_ = s.docker.ContainerRemove(context.Background(), containerID, true)
		}
		return err
	}
	slog.Info("deployment promoted", "deployment_id", deploymentID)

	// Best-effort image pruning. Failure here MUST NOT fail the deployment
	// — the candidates are already promoted and serving traffic. Images
	// left behind are caught on the next successful promote.
	s.pruneImagesAfterPromote(context.Background(), plan)
	return nil
}

// pruneImagesAfterPromote drops image refs from the local Docker daemon
// that fall outside each component's keep_releases window and aren't
// still bound to a live instance. The query side handles the in-use
// exclusion; here we just iterate and call Docker. Docker's own refcount
// catches anything the SQL missed (returns 409 → ImageRemove swallows).
func (s *Service) pruneImagesAfterPromote(ctx context.Context, plan db.DeploymentPlan) {
	for _, item := range plan.Components {
		component := item.Component
		keep := component.KeepReleases
		if keep < 1 {
			keep = 3
		}
		refs, err := s.state.ListPrunableImageRefs(ctx, component.ID, keep)
		if err != nil {
			slog.Warn("image prune query failed", "component", component.Slug, "error", err)
			continue
		}
		for _, ref := range refs {
			if err := s.docker.ImageRemove(ctx, ref, false); err != nil {
				slog.Warn("image prune remove failed", "component", component.Slug, "image", ref, "error", err)
				continue
			}
			slog.Info("pruned image", "component", component.Slug, "image", ref)
		}
	}
}

func (s *Service) runMigration(ctx context.Context, deploymentID string, plan db.DeploymentPlan, component db.DeployComponent, imageRef string, env map[string]string) error {
	_ = s.state.AddEvent(ctx, deploymentID, "migration", "Running migration", map[string]any{"component": component.Slug, "command": component.MigrationCommand})
	name := containerName(plan.Project.Slug, component.Slug+"-migration", plan.Release.ReleaseID)
	labels := map[string]string{
		"muvon.project":    plan.Project.Slug,
		"muvon.component":  component.Slug,
		"muvon.release_id": plan.Release.ReleaseID,
		"muvon.managed":    "true",
		"muvon.job":        "migration",
	}
	exitCode, _, err := s.runOneOff(ctx, name, component.Slug+"-migration", component, imageRef, component.MigrationCommand, env, labels)
	if err != nil {
		return fmt.Errorf("migration %s: %w", component.Slug, err)
	}
	if exitCode != 0 {
		return fmt.Errorf("migration failed for %s with exit code %d", component.Slug, exitCode)
	}
	_ = s.state.AddEvent(ctx, deploymentID, "migration_succeeded", "Migration succeeded", map[string]string{"component": component.Slug})
	return nil
}

// runOneOff runs a single short-lived container to completion: create →
// (connect extra networks) → start → wait for exit → capture log tail →
// remove. Returns the exit code and captured output tail. err covers only
// infrastructure failures (bad mounts, create/start, or a wait that errored
// — e.g. ctx timeout), never a non-zero process exit. The image must
// already be present locally; callers that can't guarantee that pull first.
func (s *Service) runOneOff(ctx context.Context, name, alias string, component db.DeployComponent, imageRef string, cmd []string, env map[string]string, labels map[string]string) (int, string, error) {
	mounts, err := buildDockerMounts(component.Mounts)
	if err != nil {
		return 0, "", fmt.Errorf("invalid mounts for %s: %w", component.Slug, err)
	}
	req := containerCreateRequest{
		Image:            imageRef,
		Cmd:              cmd,
		Env:              envList(env),
		Labels:           labels,
		HostConfig:       hostConfig{NetworkMode: firstNetwork(component.Networks), Mounts: mounts},
		NetworkingConfig: networkConfig(component.Networks, alias),
	}
	containerID, err := s.docker.ContainerCreate(ctx, name, req)
	if err != nil {
		return 0, "", fmt.Errorf("create container: %w", err)
	}
	// Mark this container in-flight before it starts so the orphan
	// reconciler (which runs on the main tick loop while a scheduled job
	// executes in a background goroutine) never reaps it as a stray
	// muvon.managed container. Cleared once we're done with it.
	s.inflightOneOff.Store(containerID, struct{}{})
	defer s.inflightOneOff.Delete(containerID)
	defer s.docker.ContainerRemove(context.Background(), containerID, true)
	if err := s.connectExtraNetworks(ctx, component.Networks, containerID, alias); err != nil {
		return 0, "", fmt.Errorf("connect networks: %w", err)
	}
	if err := s.docker.ContainerStart(ctx, containerID); err != nil {
		return 0, "", fmt.Errorf("start container: %w", err)
	}
	status, werr := s.docker.ContainerWait(ctx, containerID)
	// Capture logs with a detached context — the run ctx may already be
	// cancelled (timeout) but the carcass still holds its log tail.
	out := s.captureContainerOutput(context.Background(), containerID)
	if werr != nil {
		return 0, out, fmt.Errorf("wait container: %w", werr)
	}
	return int(status), out, nil
}

// captureContainerOutput best-effort reads the tail of a container's
// combined stdout+stderr and returns it capped to ~16 KiB. Gives a
// scheduled-job run a readable result without depending on the async
// container-log pipeline (which may miss a short-lived one-off).
func (s *Service) captureContainerOutput(ctx context.Context, containerID string) string {
	rc, err := s.docker.ContainerLogs(ctx, containerID, ContainerLogsOptions{Stdout: true, Stderr: true, Tail: "400"})
	if err != nil {
		return ""
	}
	defer rc.Close()
	dem := NewLogDemuxer(rc, DemuxOptions{MaxLine: 1 << 16})
	var b strings.Builder
	for chunk := range dem.Out() {
		b.WriteString(chunk.Line)
		b.WriteByte('\n')
	}
	return truncateOutput(b.String())
}

func truncateOutput(s string) string {
	const max = 16 << 10
	if len(s) <= max {
		return s
	}
	return "...(truncated)\n" + s[len(s)-max:]
}

// dispatchJobRun claims at most one pending run per tick (when a worker
// slot is free) and runs it in a background goroutine. Skips silently when
// all slots are busy — the next tick retries. processJobRun records each
// run's own terminal state; the fallback Finish here covers a setup error
// or a panic before that happens.
func (s *Service) dispatchJobRun(ctx context.Context) {
	select {
	case s.jobSem <- struct{}{}:
	default:
		return // all job workers busy
	}
	run, ok, err := s.state.ClaimJobRun(ctx)
	if err != nil {
		<-s.jobSem
		slog.Warn("job run claim failed", "error", err)
		return
	}
	if !ok {
		<-s.jobSem
		return // queue empty
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("scheduled job run panicked", "run_id", run.ID, "panic", r)
				ec := -1
				_ = s.state.FinishJobRun(context.Background(), run.ID, "failed", &ec, fmt.Sprintf("panic: %v", r), "")
			}
			<-s.jobSem
		}()
		if err := s.processJobRun(ctx, run); err != nil {
			slog.Error("scheduled job run failed", "run_id", run.ID, "error", err)
			ec := -1
			_ = s.state.FinishJobRun(context.Background(), run.ID, "failed", &ec, err.Error(), "")
		}
	}()
}

// processJobRun executes one claimed scheduled job run end-to-end and
// records its terminal state via FinishJobRun. A non-zero process exit is
// recorded as 'failed' but is NOT returned as a Go error (it's expected job
// output). A returned error means the run could not be set up or finalised;
// the tick loop turns that into a 'failed' run as a backstop.
func (s *Service) processJobRun(ctx context.Context, run db.ScheduledJobRun) error {
	plan, err := s.state.LoadJob(ctx, run.ID)
	if err != nil {
		return fmt.Errorf("load job: %w", err)
	}
	job := plan.Job
	component := plan.Component

	env, err := s.loadComponentEnv(ctx, component)
	if err != nil {
		return fmt.Errorf("load env: %w", err)
	}

	timeout := time.Duration(job.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Hour
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// FinishJobRun must outlive a cancelled runCtx, so use a detached ctx.
	fin := context.Background()

	if job.ExecMode == "exec" {
		if plan.ActiveContainerID == "" {
			return s.state.FinishJobRun(fin, run.ID, "failed", nil, "no active container for component", "")
		}
		output, code, execErr := s.docker.ContainerExecCaptureCode(runCtx, plan.ActiveContainerID, job.Command)
		if execErr != nil {
			return s.state.FinishJobRun(fin, run.ID, "failed", nil, execErr.Error(), truncateOutput(string(output)))
		}
		status := "succeeded"
		if code != 0 {
			status = "failed"
		}
		return s.state.FinishJobRun(fin, run.ID, status, &code, "", truncateOutput(string(output)))
	}

	// Default "run" mode — fresh one-off container from the component image.
	if plan.ImageRef == "" {
		return s.state.FinishJobRun(fin, run.ID, "failed", nil, "component has no succeeded release image", "")
	}
	if err := s.docker.ImagePull(runCtx, plan.ImageRef); err != nil {
		return s.state.FinishJobRun(fin, run.ID, "failed", nil, fmt.Sprintf("image pull: %v", err), "")
	}
	name := containerName(job.ProjectSlug, component.Slug+"-job-"+job.Slug, fmt.Sprintf("%d", run.ID))
	labels := map[string]string{
		"muvon.project":       job.ProjectSlug,
		"muvon.component":     component.Slug,
		"muvon.managed":       "true",
		"muvon.job":           "scheduled",
		"muvon.scheduled_job": job.Slug,
	}
	exitCode, output, err := s.runOneOff(runCtx, name, component.Slug+"-job", component, plan.ImageRef, job.Command, env, labels)
	if err != nil {
		return s.state.FinishJobRun(fin, run.ID, "failed", nil, err.Error(), truncateOutput(output))
	}
	status := "succeeded"
	if exitCode != 0 {
		status = "failed"
	}
	return s.state.FinishJobRun(fin, run.ID, status, &exitCode, "", truncateOutput(output))
}

func (s *Service) waitHealthyWithRestart(ctx context.Context, deploymentID string, component db.DeployComponent, containerID, backendURL string) error {
	attempts := component.RestartRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			_ = s.state.AddEvent(ctx, deploymentID, "restart", "Restarting unhealthy candidate", map[string]any{"component": component.Slug, "attempt": attempt - 1})
			if err := s.docker.ContainerRestart(ctx, containerID, 10); err != nil {
				return fmt.Errorf("restart candidate %s: %w", component.Slug, err)
			}
		}
		if err := s.waitHealthy(ctx, component, containerID, backendURL); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("candidate %s failed health after %d attempt(s): %w", component.Slug, attempts, lastErr)
}

// waitHealthy dispatches the candidate health check by HealthMode. The
// default (and "http") preserves the original HTTP probe verbatim, so
// existing components are unaffected.
func (s *Service) waitHealthy(ctx context.Context, component db.DeployComponent, containerID, backendURL string) error {
	switch component.HealthMode {
	case "exec":
		return s.waitHealthyExec(ctx, component, containerID)
	case "running":
		return s.waitHealthyRunning(ctx, component, containerID)
	default: // "http" or "" — unchanged behaviour
		return s.waitHealthyHTTP(ctx, component, backendURL)
	}
}

func (s *Service) waitHealthyHTTP(ctx context.Context, component db.DeployComponent, backendURL string) error {
	healthURL := strings.TrimRight(backendURL, "/") + normalizePath(component.HealthPath)
	timeout := time.Duration(component.DrainTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	// Give the process a moment to bind its port before probing.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(3 * time.Second):
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return err
		}
		// Same reason as the runtime health probe: the container-name Host is not
		// in the app's ALLOWED_HOSTS, so send an accepted one.
		req.Host = "localhost"
		resp, err := s.healthClient.Do(req)
		if err == nil {
			ioErr := resp.Body.Close()
			if resp.StatusCode == component.HealthExpectedStatus {
				return nil
			}
			lastErr = fmt.Errorf("health returned HTTP %d", resp.StatusCode)
			if ioErr != nil {
				lastErr = ioErr
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("health timed out")
	}
	return lastErr
}

// waitHealthyExec runs HealthCommand inside the candidate until it exits 0 or
// the timeout elapses. For workers that can self-report (e.g. `celery -A
// config inspect ping`) — proves the worker is functional, not just "up".
func (s *Service) waitHealthyExec(ctx context.Context, component db.DeployComponent, containerID string) error {
	if len(component.HealthCommand) == 0 {
		return fmt.Errorf("health_mode=exec requires health_command")
	}
	timeout := time.Duration(component.DrainTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(3 * time.Second):
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := s.docker.ContainerExecCapture(ctx, containerID, component.HealthCommand); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("exec health timed out")
	}
	return lastErr
}

// waitHealthyRunning treats the candidate as healthy once it has stayed in the
// "running" state for a short grace window without exiting or its restart
// count climbing (crash-loop). For workers with no probe surface (e.g.
// celery-beat). Weaker than exec — prefer exec where the worker can answer.
func (s *Service) waitHealthyRunning(ctx context.Context, component db.DeployComponent, containerID string) error {
	const graceWindow = 8 * time.Second
	timeout := time.Duration(component.DrainTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if timeout < graceWindow+2*time.Second {
		timeout = graceWindow + 2*time.Second
	}
	deadline := time.Now().Add(timeout)
	// baseRestart is captured on the FIRST successful inspect, whatever the
	// state — so a container that crash-restarts before we ever see it
	// "running" is still measured against its true starting count. Any
	// increase thereafter is a crash-loop (restart policy is unless-stopped),
	// which fails immediately rather than risking a "running" snapshot
	// between two restarts slipping through the grace window.
	baseRestart := -1
	var runningSince time.Time
	var lastErr error
	for time.Now().Before(deadline) {
		st, err := s.docker.ContainerInspect(ctx, containerID)
		if err != nil {
			lastErr = err
		} else {
			if baseRestart < 0 {
				baseRestart = st.RestartCount
			}
			if st.RestartCount > baseRestart {
				return fmt.Errorf("container crash-looping (restarts=%d)", st.RestartCount)
			}
			switch st.State {
			case "exited", "dead":
				return fmt.Errorf("container exited (code %d) before becoming healthy", st.ExitCode)
			case "running":
				if runningSince.IsZero() {
					runningSince = time.Now()
				}
				if time.Since(runningSince) >= graceWindow {
					return nil
				}
			default: // created, restarting, paused — not yet stable; restart the clock
				runningSince = time.Time{}
				lastErr = fmt.Errorf("container state %q", st.State)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("container did not stay running for %s", graceWindow)
	}
	return lastErr
}

// stopOldForRecreate stops the previous container(s) of a recreate component
// before its candidate starts, so a singleton never overlaps. It first flips the
// component's 'active' instances to 'draining' in the DB and stops their
// containers: doing the state transition up front means a subsequently-failed
// candidate never leaves a stopped container behind a still-'active' row (which
// the proxy would keep routing to). cleanupDraining then removes the drained
// containers on both the success and failure paths. A label sweep afterward
// catches any other still-running container of a different release
// (warming/draining leftovers) so the no-overlap guarantee holds. A stop error
// fails the deploy: better to abort than start a second singleton on top of a
// still-running old one.
func (s *Service) stopOldForRecreate(ctx context.Context, deploymentID string, plan db.DeploymentPlan, component db.DeployComponent) error {
	drained, err := s.state.DrainActiveForRecreate(ctx, component.ID)
	if err != nil {
		return fmt.Errorf("drain active for recreate %s: %w", component.Slug, err)
	}
	for _, inst := range drained {
		if inst.ContainerID == "" {
			continue
		}
		_ = s.state.AddEvent(ctx, deploymentID, "recreate_stop", "Stopping previous instance before recreate", map[string]string{"component": component.Slug, "container": inst.ContainerID})
		if err := s.docker.ContainerStop(ctx, inst.ContainerID, 10); err != nil {
			return fmt.Errorf("stop old container %s: %w", short(inst.ContainerID), err)
		}
	}

	containers, err := s.docker.ContainerListAll(ctx, true)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if c.Labels["muvon.project"] != plan.Project.Slug ||
			c.Labels["muvon.component"] != component.Slug ||
			c.Labels["muvon.release_id"] == plan.Release.ReleaseID {
			continue
		}
		if c.State == "exited" || c.State == "dead" {
			continue // already down — cleanup/reconcile will remove it
		}
		if err := s.docker.ContainerStop(ctx, c.ID, 10); err != nil {
			return fmt.Errorf("stop old container %s: %w", short(c.ID), err)
		}
	}
	return nil
}

func (s *Service) cleanupDraining(ctx context.Context) error {
	instances, err := s.state.ListDrainable(ctx)
	if err != nil {
		return err
	}
	for _, inst := range instances {
		if inst.ContainerID == "" {
			// No container to remove (instance never came up cleanly).
			// Mark stopped so it leaves the drainable view.
			if err := s.state.MarkInstanceStopped(ctx, inst.ID); err != nil {
				return err
			}
			continue
		}
		// Stop is best-effort: if the daemon refuses or times out we
		// still try a forced remove. Logging — not error returns — is
		// what we want so the loop keeps making progress for the rest
		// of the queue.
		if err := s.docker.ContainerStop(ctx, inst.ContainerID, 10); err != nil {
			slog.Warn("drain stop failed; will force remove", "instance", inst.ID, "container", short(inst.ContainerID), "error", err)
		}
		// force=true: without force a stuck process leaves the container
		// behind permanently — the next tick would see state='stopped'
		// in DB (set by the optimistic flow below) and never retry.
		if err := s.docker.ContainerRemove(ctx, inst.ContainerID, true); err != nil {
			slog.Warn("drain remove failed; instance stays draining for retry", "instance", inst.ID, "container", short(inst.ContainerID), "error", err)
			// Skip MarkInstanceStopped so this row stays drainable and
			// we try again next tick.
			continue
		}
		if err := s.state.MarkInstanceStopped(ctx, inst.ID); err != nil {
			return err
		}
	}
	return nil
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// reconcileOrphanContainers removes Docker containers that carry the
// muvon.managed=true label but are no longer tracked as live (warming /
// active / draining) in the database.  This happens when the deployer
// crashes mid-deployment and leaves containers behind that were never
// properly registered or whose cleanup code never ran.
func (s *Service) reconcileOrphanContainers(ctx context.Context) error {
	liveIDs, err := s.state.ListLiveManagedContainerIDs(ctx)
	if err != nil {
		return err
	}
	// all=true so exited containers (failed candidates, migration leftovers)
	// are visible too. The running-only list misses every container whose
	// process died between Promote and our cleanup pass.
	containers, err := s.docker.ContainerListAll(ctx, true)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if _, alive := liveIDs[c.ID]; alive {
			continue
		}
		// One-off runs (migration + scheduled job) in flight on this deployer
		// own their own lifecycle via runOneOff. They carry muvon.managed=true
		// but are not deploy_instances, so without this guard a scheduled job
		// running in a background goroutine would be reaped mid-run (exit 137).
		if _, busy := s.inflightOneOff.Load(c.ID); busy {
			continue
		}
		// Helper containers (system upgrader, future short-lived jobs) own
		// their own lifecycle and must never be touched by orphan cleanup.
		if c.Labels["muvon.helper"] == "true" {
			continue
		}
		project := c.Labels["muvon.project"]
		component := c.Labels["muvon.component"]
		release := c.Labels["muvon.release_id"]
		slog.Info("removing orphan container", "id", short(c.ID), "state", c.State, "project", project, "component", component, "release", release)
		_ = s.docker.ContainerStop(ctx, c.ID, 10)
		// force=true catches stuck-running orphans the same way cleanupDraining does.
		if err := s.docker.ContainerRemove(ctx, c.ID, true); err != nil {
			slog.Warn("failed to remove orphan container", "id", short(c.ID), "error", err)
		}
	}
	return nil
}

func (s *Service) ensureNetworks(ctx context.Context, networks []string) error {
	for _, network := range networks {
		if err := s.docker.EnsureNetwork(ctx, network); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) connectExtraNetworks(ctx context.Context, networks []string, containerID, alias string) error {
	if len(networks) <= 1 {
		return nil
	}
	for _, network := range networks[1:] {
		if err := s.docker.NetworkConnect(ctx, network, containerID, alias); err != nil {
			return err
		}
	}
	return nil
}

// The edge proxy's address on a component's network is assigned by Docker at
// attach time and reused when containers churn, so it must never be written into
// configuration by hand. The deployer resolves it live and exposes it two ways:
// as MUVON_EDGE_IP in the container env, and by substituting the literal
// ${MUVON_EDGE_IP} token in any component env value. That lets an operator write
// FORWARDED_ALLOW_IPS=${MUVON_EDGE_IP} (or the equivalent for their server) once
// and have it stay correct across restarts, redeploys and reinstalls.
//
// Substitution is a literal token replace, not shell-style expansion, so secret
// values that happen to contain "$" are never mangled.
const (
	edgeIPVar         = "MUVON_EDGE_IP"
	edgeIPPlaceholder = "${MUVON_EDGE_IP}"
	edgeRoleLabel     = "muvon.role=edge"
)

// edgeIPFor resolves the address the edge proxy reaches this component from.
// On an edge host the deployer runs inside the agent, which is itself the proxy,
// so its own container answers. On central the proxy is a separate container,
// located by the muvon.role=edge label. Returns "" when it cannot be determined;
// callers then leave the placeholder untouched so a miss stays visible instead of
// silently collapsing into an empty allow-list.
//
// Deliberately uncached: a stale value here is exactly the failure this exists to
// prevent, and it is read at most once per component per deployment.
func (s *Service) edgeIPFor(ctx context.Context, networks []string) string {
	if len(networks) == 0 {
		return ""
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		if self, err := s.docker.ContainerInspect(ctx, host); err == nil {
			if ip := pickNetworkIP(self.Networks, networks); ip != "" {
				return ip
			}
		}
	}
	containers, err := s.docker.ContainerList(ctx, edgeRoleLabel)
	if err != nil {
		return ""
	}
	for _, c := range containers {
		info, err := s.docker.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}
		if ip := pickNetworkIP(info.Networks, networks); ip != "" {
			return ip
		}
	}
	return ""
}

// pickNetworkIP returns the proxy's address on the first of the component's
// networks it is actually attached to. A component is normally on more than one:
// an isolated database network plus the shared routing network. The proxy joins
// only the routing one, and that is not necessarily listed first, so every
// network has to be tried rather than just networks[0].
func pickNetworkIP(have map[string]string, want []string) string {
	for _, n := range want {
		if ip := have[n]; ip != "" {
			return ip
		}
	}
	return ""
}

// errUnresolvedEdgeIP reports a component that asks for ${MUVON_EDGE_IP} when the
// address could not be determined. The deployment is failed before the container
// is created: passing the literal token through would hand the app an invalid
// address and crash-loop it at startup, which is a far worse failure than a
// deployment that stops with a clear reason while the previous instance keeps
// serving.
func errUnresolvedEdgeIP(where string) error {
	return fmt.Errorf("%s in %s could not be resolved: the edge proxy is not attached to any of this component's networks", edgeIPPlaceholder, where)
}

func checkEdgeIPResolved(env map[string]string, cmd []string) error {
	for k, v := range env {
		if strings.Contains(v, edgeIPPlaceholder) {
			return errUnresolvedEdgeIP("env " + k)
		}
	}
	for _, a := range cmd {
		if strings.Contains(a, edgeIPPlaceholder) {
			return errUnresolvedEdgeIP("command")
		}
	}
	return nil
}

// applyEdgeIP publishes the resolved edge address as MUVON_EDGE_IP and resolves
// ${MUVON_EDGE_IP} references in the remaining values. No-op when ip is empty, so
// an unresolved placeholder stays visible instead of turning into an empty
// allow-list that silently disables proxy trust.
// applyEdgeIPToArgs resolves ${MUVON_EDGE_IP} inside a container command. App
// servers often carry the trusted-proxy address as a command-line flag
// (gunicorn's --forwarded-allow-ips), and there it overrides the environment
// variable, so the token has to work in both places or the fix is incomplete.
func applyEdgeIPToArgs(args []string, ip string) []string {
	if ip == "" || len(args) == 0 {
		return args
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.ReplaceAll(a, edgeIPPlaceholder, ip)
	}
	return out
}

func applyEdgeIP(env map[string]string, ip string) {
	if ip == "" {
		return
	}
	env[edgeIPVar] = ip
	for k, v := range env {
		if k != edgeIPVar && strings.Contains(v, edgeIPPlaceholder) {
			env[k] = strings.ReplaceAll(v, edgeIPPlaceholder, ip)
		}
	}
}

func (s *Service) loadComponentEnv(ctx context.Context, component db.DeployComponent) (map[string]string, error) {
	env := map[string]string{}
	if component.EnvFilePath != "" {
		fileEnv, err := parseEnvFile(component.EnvFilePath)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for k, v := range fileEnv {
			env[k] = v
		}
	}
	for k, v := range component.Env {
		// Secret-marked values land here as "enc:"-prefixed ciphertext.
		// Decrypt before handing the env list to Docker; if the key was
		// never marked secret, the value passes through unchanged.
		if secret.IsEncrypted(v) {
			plain, err := s.secretBox.Decrypt(v)
			if err != nil {
				return nil, fmt.Errorf("decrypt env %s for component %s: %w", k, component.Slug, err)
			}
			env[k] = plain
		} else {
			env[k] = v
		}
	}

	applyEdgeIP(env, s.edgeIPFor(ctx, component.Networks))
	return env, nil
}

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return out, scanner.Err()
}

func envList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}

func firstNetwork(networks []string) string {
	for _, network := range networks {
		if network != "" {
			return network
		}
	}
	return "muvon-edge"
}

func networkConfig(networks []string, alias string) networkingConfig {
	first := firstNetwork(networks)
	ep := endpointSettings{}
	if alias != "" {
		ep.Aliases = []string{alias}
	}
	return networkingConfig{EndpointsConfig: map[string]endpointSettings{first: ep}}
}

func containerName(project, component, releaseID string) string {
	shortRelease := sanitizeName(releaseID)
	if len(shortRelease) > 12 {
		shortRelease = shortRelease[:12]
	}
	return sanitizeName("muvon-" + project + "-" + component + "-" + shortRelease + "-" + time.Now().Format("20060102150405"))
}

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func normalizePath(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

// buildDockerMounts converts the persisted db.Mount specs into the
// Docker Engine API representation used in HostConfig.Mounts. It
// validates each entry up front so a bad mount fails the deployment
// before any container is created. Returns an empty (nil) slice when
// the component has no mounts so we don't ship an empty Mounts array
// to Docker.
func buildDockerMounts(mounts []db.Mount) ([]dockerMount, error) {
	if len(mounts) == 0 {
		return nil, nil
	}
	out := make([]dockerMount, 0, len(mounts))
	for i, m := range mounts {
		mountType := strings.ToLower(strings.TrimSpace(m.Type))
		target := strings.TrimSpace(m.Target)
		source := strings.TrimSpace(m.Source)
		if target == "" {
			return nil, fmt.Errorf("mount[%d]: target is required", i)
		}
		if !strings.HasPrefix(target, "/") {
			return nil, fmt.Errorf("mount[%d]: target %q must be absolute", i, target)
		}
		dm := dockerMount{Type: mountType, Source: source, Target: target, ReadOnly: m.ReadOnly}
		switch mountType {
		case "bind":
			if source == "" {
				return nil, fmt.Errorf("mount[%d]: bind source is required", i)
			}
			if !strings.HasPrefix(source, "/") {
				return nil, fmt.Errorf("mount[%d]: bind source %q must be absolute", i, source)
			}
			// Default CreateMountpoint=true so a fresh host doesn't
			// fail the first deploy when the host directory has
			// not been pre-created.
			bopts := dockerMountBindOptions{CreateMountpoint: true}
			if m.BindOptions != nil {
				bopts.Propagation = m.BindOptions.Propagation
				bopts.CreateMountpoint = m.BindOptions.CreateMountpoint
			}
			dm.BindOptions = &bopts
		case "volume":
			// source may be empty -> Docker creates an anonymous volume.
			if m.VolumeOptions != nil {
				dm.VolumeOptions = &dockerMountVolumeOptions{
					NoCopy: m.VolumeOptions.NoCopy,
					Labels: m.VolumeOptions.Labels,
				}
			}
		case "tmpfs":
			if source != "" {
				return nil, fmt.Errorf("mount[%d]: tmpfs must not have a source", i)
			}
		default:
			return nil, fmt.Errorf("mount[%d]: unknown type %q (want bind|volume|tmpfs)", i, m.Type)
		}
		out = append(out, dm)
	}
	return out, nil
}
