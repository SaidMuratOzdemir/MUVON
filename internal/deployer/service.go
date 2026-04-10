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
	"time"

	"muvon/internal/db"
)

type Service struct {
	db           *db.DB
	docker       *DockerClient
	pollInterval time.Duration
	healthClient *http.Client
}

func NewService(database *db.DB, docker *DockerClient, pollInterval time.Duration) *Service {
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	return &Service{
		db:           database,
		docker:       docker,
		pollInterval: pollInterval,
		healthClient: defaultHTTPClient(),
	}
}

func (s *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		if err := s.tick(ctx); err != nil {
			slog.Error("deployer tick failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) tick(ctx context.Context) error {
	if err := s.cleanupDraining(ctx); err != nil {
		slog.Warn("drain cleanup failed", "error", err)
	}

	deployment, ok, err := s.db.ClaimNextDeployment(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := s.processDeployment(ctx, deployment.ID); err != nil {
		slog.Error("deployment failed", "deployment_id", deployment.ID, "error", err)
		_ = s.db.FailDeployment(context.Background(), deployment.ID, err.Error())
		return err
	}
	return nil
}

func (s *Service) processDeployment(ctx context.Context, deploymentID string) error {
	plan, err := s.db.LoadDeploymentPlan(ctx, deploymentID)
	if err != nil {
		return err
	}
	_ = s.db.AddDeploymentEvent(ctx, deploymentID, "started", "Deployment started", nil)

	candidates := make([]string, 0, len(plan.Components))
	createdContainers := make([]string, 0, len(plan.Components))
	for _, item := range plan.Components {
		component := item.Component
		imageRef := item.Release.ImageRef
		if imageRef == "" {
			return fmt.Errorf("component %s has no image_ref", component.Slug)
		}
		if err := s.db.AddDeploymentEvent(ctx, deploymentID, "pull", "Pulling image", map[string]string{"component": component.Slug, "image": imageRef}); err != nil {
			return err
		}
		if err := s.docker.ImagePull(ctx, imageRef); err != nil {
			return fmt.Errorf("pull %s: %w", imageRef, err)
		}

		env, err := loadComponentEnv(component)
		if err != nil {
			return fmt.Errorf("load env for %s: %w", component.Slug, err)
		}
		if err := s.ensureNetworks(ctx, component.Networks); err != nil {
			return fmt.Errorf("ensure networks for %s: %w", component.Slug, err)
		}
		if len(component.MigrationCommand) > 0 {
			if err := s.runMigration(ctx, deploymentID, plan, component, imageRef, env); err != nil {
				return err
			}
		}

		containerName := containerName(plan.Project.Slug, component.Slug, plan.Release.ReleaseID)
		createReq := containerCreateRequest{
			Image: imageRef,
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
			},
			NetworkingConfig: networkConfig(component.Networks),
		}
		containerID, err := s.docker.ContainerCreate(ctx, containerName, createReq)
		if err != nil {
			return fmt.Errorf("create candidate %s: %w", component.Slug, err)
		}
		createdContainers = append(createdContainers, containerID)
		if err := s.connectExtraNetworks(ctx, component.Networks, containerID); err != nil {
			return fmt.Errorf("connect networks for %s: %w", component.Slug, err)
		}
		if err := s.docker.ContainerStart(ctx, containerID); err != nil {
			return fmt.Errorf("start candidate %s: %w", component.Slug, err)
		}

		backendURL := fmt.Sprintf("http://%s:%d", containerName, component.InternalPort)
		instance, err := s.db.CreateDeployInstance(ctx, component.ID, plan.Release.ID, containerID, containerName, backendURL)
		if err != nil {
			return err
		}
		if err := s.waitHealthyWithRestart(ctx, deploymentID, component, containerID, backendURL); err != nil {
			_ = s.db.MarkDeployInstanceUnhealthy(context.Background(), instance.ID, err.Error())
			_ = s.docker.ContainerRemove(context.Background(), containerID, true)
			return err
		}
		candidates = append(candidates, instance.ID)
		_ = s.db.AddDeploymentEvent(ctx, deploymentID, "candidate_healthy", "Candidate is healthy", map[string]string{"component": component.Slug, "url": backendURL})
	}

	if err := s.db.PromoteDeployInstances(ctx, deploymentID, candidates); err != nil {
		for _, containerID := range createdContainers {
			_ = s.docker.ContainerRemove(context.Background(), containerID, true)
		}
		return err
	}
	slog.Info("deployment promoted", "deployment_id", deploymentID)
	return nil
}

func (s *Service) runMigration(ctx context.Context, deploymentID string, plan db.DeploymentPlan, component db.DeployComponent, imageRef string, env map[string]string) error {
	_ = s.db.AddDeploymentEvent(ctx, deploymentID, "migration", "Running migration", map[string]any{"component": component.Slug, "command": component.MigrationCommand})
	name := containerName(plan.Project.Slug, component.Slug+"-migration", plan.Release.ReleaseID)
	req := containerCreateRequest{
		Image: imageRef,
		Cmd:   component.MigrationCommand,
		Env:   envList(env),
		Labels: map[string]string{
			"muvon.project":    plan.Project.Slug,
			"muvon.component":  component.Slug,
			"muvon.release_id": plan.Release.ReleaseID,
			"muvon.managed":    "true",
			"muvon.job":        "migration",
		},
		HostConfig:       hostConfig{NetworkMode: firstNetwork(component.Networks)},
		NetworkingConfig: networkConfig(component.Networks),
	}
	containerID, err := s.docker.ContainerCreate(ctx, name, req)
	if err != nil {
		return fmt.Errorf("create migration container: %w", err)
	}
	defer s.docker.ContainerRemove(context.Background(), containerID, true)
	if err := s.connectExtraNetworks(ctx, component.Networks, containerID); err != nil {
		return fmt.Errorf("connect migration networks: %w", err)
	}
	if err := s.docker.ContainerStart(ctx, containerID); err != nil {
		return fmt.Errorf("start migration container: %w", err)
	}
	status, err := s.docker.ContainerWait(ctx, containerID)
	if err != nil {
		return fmt.Errorf("wait migration container: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("migration failed for %s with exit code %d", component.Slug, status)
	}
	_ = s.db.AddDeploymentEvent(ctx, deploymentID, "migration_succeeded", "Migration succeeded", map[string]string{"component": component.Slug})
	return nil
}

func (s *Service) waitHealthyWithRestart(ctx context.Context, deploymentID string, component db.DeployComponent, containerID, backendURL string) error {
	attempts := component.RestartRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			_ = s.db.AddDeploymentEvent(ctx, deploymentID, "restart", "Restarting unhealthy candidate", map[string]any{"component": component.Slug, "attempt": attempt - 1})
			if err := s.docker.ContainerRestart(ctx, containerID, 10); err != nil {
				return fmt.Errorf("restart candidate %s: %w", component.Slug, err)
			}
		}
		if err := s.waitHealthy(ctx, component, backendURL); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("candidate %s failed health after %d attempt(s): %w", component.Slug, attempts, lastErr)
}

func (s *Service) waitHealthy(ctx context.Context, component db.DeployComponent, backendURL string) error {
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

func (s *Service) cleanupDraining(ctx context.Context) error {
	instances, err := s.db.ListDrainableDeployInstances(ctx)
	if err != nil {
		return err
	}
	for _, inst := range instances {
		if inst.ContainerID != "" {
			_ = s.docker.ContainerStop(ctx, inst.ContainerID, 10)
			_ = s.docker.ContainerRemove(ctx, inst.ContainerID, false)
		}
		if err := s.db.MarkDeployInstanceStopped(ctx, inst.ID); err != nil {
			return err
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

func (s *Service) connectExtraNetworks(ctx context.Context, networks []string, containerID string) error {
	if len(networks) <= 1 {
		return nil
	}
	for _, network := range networks[1:] {
		if err := s.docker.NetworkConnect(ctx, network, containerID); err != nil {
			return err
		}
	}
	return nil
}

func loadComponentEnv(component db.DeployComponent) (map[string]string, error) {
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
		env[k] = v
	}
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

func networkConfig(networks []string) networkingConfig {
	first := firstNetwork(networks)
	return networkingConfig{EndpointsConfig: map[string]endpointSettings{first: {}}}
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
