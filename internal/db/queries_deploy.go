package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type DeployProject struct {
	ID            int       `json:"id"`
	Slug          string    `json:"slug"`
	Name          string    `json:"name"`
	SourceRepo    string    `json:"source_repo"`
	WebhookSecret string    `json:"-"`
	IsActive      bool      `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Mount mirrors the subset of the Docker Engine API "Mount" object that
// MUVON cares about. Persisted in the deploy_components.mounts JSONB
// column and applied verbatim when the deployer creates candidate (and
// migration) containers. JSON tags use snake_case so SQL seed payloads
// and admin tooling can author the column directly without a wrapper.
type Mount struct {
	Type          string              `json:"type"`                     // "bind" | "volume" | "tmpfs"
	Source        string              `json:"source,omitempty"`         // host path for bind, volume name for volume
	Target        string              `json:"target"`                   // path inside the container
	ReadOnly      bool                `json:"read_only,omitempty"`      //
	BindOptions   *MountBindOptions   `json:"bind_options,omitempty"`   // bind-only
	VolumeOptions *MountVolumeOptions `json:"volume_options,omitempty"` // volume-only
}

type MountBindOptions struct {
	// Propagation: "rprivate" | "private" | "rshared" | "shared" | "rslave" | "slave"
	Propagation string `json:"propagation,omitempty"`
	// CreateMountpoint asks Docker to create the host source path if it
	// is missing. We default this true on bind mounts when applying so
	// fresh hosts don't fail the first deploy.
	CreateMountpoint bool `json:"create_mountpoint,omitempty"`
}

type MountVolumeOptions struct {
	NoCopy bool              `json:"no_copy,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

type DeployComponent struct {
	ID                      int               `json:"id"`
	ProjectID               int               `json:"project_id"`
	ProjectSlug             string            `json:"project_slug,omitempty"`
	Slug                    string            `json:"slug"`
	Name                    string            `json:"name"`
	SourceRepo              string            `json:"source_repo"`
	ImageRepo               string            `json:"image_repo"`
	InternalPort            int               `json:"internal_port"`
	HealthPath              string            `json:"health_path"`
	HealthExpectedStatus    int               `json:"health_expected_status"`
	MigrationCommand        []string          `json:"migration_command"`
	RestartRetries          int               `json:"restart_retries"`
	DrainTimeoutSeconds     int               `json:"drain_timeout_seconds"`
	LongDrainTimeoutSeconds int               `json:"long_drain_timeout_seconds"`
	Networks                []string          `json:"networks"`
	EnvFilePath             string            `json:"env_file_path"`
	Env                     map[string]string `json:"env"`
	Mounts                  []Mount           `json:"mounts"`
	IsRoutable              bool              `json:"is_routable"`
	CreatedAt               time.Time         `json:"created_at"`
	UpdatedAt               time.Time         `json:"updated_at"`
}

type DeployProjectSummary struct {
	Project    DeployProject     `json:"project"`
	Components []DeployComponent `json:"components"`
	Instances  []DeployInstance  `json:"instances"`
}

type DeployRelease struct {
	ID        string    `json:"id"`
	ProjectID int       `json:"project_id"`
	ReleaseID string    `json:"release_id"`
	Repo      string    `json:"repo"`
	Branch    string    `json:"branch"`
	CommitSHA string    `json:"commit_sha"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type DeployReleaseComponent struct {
	ReleaseUUID string    `json:"release_uuid"`
	ComponentID int       `json:"component_id"`
	Slug        string    `json:"slug"`
	ImageRef    string    `json:"image_ref"`
	ImageDigest string    `json:"image_digest"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type DeployInstance struct {
	ID             string     `json:"id"`
	ComponentID    int        `json:"component_id"`
	ProjectSlug    string     `json:"project_slug,omitempty"`
	ComponentSlug  string     `json:"component_slug,omitempty"`
	ReleaseUUID    *string    `json:"release_uuid,omitempty"`
	ReleaseID      string     `json:"release_id,omitempty"`
	ContainerID    string     `json:"container_id"`
	ContainerName  string     `json:"container_name"`
	BackendURL     string     `json:"backend_url"`
	State          string     `json:"state"`
	HealthStatus   string     `json:"health_status"`
	InFlight       int        `json:"in_flight"`
	LastError      string     `json:"last_error"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	DrainStartedAt *time.Time `json:"drain_started_at,omitempty"`
	StoppedAt      *time.Time `json:"stopped_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type ManagedBackend struct {
	InstanceID    string `json:"instance_id"`
	ComponentID   int    `json:"component_id"`
	ProjectSlug   string `json:"project_slug"`
	ComponentSlug string `json:"component_slug"`
	BackendURL    string `json:"backend_url"`
	HealthURL     string `json:"health_url"`
}

type Deployment struct {
	ID          string          `json:"id"`
	ProjectID   int             `json:"project_id"`
	ProjectSlug string          `json:"project_slug,omitempty"`
	ReleaseUUID string          `json:"release_uuid"`
	ReleaseID   string          `json:"release_id"`
	Repo        string          `json:"repo,omitempty"`
	Branch      string          `json:"branch,omitempty"`
	CommitSHA   string          `json:"commit_sha,omitempty"`
	Trigger     string          `json:"trigger"`
	Status      string          `json:"status"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	Error       string          `json:"error"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type DeploymentEvent struct {
	ID           int64           `json:"id"`
	DeploymentID string          `json:"deployment_id"`
	EventType    string          `json:"event_type"`
	Message      string          `json:"message"`
	Detail       json.RawMessage `json:"detail"`
	CreatedAt    time.Time       `json:"created_at"`
}

type EnqueueDeploymentInput struct {
	ProjectSlug string
	ReleaseID   string
	Repo        string
	Branch      string
	CommitSHA   string
	Trigger     string
	Payload     json.RawMessage
	Components  []EnqueueDeploymentComponent
}

type EnqueueDeploymentComponent struct {
	Slug        string
	ImageRef    string
	ImageDigest string
}

type DeploymentPlan struct {
	Deployment Deployment                `json:"deployment"`
	Project    DeployProject             `json:"project"`
	Release    DeployRelease             `json:"release"`
	Components []DeploymentPlanComponent `json:"components"`
}

type DeploymentPlanComponent struct {
	Component DeployComponent        `json:"component"`
	Release   DeployReleaseComponent `json:"release"`
}

func scanDeployProject(scan func(...any) error) (DeployProject, error) {
	var p DeployProject
	err := scan(&p.ID, &p.Slug, &p.Name, &p.SourceRepo, &p.WebhookSecret, &p.IsActive, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

func scanDeployComponent(scan func(...any) error) (DeployComponent, error) {
	var c DeployComponent
	var envRaw, mountsRaw []byte
	err := scan(
		&c.ID, &c.ProjectID, &c.ProjectSlug, &c.Slug, &c.Name, &c.SourceRepo, &c.ImageRepo,
		&c.InternalPort, &c.HealthPath, &c.HealthExpectedStatus, &c.MigrationCommand,
		&c.RestartRetries, &c.DrainTimeoutSeconds, &c.LongDrainTimeoutSeconds, &c.Networks,
		&c.EnvFilePath, &envRaw, &mountsRaw, &c.IsRoutable, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return c, err
	}
	if len(envRaw) > 0 {
		_ = json.Unmarshal(envRaw, &c.Env)
	}
	if c.Env == nil {
		c.Env = map[string]string{}
	}
	if len(mountsRaw) > 0 {
		_ = json.Unmarshal(mountsRaw, &c.Mounts)
	}
	if c.Mounts == nil {
		c.Mounts = []Mount{}
	}
	return c, nil
}

func (d *DB) GetDeployProjectBySlug(ctx context.Context, slug string) (DeployProject, error) {
	p, err := scanDeployProject(d.Pool.QueryRow(ctx,
		`SELECT id, slug, name, source_repo, webhook_secret, is_active, created_at, updated_at
		 FROM deploy_projects WHERE slug = $1 AND is_active = true`, slug).Scan)
	if err != nil {
		return p, fmt.Errorf("get deploy project: %w", err)
	}
	return p, nil
}

func (d *DB) ListDeployProjects(ctx context.Context) ([]DeployProjectSummary, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, slug, name, source_repo, webhook_secret, is_active, created_at, updated_at
		 FROM deploy_projects ORDER BY slug`)
	if err != nil {
		return nil, fmt.Errorf("list deploy projects: %w", err)
	}
	defer rows.Close()

	var summaries []DeployProjectSummary
	for rows.Next() {
		p, err := scanDeployProject(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list deploy projects scan: %w", err)
		}
		summaries = append(summaries, DeployProjectSummary{Project: p})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range summaries {
		components, err := d.ListDeployComponents(ctx, summaries[i].Project.ID)
		if err != nil {
			return nil, err
		}
		instances, err := d.ListDeployInstancesByProject(ctx, summaries[i].Project.ID)
		if err != nil {
			return nil, err
		}
		summaries[i].Components = components
		summaries[i].Instances = instances
	}
	return summaries, nil
}

func (d *DB) UpdateDeployProject(ctx context.Context, slug, name, sourceRepo, webhookSecret string) (DeployProject, error) {
	p, err := scanDeployProject(d.Pool.QueryRow(ctx,
		`UPDATE deploy_projects
		 SET name = $2, source_repo = $3, webhook_secret = $4, updated_at = now()
		 WHERE slug = $1
		 RETURNING id, slug, name, source_repo, webhook_secret, is_active, created_at, updated_at`,
		slug, name, sourceRepo, webhookSecret,
	).Scan)
	if err != nil {
		return p, fmt.Errorf("update deploy project: %w", err)
	}
	return p, nil
}

func (d *DB) ListDeployComponents(ctx context.Context, projectID int) ([]DeployComponent, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT c.id, c.project_id, p.slug, c.slug, c.name, c.source_repo, c.image_repo,
		        c.internal_port, c.health_path, c.health_expected_status, c.migration_command,
		        c.restart_retries, c.drain_timeout_seconds, c.long_drain_timeout_seconds, c.networks,
		        c.env_file_path, c.env, c.mounts, c.is_routable, c.created_at, c.updated_at
		 FROM deploy_components c
		 JOIN deploy_projects p ON p.id = c.project_id
		 WHERE c.project_id = $1
		 ORDER BY c.slug`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list deploy components: %w", err)
	}
	defer rows.Close()

	var out []DeployComponent
	for rows.Next() {
		c, err := scanDeployComponent(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list deploy components scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) ListActiveManagedBackends(ctx context.Context) (map[int][]ManagedBackend, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT i.id::text, c.id, p.slug, c.slug, i.backend_url,
		        concat(rtrim(i.backend_url, '/'), CASE WHEN c.health_path LIKE '/%' THEN c.health_path ELSE '/' || c.health_path END)
		 FROM deploy_instances i
		 JOIN deploy_components c ON c.id = i.component_id
		 JOIN deploy_projects p ON p.id = c.project_id
		 WHERE i.state = 'active' AND i.backend_url <> ''
		 ORDER BY c.id, i.created_at`)
	if err != nil {
		return nil, fmt.Errorf("list active managed backends: %w", err)
	}
	defer rows.Close()

	out := map[int][]ManagedBackend{}
	for rows.Next() {
		var b ManagedBackend
		if err := rows.Scan(&b.InstanceID, &b.ComponentID, &b.ProjectSlug, &b.ComponentSlug, &b.BackendURL, &b.HealthURL); err != nil {
			return nil, fmt.Errorf("list active managed backends scan: %w", err)
		}
		out[b.ComponentID] = append(out[b.ComponentID], b)
	}
	return out, rows.Err()
}

func (d *DB) EnqueueDeployment(ctx context.Context, in EnqueueDeploymentInput) (Deployment, bool, error) {
	if in.Trigger == "" {
		in.Trigger = "webhook"
	}
	if len(in.Payload) == 0 {
		in.Payload = json.RawMessage(`{}`)
	}

	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Deployment{}, false, fmt.Errorf("enqueue deployment begin: %w", err)
	}
	defer tx.Rollback(ctx)

	project, err := scanDeployProject(tx.QueryRow(ctx,
		`SELECT id, slug, name, source_repo, webhook_secret, is_active, created_at, updated_at
		 FROM deploy_projects WHERE slug = $1 AND is_active = true`, in.ProjectSlug).Scan)
	if err != nil {
		return Deployment{}, false, fmt.Errorf("enqueue deployment project: %w", err)
	}

	var releaseUUID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO deploy_releases (project_id, release_id, repo, branch, commit_sha, status)
		 VALUES ($1, $2, $3, $4, $5, 'pending')
		 ON CONFLICT (project_id, release_id) DO UPDATE
		 SET repo = EXCLUDED.repo, branch = EXCLUDED.branch, commit_sha = EXCLUDED.commit_sha, updated_at = now()
		 RETURNING id::text`,
		project.ID, in.ReleaseID, in.Repo, in.Branch, in.CommitSHA,
	).Scan(&releaseUUID); err != nil {
		return Deployment{}, false, fmt.Errorf("enqueue deployment release: %w", err)
	}

	for _, component := range in.Components {
		var componentID int
		if err := tx.QueryRow(ctx,
			`SELECT id FROM deploy_components WHERE project_id = $1 AND slug = $2`,
			project.ID, component.Slug,
		).Scan(&componentID); err != nil {
			return Deployment{}, false, fmt.Errorf("enqueue deployment component %s: %w", component.Slug, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO deploy_release_components (release_uuid, component_id, image_ref, image_digest, status)
			 VALUES ($1, $2, $3, $4, 'pending')
			 ON CONFLICT (release_uuid, component_id) DO UPDATE
			 SET image_ref = EXCLUDED.image_ref, image_digest = EXCLUDED.image_digest, updated_at = now()`,
			releaseUUID, componentID, component.ImageRef, component.ImageDigest,
		); err != nil {
			return Deployment{}, false, fmt.Errorf("enqueue deployment release component: %w", err)
		}
	}

	var dep Deployment
	var inserted bool
	if err := tx.QueryRow(ctx,
		`WITH ins AS (
		    INSERT INTO deployments (project_id, release_uuid, release_id, trigger, status, payload)
		    VALUES ($1, $2, $3, $4, 'pending', $5)
		    ON CONFLICT (project_id, release_uuid) DO UPDATE
		      SET status = 'pending', started_at = NULL, finished_at = NULL,
		          updated_at = now(), payload = EXCLUDED.payload
		      WHERE deployments.status IN ('succeeded', 'failed')
		    RETURNING id::text, project_id, release_uuid::text, release_id, trigger, status, payload, error, started_at, finished_at, created_at, updated_at, true AS inserted
		 )
		 SELECT id, project_id, release_uuid, release_id, trigger, status, payload, error, started_at, finished_at, created_at, updated_at, inserted
		 FROM (
		     SELECT id::text, project_id, release_uuid::text, release_id, trigger, status, payload, error, started_at, finished_at, created_at, updated_at, inserted
		     FROM ins
		     UNION ALL
		     SELECT id::text, project_id, release_uuid::text, release_id, trigger, status, payload, error, started_at, finished_at, created_at, updated_at, false AS inserted
		     FROM deployments
		     WHERE project_id = $1 AND release_uuid = $2
		 ) q
		 ORDER BY inserted DESC
		 LIMIT 1`,
		project.ID, releaseUUID, in.ReleaseID, in.Trigger, in.Payload,
	).Scan(&dep.ID, &dep.ProjectID, &dep.ReleaseUUID, &dep.ReleaseID, &dep.Trigger, &dep.Status, &dep.Payload, &dep.Error, &dep.StartedAt, &dep.FinishedAt, &dep.CreatedAt, &dep.UpdatedAt, &inserted); err != nil {
		return Deployment{}, false, fmt.Errorf("enqueue deployment deployment: %w", err)
	}
	dep.ProjectSlug = project.Slug

	if inserted {
		if _, err := tx.Exec(ctx,
			`INSERT INTO deployment_events (deployment_id, event_type, message)
			 VALUES ($1, 'queued', 'Deployment queued')`, dep.ID); err != nil {
			return Deployment{}, false, fmt.Errorf("enqueue deployment event: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Deployment{}, false, fmt.Errorf("enqueue deployment commit: %w", err)
	}
	return dep, !inserted, nil
}

func (d *DB) ClaimNextDeployment(ctx context.Context) (Deployment, bool, error) {
	var dep Deployment
	err := d.Pool.QueryRow(ctx,
		`WITH next AS (
		    SELECT id FROM deployments
		    WHERE status = 'pending'
		    ORDER BY created_at
		    LIMIT 1
		    FOR UPDATE SKIP LOCKED
		 )
		 UPDATE deployments d
		 SET status = 'running', started_at = COALESCE(started_at, now()), updated_at = now()
		 FROM next
		 WHERE d.id = next.id
		 RETURNING d.id::text, d.project_id, d.release_uuid::text, d.release_id, d.trigger, d.status,
		           d.payload, d.error, d.started_at, d.finished_at, d.created_at, d.updated_at`,
	).Scan(&dep.ID, &dep.ProjectID, &dep.ReleaseUUID, &dep.ReleaseID, &dep.Trigger, &dep.Status, &dep.Payload, &dep.Error, &dep.StartedAt, &dep.FinishedAt, &dep.CreatedAt, &dep.UpdatedAt)
	if err == pgx.ErrNoRows {
		return dep, false, nil
	}
	if err != nil {
		return dep, false, fmt.Errorf("claim next deployment: %w", err)
	}
	return dep, true, nil
}

func (d *DB) LoadDeploymentPlan(ctx context.Context, deploymentID string) (DeploymentPlan, error) {
	var plan DeploymentPlan
	err := d.Pool.QueryRow(ctx,
		`SELECT d.id::text, d.project_id, p.slug, d.release_uuid::text, d.release_id,
		        r.repo, r.branch, r.commit_sha, d.trigger, d.status, d.payload, d.error,
		        d.started_at, d.finished_at, d.created_at, d.updated_at,
		        p.id, p.slug, p.name, p.source_repo, p.webhook_secret, p.is_active, p.created_at, p.updated_at,
		        r.id::text, r.project_id, r.release_id, r.repo, r.branch, r.commit_sha, r.status, r.created_at, r.updated_at
		 FROM deployments d
		 JOIN deploy_projects p ON p.id = d.project_id
		 JOIN deploy_releases r ON r.id = d.release_uuid
		 WHERE d.id = $1`, deploymentID,
	).Scan(
		&plan.Deployment.ID, &plan.Deployment.ProjectID, &plan.Deployment.ProjectSlug, &plan.Deployment.ReleaseUUID,
		&plan.Deployment.ReleaseID, &plan.Deployment.Repo, &plan.Deployment.Branch, &plan.Deployment.CommitSHA,
		&plan.Deployment.Trigger, &plan.Deployment.Status, &plan.Deployment.Payload, &plan.Deployment.Error,
		&plan.Deployment.StartedAt, &plan.Deployment.FinishedAt, &plan.Deployment.CreatedAt, &plan.Deployment.UpdatedAt,
		&plan.Project.ID, &plan.Project.Slug, &plan.Project.Name, &plan.Project.SourceRepo, &plan.Project.WebhookSecret,
		&plan.Project.IsActive, &plan.Project.CreatedAt, &plan.Project.UpdatedAt,
		&plan.Release.ID, &plan.Release.ProjectID, &plan.Release.ReleaseID, &plan.Release.Repo, &plan.Release.Branch,
		&plan.Release.CommitSHA, &plan.Release.Status, &plan.Release.CreatedAt, &plan.Release.UpdatedAt,
	)
	if err != nil {
		return plan, fmt.Errorf("load deployment plan: %w", err)
	}

	rows, err := d.Pool.Query(ctx,
		`SELECT c.id, c.project_id, p.slug, c.slug, c.name, c.source_repo, c.image_repo,
		        c.internal_port, c.health_path, c.health_expected_status, c.migration_command,
		        c.restart_retries, c.drain_timeout_seconds, c.long_drain_timeout_seconds, c.networks,
		        c.env_file_path, c.env, c.mounts, c.is_routable, c.created_at, c.updated_at,
		        rc.release_uuid::text, rc.component_id, c.slug, rc.image_ref, rc.image_digest, rc.status, rc.created_at, rc.updated_at
		 FROM deploy_release_components rc
		 JOIN deploy_components c ON c.id = rc.component_id
		 JOIN deploy_projects p ON p.id = c.project_id
		 WHERE rc.release_uuid = $1 AND rc.status = 'pending'
		 ORDER BY c.slug`, plan.Release.ID)
	if err != nil {
		return plan, fmt.Errorf("load deployment components: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item DeploymentPlanComponent
		var envRaw, mountsRaw []byte
		if err := rows.Scan(
			&item.Component.ID, &item.Component.ProjectID, &item.Component.ProjectSlug, &item.Component.Slug,
			&item.Component.Name, &item.Component.SourceRepo, &item.Component.ImageRepo, &item.Component.InternalPort,
			&item.Component.HealthPath, &item.Component.HealthExpectedStatus, &item.Component.MigrationCommand,
			&item.Component.RestartRetries, &item.Component.DrainTimeoutSeconds, &item.Component.LongDrainTimeoutSeconds,
			&item.Component.Networks, &item.Component.EnvFilePath, &envRaw, &mountsRaw, &item.Component.IsRoutable,
			&item.Component.CreatedAt, &item.Component.UpdatedAt,
			&item.Release.ReleaseUUID, &item.Release.ComponentID, &item.Release.Slug, &item.Release.ImageRef,
			&item.Release.ImageDigest, &item.Release.Status, &item.Release.CreatedAt, &item.Release.UpdatedAt,
		); err != nil {
			return plan, fmt.Errorf("load deployment components scan: %w", err)
		}
		if len(envRaw) > 0 {
			_ = json.Unmarshal(envRaw, &item.Component.Env)
		}
		if item.Component.Env == nil {
			item.Component.Env = map[string]string{}
		}
		if len(mountsRaw) > 0 {
			_ = json.Unmarshal(mountsRaw, &item.Component.Mounts)
		}
		if item.Component.Mounts == nil {
			item.Component.Mounts = []Mount{}
		}
		plan.Components = append(plan.Components, item)
	}
	return plan, rows.Err()
}

func (d *DB) AddDeploymentEvent(ctx context.Context, deploymentID, eventType, message string, detail any) error {
	detailJSON := json.RawMessage(`{}`)
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("deployment event marshal detail: %w", err)
		}
		detailJSON = b
	}
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO deployment_events (deployment_id, event_type, message, detail)
		 VALUES ($1, $2, $3, $4)`,
		deploymentID, eventType, message, detailJSON,
	)
	if err != nil {
		return fmt.Errorf("add deployment event: %w", err)
	}
	return nil
}

func (d *DB) GetDeployment(ctx context.Context, id string) (Deployment, error) {
	var dep Deployment
	err := d.Pool.QueryRow(ctx,
		`SELECT d.id::text, d.project_id, p.slug, d.release_uuid::text, d.release_id,
		        r.repo, r.branch, r.commit_sha, d.trigger, d.status, d.payload, d.error,
		        d.started_at, d.finished_at, d.created_at, d.updated_at
		 FROM deployments d
		 JOIN deploy_projects p ON p.id = d.project_id
		 JOIN deploy_releases r ON r.id = d.release_uuid
		 WHERE d.id = $1`, id).Scan(
		&dep.ID, &dep.ProjectID, &dep.ProjectSlug, &dep.ReleaseUUID, &dep.ReleaseID,
		&dep.Repo, &dep.Branch, &dep.CommitSHA, &dep.Trigger, &dep.Status, &dep.Payload, &dep.Error,
		&dep.StartedAt, &dep.FinishedAt, &dep.CreatedAt, &dep.UpdatedAt)
	if err != nil {
		return dep, fmt.Errorf("get deployment: %w", err)
	}
	return dep, nil
}

func (d *DB) ListDeployments(ctx context.Context, limit int) ([]Deployment, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Pool.Query(ctx,
		`SELECT d.id::text, d.project_id, p.slug, d.release_uuid::text, d.release_id,
		        r.repo, r.branch, r.commit_sha, d.trigger, d.status, d.payload, d.error,
		        d.started_at, d.finished_at, d.created_at, d.updated_at
		 FROM deployments d
		 JOIN deploy_projects p ON p.id = d.project_id
		 JOIN deploy_releases r ON r.id = d.release_uuid
		 ORDER BY d.created_at DESC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	defer rows.Close()

	var out []Deployment
	for rows.Next() {
		var dep Deployment
		if err := rows.Scan(&dep.ID, &dep.ProjectID, &dep.ProjectSlug, &dep.ReleaseUUID, &dep.ReleaseID,
			&dep.Repo, &dep.Branch, &dep.CommitSHA, &dep.Trigger, &dep.Status, &dep.Payload, &dep.Error,
			&dep.StartedAt, &dep.FinishedAt, &dep.CreatedAt, &dep.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list deployments scan: %w", err)
		}
		out = append(out, dep)
	}
	return out, rows.Err()
}

func (d *DB) ListDeploymentEvents(ctx context.Context, deploymentID string) ([]DeploymentEvent, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, deployment_id::text, event_type, message, detail, created_at
		 FROM deployment_events
		 WHERE deployment_id = $1
		 ORDER BY created_at, id`, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("list deployment events: %w", err)
	}
	defer rows.Close()

	var out []DeploymentEvent
	for rows.Next() {
		var event DeploymentEvent
		if err := rows.Scan(&event.ID, &event.DeploymentID, &event.EventType, &event.Message, &event.Detail, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("list deployment events scan: %w", err)
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (d *DB) CreateDeployInstance(ctx context.Context, componentID int, releaseUUID, containerID, containerName, backendURL string) (DeployInstance, error) {
	var inst DeployInstance
	var releaseUUIDOut string
	err := d.Pool.QueryRow(ctx,
		`INSERT INTO deploy_instances (component_id, release_uuid, container_id, container_name, backend_url, state, health_status, started_at)
		 VALUES ($1, $2, $3, $4, $5, 'warming', 'unknown', now())
		 RETURNING id::text, component_id, release_uuid::text, container_id, container_name, backend_url, state, health_status,
		           in_flight, last_error, started_at, drain_started_at, stopped_at, created_at, updated_at`,
		componentID, releaseUUID, containerID, containerName, backendURL,
	).Scan(&inst.ID, &inst.ComponentID, &releaseUUIDOut, &inst.ContainerID, &inst.ContainerName, &inst.BackendURL,
		&inst.State, &inst.HealthStatus, &inst.InFlight, &inst.LastError, &inst.StartedAt, &inst.DrainStartedAt,
		&inst.StoppedAt, &inst.CreatedAt, &inst.UpdatedAt)
	if err != nil {
		return inst, fmt.Errorf("create deploy instance: %w", err)
	}
	inst.ReleaseUUID = &releaseUUIDOut
	return inst, nil
}

func (d *DB) MarkDeployInstanceUnhealthy(ctx context.Context, instanceID, message string) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE deploy_instances
		 SET state = 'unhealthy', health_status = 'failed', last_error = $2, updated_at = now()
		 WHERE id = $1`, instanceID, message)
	if err != nil {
		return fmt.Errorf("mark deploy instance unhealthy: %w", err)
	}
	return nil
}

func (d *DB) PromoteDeployInstances(ctx context.Context, deploymentID string, candidateIDs []string) error {
	if len(candidateIDs) == 0 {
		return fmt.Errorf("promote deploy instances: no candidate instances")
	}
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("promote deploy instances begin: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT DISTINCT component_id FROM deploy_instances WHERE id = ANY($1::uuid[])`, candidateIDs)
	if err != nil {
		return fmt.Errorf("promote deploy instances components: %w", err)
	}
	var componentIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("promote deploy instances component scan: %w", err)
		}
		componentIDs = append(componentIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE deploy_instances
		 SET state = 'draining', drain_started_at = now(), updated_at = now()
		 WHERE state = 'active' AND component_id = ANY($1::int[])`, componentIDs); err != nil {
		return fmt.Errorf("promote deploy instances drain old: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE deploy_instances
		 SET state = 'active', health_status = 'healthy', updated_at = now()
		 WHERE id = ANY($1::uuid[])`, candidateIDs); err != nil {
		return fmt.Errorf("promote deploy instances activate candidates: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE deployments SET status = 'succeeded', finished_at = now(), updated_at = now()
		 WHERE id = $1`, deploymentID); err != nil {
		return fmt.Errorf("promote deploy instances update deployment: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE deploy_releases r
		 SET status = 'succeeded', updated_at = now()
		 FROM deployments d
		 WHERE d.id = $1 AND r.id = d.release_uuid`, deploymentID); err != nil {
		return fmt.Errorf("promote deploy instances update release: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE deploy_release_components rc
		 SET status = 'succeeded', updated_at = now()
		 FROM deployments d
		 WHERE d.id = $1 AND rc.release_uuid = d.release_uuid`, deploymentID); err != nil {
		return fmt.Errorf("promote deploy instances update release components: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO deployment_events (deployment_id, event_type, message)
		 VALUES ($1, 'promoted', 'Release promoted')`, deploymentID); err != nil {
		return fmt.Errorf("promote deploy instances event: %w", err)
	}
	return tx.Commit(ctx)
}

func (d *DB) FailDeployment(ctx context.Context, deploymentID, message string) error {
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("fail deployment begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE deployments SET status = 'failed', error = $2, finished_at = now(), updated_at = now()
		 WHERE id = $1`, deploymentID, message); err != nil {
		return fmt.Errorf("fail deployment update: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE deploy_releases r
		 SET status = 'failed', updated_at = now()
		 FROM deployments d
		 WHERE d.id = $1 AND r.id = d.release_uuid`, deploymentID); err != nil {
		return fmt.Errorf("fail deployment release: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO deployment_events (deployment_id, event_type, message)
		 VALUES ($1, 'failed', $2)`, deploymentID, message); err != nil {
		return fmt.Errorf("fail deployment event: %w", err)
	}
	return tx.Commit(ctx)
}

func (d *DB) AdjustDeployInstanceInFlight(ctx context.Context, instanceID string, delta int) {
	_, _ = d.Pool.Exec(ctx,
		`UPDATE deploy_instances
		 SET in_flight = GREATEST(in_flight + $2, 0), updated_at = now()
		 WHERE id = $1`, instanceID, delta)
}

func (d *DB) ListDrainableDeployInstances(ctx context.Context) ([]DeployInstance, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT i.id::text, i.component_id, p.slug, c.slug, COALESCE(i.release_uuid::text, ''), COALESCE(r.release_id, ''),
		        i.container_id, i.container_name, i.backend_url, i.state, i.health_status, i.in_flight,
		        i.last_error, i.started_at, i.drain_started_at, i.stopped_at, i.created_at, i.updated_at
		 FROM deploy_instances i
		 JOIN deploy_components c ON c.id = i.component_id
		 JOIN deploy_projects p ON p.id = c.project_id
		 LEFT JOIN deploy_releases r ON r.id = i.release_uuid
		 WHERE i.state = 'draining'
		   AND (
		       i.in_flight <= 0
		       OR i.drain_started_at <= now() - (
		           CASE WHEN i.in_flight > 0
		                THEN c.long_drain_timeout_seconds
		                ELSE c.drain_timeout_seconds
		           END || ' seconds'
		       )::interval
		   )
		 ORDER BY i.drain_started_at NULLS FIRST`)
	if err != nil {
		return nil, fmt.Errorf("list drainable deploy instances: %w", err)
	}
	defer rows.Close()
	return scanDeployInstances(rows)
}

func (d *DB) MarkDeployInstanceStopped(ctx context.Context, instanceID string) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE deploy_instances
		 SET state = 'stopped', health_status = 'stopped', stopped_at = now(), updated_at = now()
		 WHERE id = $1`, instanceID)
	if err != nil {
		return fmt.Errorf("mark deploy instance stopped: %w", err)
	}
	return nil
}

// ListLiveManagedContainerIDs returns the set of container IDs that Muvon
// considers alive. A container is live when:
//   - its instance is 'active' or 'draining' (already promoted or being drained), OR
//   - its instance is 'warming' AND the associated deployment is still 'running'
//     (i.e. actively being health-checked right now).
//
// Containers NOT in this set are orphans: they were created during a
// deployment that crashed before completing and should be removed.
func (d *DB) ListLiveManagedContainerIDs(ctx context.Context) (map[string]struct{}, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT container_id FROM deploy_instances
		 WHERE state IN ('active', 'draining') AND container_id != ''
		 UNION
		 SELECT di.container_id
		 FROM deploy_instances di
		 JOIN deployments dep ON dep.release_uuid = di.release_uuid
		 WHERE di.state = 'warming' AND di.container_id != '' AND dep.status = 'running'`)
	if err != nil {
		return nil, fmt.Errorf("list live managed container ids: %w", err)
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("list live managed container ids scan: %w", err)
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

// ResetStaleRunningDeployments resets deployments that got stuck in the
// "running" state (deployer crashed mid-flight) back to "pending" so they
// are retried on the next tick. Returns the number of deployments reset.
func (d *DB) ResetStaleRunningDeployments(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	tag, err := d.Pool.Exec(ctx,
		`UPDATE deployments
		 SET status = 'pending', started_at = NULL, updated_at = now()
		 WHERE status = 'running' AND updated_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("reset stale running deployments: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (d *DB) CleanupStaleWarmingInstances(ctx context.Context) (int, error) {
	tag, err := d.Pool.Exec(ctx,
		`UPDATE deploy_instances
		 SET state = 'unhealthy', health_status = 'deployment terminated'
		 FROM deployments dep
		 WHERE deploy_instances.state = 'warming'
		   AND deploy_instances.release_uuid = dep.release_uuid
		   AND dep.status IN ('failed', 'succeeded')`)
	if err != nil {
		return 0, fmt.Errorf("cleanup stale warming instances: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (d *DB) ListDeployInstancesByProject(ctx context.Context, projectID int) ([]DeployInstance, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT i.id::text, i.component_id, p.slug, c.slug, COALESCE(i.release_uuid::text, ''), COALESCE(r.release_id, ''),
		        i.container_id, i.container_name, i.backend_url, i.state, i.health_status, i.in_flight,
		        i.last_error, i.started_at, i.drain_started_at, i.stopped_at, i.created_at, i.updated_at
		 FROM deploy_instances i
		 JOIN deploy_components c ON c.id = i.component_id
		 JOIN deploy_projects p ON p.id = c.project_id
		 LEFT JOIN deploy_releases r ON r.id = i.release_uuid
		 WHERE p.id = $1
		 ORDER BY c.slug, i.created_at DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list deploy instances by project: %w", err)
	}
	defer rows.Close()
	return scanDeployInstances(rows)
}

func scanDeployInstances(rows pgx.Rows) ([]DeployInstance, error) {
	var out []DeployInstance
	for rows.Next() {
		var inst DeployInstance
		var releaseUUID string
		if err := rows.Scan(&inst.ID, &inst.ComponentID, &inst.ProjectSlug, &inst.ComponentSlug, &releaseUUID,
			&inst.ReleaseID, &inst.ContainerID, &inst.ContainerName, &inst.BackendURL, &inst.State,
			&inst.HealthStatus, &inst.InFlight, &inst.LastError, &inst.StartedAt, &inst.DrainStartedAt,
			&inst.StoppedAt, &inst.CreatedAt, &inst.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan deploy instances: %w", err)
		}
		if releaseUUID != "" {
			inst.ReleaseUUID = &releaseUUID
		}
		out = append(out, inst)
	}
	return out, rows.Err()
}
