package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ScheduledJob is a periodic, component-bound execution definition. It
// borrows the bound component's image / env / secrets / networks / mounts;
// Command overrides the image CMD. AgentID mirrors the component's owner
// ("" = central) so the central scheduler enqueues runs and the matching
// deployer (central muvon-deployer or an edge agent) claims them.
type ScheduledJob struct {
	ID                int64      `json:"id"`
	ProjectID         int        `json:"project_id"`
	ProjectSlug       string     `json:"project_slug,omitempty"`
	ComponentID       int        `json:"component_id"`
	ComponentSlug     string     `json:"component_slug,omitempty"`
	AgentID           string     `json:"agent_id"`
	Name              string     `json:"name"`
	Slug              string     `json:"slug"`
	Schedule          string     `json:"schedule"`
	Timezone          string     `json:"timezone"`
	Command           []string   `json:"command"`
	ExecMode          string     `json:"exec_mode"` // "run" | "exec"
	Enabled           bool       `json:"enabled"`
	ConcurrencyPolicy string     `json:"concurrency_policy"` // "forbid" | "allow"
	TimeoutSeconds    int        `json:"timeout_seconds"`
	LastRunAt         *time.Time `json:"last_run_at"`
	NextRunAt         *time.Time `json:"next_run_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// ScheduledJobRun is one execution of a ScheduledJob. The scheduler inserts
// 'pending' rows; the deployer claims and runs them, then records the
// terminal status + exit code + captured output tail.
type ScheduledJobRun struct {
	ID           int64      `json:"id"`
	JobID        int64      `json:"job_id"`
	AgentID      string     `json:"agent_id"`
	Status       string     `json:"status"`  // pending|running|succeeded|failed|skipped
	Trigger      string     `json:"trigger"` // schedule|manual
	ExitCode     *int       `json:"exit_code"`
	ScheduledFor time.Time  `json:"scheduled_for"`
	StartedAt    *time.Time `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	Error        string     `json:"error"`
	Output       string     `json:"output"`
	CreatedAt    time.Time  `json:"created_at"`
}

// scheduledJobSelectCols lists every column scanScheduledJob expects,
// prefixed `j.` and joining deploy_projects p + deploy_components c to
// recover the human-friendly project/component slugs.
const scheduledJobSelectCols = `j.id, j.project_id, p.slug, j.component_id, c.slug,
	COALESCE(j.agent_id, ''), j.name, j.slug, j.schedule, j.timezone, j.command,
	j.exec_mode, j.enabled, j.concurrency_policy, j.timeout_seconds,
	j.last_run_at, j.next_run_at, j.created_at, j.updated_at`

func scanScheduledJob(scan func(...any) error) (ScheduledJob, error) {
	var j ScheduledJob
	err := scan(
		&j.ID, &j.ProjectID, &j.ProjectSlug, &j.ComponentID, &j.ComponentSlug,
		&j.AgentID, &j.Name, &j.Slug, &j.Schedule, &j.Timezone, &j.Command,
		&j.ExecMode, &j.Enabled, &j.ConcurrencyPolicy, &j.TimeoutSeconds,
		&j.LastRunAt, &j.NextRunAt, &j.CreatedAt, &j.UpdatedAt,
	)
	if err != nil {
		return j, err
	}
	if j.Command == nil {
		j.Command = []string{}
	}
	return j, nil
}

func scanScheduledJobRun(scan func(...any) error) (ScheduledJobRun, error) {
	var run ScheduledJobRun
	err := scan(
		&run.ID, &run.JobID, &run.AgentID, &run.Status, &run.Trigger,
		&run.ExitCode, &run.ScheduledFor, &run.StartedAt, &run.FinishedAt,
		&run.Error, &run.Output, &run.CreatedAt,
	)
	return run, err
}

// ── Admin CRUD ──────────────────────────────────────────────────────────

func (d *DB) ListScheduledJobs(ctx context.Context, projectSlug string) ([]ScheduledJob, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT `+scheduledJobSelectCols+`
		 FROM scheduled_jobs j
		 JOIN deploy_projects p ON p.id = j.project_id
		 JOIN deploy_components c ON c.id = j.component_id
		 WHERE p.slug = $1
		 ORDER BY j.slug`, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("list scheduled jobs: %w", err)
	}
	defer rows.Close()
	var out []ScheduledJob
	for rows.Next() {
		j, err := scanScheduledJob(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list scheduled jobs scan: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (d *DB) GetScheduledJob(ctx context.Context, projectSlug, jobSlug string) (ScheduledJob, error) {
	j, err := scanScheduledJob(d.Pool.QueryRow(ctx,
		`SELECT `+scheduledJobSelectCols+`
		 FROM scheduled_jobs j
		 JOIN deploy_projects p ON p.id = j.project_id
		 JOIN deploy_components c ON c.id = j.component_id
		 WHERE p.slug = $1 AND j.slug = $2`, projectSlug, jobSlug).Scan)
	if err != nil {
		return j, fmt.Errorf("get scheduled job: %w", err)
	}
	return j, nil
}

// CreateScheduledJobInput is the validated, defaulted shape the admin
// handler builds. AgentID is derived from the bound component; NextRunAt
// is computed by the scheduler package (the DB layer is cron-agnostic).
type CreateScheduledJobInput struct {
	ProjectSlug       string
	ComponentSlug     string
	AgentID           string
	Name              string
	Slug              string
	Schedule          string
	Timezone          string
	Command           []string
	ExecMode          string
	Enabled           bool
	ConcurrencyPolicy string
	TimeoutSeconds    int
	NextRunAt         time.Time
}

func (d *DB) CreateScheduledJob(ctx context.Context, in CreateScheduledJobInput) (ScheduledJob, error) {
	if in.Command == nil {
		in.Command = []string{}
	}
	var agentID any
	if in.AgentID != "" {
		agentID = in.AgentID
	}
	var jobID int64
	err := d.Pool.QueryRow(ctx,
		`INSERT INTO scheduled_jobs (
		    project_id, component_id, agent_id, name, slug, schedule, timezone,
		    command, exec_mode, enabled, concurrency_policy, timeout_seconds, next_run_at
		 )
		 SELECT c.project_id, c.id, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		 FROM deploy_components c
		 JOIN deploy_projects p ON p.id = c.project_id
		 WHERE p.slug = $1 AND c.slug = $2
		 RETURNING id`,
		in.ProjectSlug, in.ComponentSlug, agentID, in.Name, in.Slug, in.Schedule,
		in.Timezone, in.Command, in.ExecMode, in.Enabled, in.ConcurrencyPolicy,
		in.TimeoutSeconds, in.NextRunAt,
	).Scan(&jobID)
	if err != nil {
		return ScheduledJob{}, fmt.Errorf("create scheduled job: %w", err)
	}
	return d.GetScheduledJob(ctx, in.ProjectSlug, in.Slug)
}

// UpdateScheduledJobInput carries only the mutable fields; nil pointers
// leave the stored value untouched. When Schedule or Timezone change the
// handler recomputes NextRunAt and passes it here.
type UpdateScheduledJobInput struct {
	Name              *string
	Schedule          *string
	Timezone          *string
	Command           *[]string
	ExecMode          *string
	Enabled           *bool
	ConcurrencyPolicy *string
	TimeoutSeconds    *int
	NextRunAt         *time.Time
}

func (d *DB) UpdateScheduledJob(ctx context.Context, projectSlug, jobSlug string, in UpdateScheduledJobInput) (ScheduledJob, error) {
	existing, err := d.GetScheduledJob(ctx, projectSlug, jobSlug)
	if err != nil {
		return ScheduledJob{}, err
	}
	name := existing.Name
	if in.Name != nil {
		name = *in.Name
	}
	schedule := existing.Schedule
	if in.Schedule != nil {
		schedule = *in.Schedule
	}
	timezone := existing.Timezone
	if in.Timezone != nil {
		timezone = *in.Timezone
	}
	command := existing.Command
	if in.Command != nil {
		command = *in.Command
	}
	execMode := existing.ExecMode
	if in.ExecMode != nil {
		execMode = *in.ExecMode
	}
	enabled := existing.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	policy := existing.ConcurrencyPolicy
	if in.ConcurrencyPolicy != nil {
		policy = *in.ConcurrencyPolicy
	}
	timeout := existing.TimeoutSeconds
	if in.TimeoutSeconds != nil {
		timeout = *in.TimeoutSeconds
	}
	nextRun := existing.NextRunAt
	if in.NextRunAt != nil {
		nextRun = in.NextRunAt
	}
	_, err = d.Pool.Exec(ctx,
		`UPDATE scheduled_jobs
		 SET name = $1, schedule = $2, timezone = $3, command = $4, exec_mode = $5,
		     enabled = $6, concurrency_policy = $7, timeout_seconds = $8,
		     next_run_at = $9, updated_at = now()
		 WHERE id = $10`,
		name, schedule, timezone, command, execMode, enabled, policy, timeout,
		nextRun, existing.ID,
	)
	if err != nil {
		return ScheduledJob{}, fmt.Errorf("update scheduled job: %w", err)
	}
	return d.GetScheduledJob(ctx, projectSlug, jobSlug)
}

func (d *DB) DeleteScheduledJob(ctx context.Context, projectSlug, jobSlug string) error {
	tag, err := d.Pool.Exec(ctx,
		`DELETE FROM scheduled_jobs j
		 USING deploy_projects p
		 WHERE j.project_id = p.id AND p.slug = $1 AND j.slug = $2`,
		projectSlug, jobSlug)
	if err != nil {
		return fmt.Errorf("delete scheduled job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("delete scheduled job: not found")
	}
	return nil
}

// ── Scheduler (central) ─────────────────────────────────────────────────

// ListDueJobs returns enabled jobs whose next_run_at has arrived. A NULL
// next_run_at (never computed) is treated as not-due — Create always sets
// it, so this only guards against manual SQL tampering.
func (d *DB) ListDueJobs(ctx context.Context, now time.Time) ([]ScheduledJob, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT `+scheduledJobSelectCols+`
		 FROM scheduled_jobs j
		 JOIN deploy_projects p ON p.id = j.project_id
		 JOIN deploy_components c ON c.id = j.component_id
		 WHERE j.enabled = true AND j.next_run_at IS NOT NULL AND j.next_run_at <= $1
		 ORDER BY j.next_run_at`, now)
	if err != nil {
		return nil, fmt.Errorf("list due jobs: %w", err)
	}
	defer rows.Close()
	var out []ScheduledJob
	for rows.Next() {
		j, err := scanScheduledJob(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list due jobs scan: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// EnqueueJobRun inserts a pending run. For trigger='schedule' it is
// idempotent on (job_id, scheduled_for) — a scheduler restart that
// re-processes the same tick gets created=false instead of a duplicate
// run. Manual triggers always insert (created=true).
func (d *DB) EnqueueJobRun(ctx context.Context, jobID int64, agentID string, scheduledFor time.Time, trigger string) (bool, error) {
	var agent any
	if agentID != "" {
		agent = agentID
	}
	if trigger == "manual" {
		_, err := d.Pool.Exec(ctx,
			`INSERT INTO scheduled_job_runs (job_id, agent_id, scheduled_for, trigger)
			 VALUES ($1, $2, $3, 'manual')`, jobID, agent, scheduledFor)
		if err != nil {
			return false, fmt.Errorf("enqueue manual job run: %w", err)
		}
		return true, nil
	}
	tag, err := d.Pool.Exec(ctx,
		`INSERT INTO scheduled_job_runs (job_id, agent_id, scheduled_for, trigger)
		 VALUES ($1, $2, $3, 'schedule')
		 ON CONFLICT (job_id, scheduled_for) WHERE trigger = 'schedule' DO NOTHING`,
		jobID, agent, scheduledFor)
	if err != nil {
		return false, fmt.Errorf("enqueue scheduled job run: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// RecordSkippedRun writes a visible 'skipped' run for a tick the scheduler
// declined because concurrency_policy='forbid' and a prior run is still
// in flight. Idempotent on the same scheduled_for so a retried tick never
// double-records.
func (d *DB) RecordSkippedRun(ctx context.Context, jobID int64, agentID string, scheduledFor time.Time) error {
	var agent any
	if agentID != "" {
		agent = agentID
	}
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO scheduled_job_runs (job_id, agent_id, scheduled_for, trigger, status, finished_at, error)
		 VALUES ($1, $2, $3, 'schedule', 'skipped', now(), 'previous run still in progress')
		 ON CONFLICT (job_id, scheduled_for) WHERE trigger = 'schedule' DO NOTHING`,
		jobID, agent, scheduledFor)
	if err != nil {
		return fmt.Errorf("record skipped run: %w", err)
	}
	return nil
}

// AdvanceJobSchedule records the tick just enqueued (last_run_at) and the
// next cron boundary (next_run_at), computed by the scheduler package.
func (d *DB) AdvanceJobSchedule(ctx context.Context, jobID int64, lastRun time.Time, nextRun time.Time) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE scheduled_jobs SET last_run_at = $1, next_run_at = $2, updated_at = now()
		 WHERE id = $3`, lastRun, nextRun, jobID)
	if err != nil {
		return fmt.Errorf("advance job schedule: %w", err)
	}
	return nil
}

// HasActiveRun reports whether the job already has a pending or running
// run — the scheduler consults this for concurrency_policy='forbid' so a
// slow job never piles up overlapping executions.
func (d *DB) HasActiveRun(ctx context.Context, jobID int64) (bool, error) {
	var exists bool
	err := d.Pool.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1 FROM scheduled_job_runs
		    WHERE job_id = $1 AND status IN ('pending', 'running')
		 )`, jobID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has active run: %w", err)
	}
	return exists, nil
}

// ── Executor (deployer; central + edge via the State adapter) ────────────

// ClaimNextJobRun hands out the oldest pending run whose agent_id matches
// the caller. Mirrors ClaimNextDeployment: agentID == "" claims central
// runs (NULL agent_id), a non-empty id claims only that agent's runs.
func (d *DB) ClaimNextJobRun(ctx context.Context, agentID string) (ScheduledJobRun, bool, error) {
	var (
		filter string
		args   []any
	)
	if agentID == "" {
		filter = "AND agent_id IS NULL"
	} else {
		filter = "AND agent_id = $1"
		args = append(args, agentID)
	}
	query := `WITH next AS (
	    SELECT id FROM scheduled_job_runs
	    WHERE status = 'pending' ` + filter + `
	    ORDER BY created_at
	    LIMIT 1
	    FOR UPDATE SKIP LOCKED
	 )
	 UPDATE scheduled_job_runs r
	 SET status = 'running', started_at = now()
	 FROM next
	 WHERE r.id = next.id
	 RETURNING ` + scheduledJobRunSelectColsPrefixed("r")
	run, err := scanScheduledJobRun(d.Pool.QueryRow(ctx, query, args...).Scan)
	if err == pgx.ErrNoRows {
		return run, false, nil
	}
	if err != nil {
		return run, false, fmt.Errorf("claim next job run: %w", err)
	}
	return run, true, nil
}

// scheduledJobRunSelectColsPrefixed returns the run column list aliased to
// table `t` — RETURNING in the claim CTE needs the r. prefix.
func scheduledJobRunSelectColsPrefixed(t string) string {
	return t + `.id, ` + t + `.job_id, COALESCE(` + t + `.agent_id, ''), ` + t + `.status, ` + t + `.trigger,
		` + t + `.exit_code, ` + t + `.scheduled_for, ` + t + `.started_at, ` + t + `.finished_at, ` + t + `.error, ` + t + `.output, ` + t + `.created_at`
}

// LoadJobForRun resolves everything the executor needs for one run: the
// job definition, its bound component (image_repo, env, secrets, networks,
// mounts), and the image ref of the component's most recent succeeded
// release. imageRef is "" when the component has never deployed — the
// executor turns that into a clear failure for exec_mode='run'.
func (d *DB) LoadJobForRun(ctx context.Context, runID int64) (ScheduledJob, DeployComponent, string, error) {
	var jobID, componentID int64
	err := d.Pool.QueryRow(ctx,
		`SELECT job_id, (SELECT component_id FROM scheduled_jobs WHERE id = r.job_id)
		 FROM scheduled_job_runs r WHERE r.id = $1`, runID).Scan(&jobID, &componentID)
	if err != nil {
		return ScheduledJob{}, DeployComponent{}, "", fmt.Errorf("load job for run: %w", err)
	}

	job, err := scanScheduledJob(d.Pool.QueryRow(ctx,
		`SELECT `+scheduledJobSelectCols+`
		 FROM scheduled_jobs j
		 JOIN deploy_projects p ON p.id = j.project_id
		 JOIN deploy_components c ON c.id = j.component_id
		 WHERE j.id = $1`, jobID).Scan)
	if err != nil {
		return ScheduledJob{}, DeployComponent{}, "", fmt.Errorf("load job for run job: %w", err)
	}

	component, err := scanDeployComponent(d.Pool.QueryRow(ctx,
		`SELECT `+deployComponentSelectCols+`
		 FROM deploy_components c
		 JOIN deploy_projects p ON p.id = c.project_id
		 WHERE c.id = $1`, job.ComponentID).Scan)
	if err != nil {
		return job, DeployComponent{}, "", fmt.Errorf("load job for run component: %w", err)
	}

	var imageRef string
	err = d.Pool.QueryRow(ctx,
		`SELECT rc.image_ref
		 FROM deploy_release_components rc
		 JOIN deploy_releases r ON r.id = rc.release_uuid
		 WHERE rc.component_id = $1 AND r.status = 'succeeded'
		 ORDER BY r.created_at DESC
		 LIMIT 1`, job.ComponentID).Scan(&imageRef)
	if err != nil && err != pgx.ErrNoRows {
		return job, component, "", fmt.Errorf("load job for run image: %w", err)
	}
	return job, component, imageRef, nil
}

// JobRunPlan bundles everything the executor needs for one run into a
// single serialisable shape so the edge deployer (APIState) can fetch it
// over HTTP exactly as the central deployer reads it from the DB.
type JobRunPlan struct {
	Job       ScheduledJob    `json:"job"`
	Component DeployComponent `json:"component"`
	ImageRef  string          `json:"image_ref"`
	// ActiveContainerID is the container of the component's current active
	// instance — populated for exec_mode='exec' so the executor runs the
	// command inside the live container. Empty when no active instance.
	ActiveContainerID string `json:"active_container_id"`
}

// LoadJobRunPlan wraps LoadJobForRun in the composite shape used across the
// State adapter (direct DB and HTTP-backed). For exec-mode jobs it also
// resolves the component's active container.
func (d *DB) LoadJobRunPlan(ctx context.Context, runID int64) (JobRunPlan, error) {
	job, component, imageRef, err := d.LoadJobForRun(ctx, runID)
	if err != nil {
		return JobRunPlan{}, err
	}
	plan := JobRunPlan{Job: job, Component: component, ImageRef: imageRef}
	if job.ExecMode == "exec" {
		plan.ActiveContainerID, _ = d.ActiveContainerIDForComponent(ctx, job.ComponentID)
	}
	return plan, nil
}

// ActiveContainerIDForComponent returns the container ID of the component's
// current active instance, or "" when none is active.
func (d *DB) ActiveContainerIDForComponent(ctx context.Context, componentID int) (string, error) {
	var containerID string
	err := d.Pool.QueryRow(ctx,
		`SELECT container_id FROM deploy_instances
		 WHERE component_id = $1 AND state = 'active' AND container_id <> ''
		 ORDER BY created_at DESC LIMIT 1`, componentID).Scan(&containerID)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("active container for component: %w", err)
	}
	return containerID, nil
}

// FinishJobRun records the terminal state of a run. status is one of
// succeeded|failed|skipped; exitCode may be nil (exec error before exit).
func (d *DB) FinishJobRun(ctx context.Context, runID int64, status string, exitCode *int, errMsg, output string) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE scheduled_job_runs
		 SET status = $1, exit_code = $2, error = $3, output = $4, finished_at = now()
		 WHERE id = $5`, status, exitCode, errMsg, output, runID)
	if err != nil {
		return fmt.Errorf("finish job run: %w", err)
	}
	return nil
}

// ResetStaleRunningJobRuns recovers runs stuck in 'running' after a
// deployer crash. Scoped by agent_id like the deployment variant so a
// central restart never disturbs an edge agent's in-flight runs.
func (d *DB) ResetStaleRunningJobRuns(ctx context.Context, agentID string, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	var (
		filter string
		args   []any
	)
	args = append(args, cutoff)
	if agentID == "" {
		filter = "AND agent_id IS NULL"
	} else {
		filter = "AND agent_id = $2"
		args = append(args, agentID)
	}
	tag, err := d.Pool.Exec(ctx,
		`UPDATE scheduled_job_runs
		 SET status = 'pending', started_at = NULL
		 WHERE status = 'running' AND started_at < $1 `+filter, args...)
	if err != nil {
		return 0, fmt.Errorf("reset stale job runs: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// GetJobRunAgentID resolves a run's owning agent (via its job) for the
// agent-side ownership check.
func (d *DB) GetJobRunAgentID(ctx context.Context, runID int64) (string, error) {
	var agentID *string
	err := d.Pool.QueryRow(ctx,
		`SELECT j.agent_id
		 FROM scheduled_job_runs r
		 JOIN scheduled_jobs j ON j.id = r.job_id
		 WHERE r.id = $1`, runID).Scan(&agentID)
	if err != nil {
		return "", fmt.Errorf("get job run agent: %w", err)
	}
	if agentID == nil {
		return "", nil
	}
	return *agentID, nil
}

// ListJobRuns returns the most recent runs for a job (newest first).
func (d *DB) ListJobRuns(ctx context.Context, projectSlug, jobSlug string, limit int) ([]ScheduledJobRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Pool.Query(ctx,
		`SELECT `+scheduledJobRunSelectColsPrefixed("r")+`
		 FROM scheduled_job_runs r
		 JOIN scheduled_jobs j ON j.id = r.job_id
		 JOIN deploy_projects p ON p.id = j.project_id
		 WHERE p.slug = $1 AND j.slug = $2
		 ORDER BY r.created_at DESC
		 LIMIT $3`, projectSlug, jobSlug, limit)
	if err != nil {
		return nil, fmt.Errorf("list job runs: %w", err)
	}
	defer rows.Close()
	var out []ScheduledJobRun
	for rows.Next() {
		run, err := scanScheduledJobRun(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list job runs scan: %w", err)
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// GetScheduledJobByID fetches a job by primary key — used by the manual
// trigger handler after it resolved the job from the URL slug.
func (d *DB) GetScheduledJobByID(ctx context.Context, jobID int64) (ScheduledJob, error) {
	j, err := scanScheduledJob(d.Pool.QueryRow(ctx,
		`SELECT `+scheduledJobSelectCols+`
		 FROM scheduled_jobs j
		 JOIN deploy_projects p ON p.id = j.project_id
		 JOIN deploy_components c ON c.id = j.component_id
		 WHERE j.id = $1`, jobID).Scan)
	if err != nil {
		return j, fmt.Errorf("get scheduled job by id: %w", err)
	}
	return j, nil
}
