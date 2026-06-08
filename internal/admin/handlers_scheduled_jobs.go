package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"muvon/internal/db"
	"muvon/internal/scheduler"
)

type scheduledJobRequest struct {
	ComponentSlug     string   `json:"component_slug"`
	Name              string   `json:"name"`
	Slug              string   `json:"slug"`
	Schedule          string   `json:"schedule"`
	Timezone          string   `json:"timezone"`
	Command           []string `json:"command"`
	ExecMode          string   `json:"exec_mode"`
	Enabled           *bool    `json:"enabled"`
	ConcurrencyPolicy string   `json:"concurrency_policy"`
	TimeoutSeconds    int      `json:"timeout_seconds"`
}

func jobSlugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
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

// validExecMode / validConcurrency normalise + bound the enum fields so an
// unknown value can never reach the executor.
func normExecMode(s string) (string, bool) {
	switch strings.TrimSpace(s) {
	case "", "run":
		return "run", true
	case "exec":
		return "exec", true
	}
	return "", false
}

func normConcurrency(s string) (string, bool) {
	switch strings.TrimSpace(s) {
	case "", "forbid":
		return "forbid", true
	case "allow":
		return "allow", true
	}
	return "", false
}

func (s *Server) handleListScheduledJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.db.ListScheduledJobs(r.Context(), r.PathValue("slug"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if jobs == nil {
		jobs = []db.ScheduledJob{}
	}
	writeJSON(w, http.StatusOK, jobs)
}

func (s *Server) handleGetScheduledJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.db.GetScheduledJob(r.Context(), r.PathValue("slug"), r.PathValue("job"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scheduled job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleCreateScheduledJob(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	var req scheduledJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	slug := jobSlugify(req.Slug)
	if slug == "" {
		slug = jobSlugify(req.Name)
	}
	if req.Name == "" || slug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	componentSlug := strings.ToLower(strings.TrimSpace(req.ComponentSlug))
	if componentSlug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "component_slug is required"})
		return
	}
	component, err := s.db.GetDeployComponent(r.Context(), projectSlug, componentSlug)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "component not found in this project"})
		return
	}
	timezone := strings.TrimSpace(req.Timezone)
	if timezone == "" {
		timezone = "UTC"
	}
	if err := scheduler.ValidateSchedule(req.Schedule, timezone); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	execMode, ok := normExecMode(req.ExecMode)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "exec_mode must be 'run' or 'exec'"})
		return
	}
	policy, ok := normConcurrency(req.ConcurrencyPolicy)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "concurrency_policy must be 'forbid' or 'allow'"})
		return
	}
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = 3600
	}
	if timeout > 86400 {
		timeout = 86400
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	next, err := scheduler.NextRun(req.Schedule, timezone, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	job, err := s.db.CreateScheduledJob(r.Context(), db.CreateScheduledJobInput{
		ProjectSlug:       projectSlug,
		ComponentSlug:     componentSlug,
		AgentID:           component.AgentID,
		Name:              req.Name,
		Slug:              slug,
		Schedule:          strings.TrimSpace(req.Schedule),
		Timezone:          timezone,
		Command:           req.Command,
		ExecMode:          execMode,
		Enabled:           enabled,
		ConcurrencyPolicy: policy,
		TimeoutSeconds:    timeout,
		NextRunAt:         next,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a job with this slug already exists in this project"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "scheduled_job.create", "scheduled_job", projectSlug+"/"+slug, map[string]any{"component": componentSlug, "schedule": job.Schedule})
	writeJSON(w, http.StatusCreated, job)
}

func (s *Server) handleUpdateScheduledJob(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	jobSlug := r.PathValue("job")
	existing, err := s.db.GetScheduledJob(r.Context(), projectSlug, jobSlug)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scheduled job not found"})
		return
	}
	var req scheduledJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	var in db.UpdateScheduledJobInput

	if name := strings.TrimSpace(req.Name); name != "" {
		in.Name = &name
	}
	// Schedule / timezone are coupled: recompute next_run_at when either
	// changes so the new cadence takes effect immediately.
	schedule := existing.Schedule
	timezone := existing.Timezone
	scheduleChanged := false
	if strings.TrimSpace(req.Schedule) != "" && strings.TrimSpace(req.Schedule) != existing.Schedule {
		schedule = strings.TrimSpace(req.Schedule)
		scheduleChanged = true
	}
	if strings.TrimSpace(req.Timezone) != "" && strings.TrimSpace(req.Timezone) != existing.Timezone {
		timezone = strings.TrimSpace(req.Timezone)
		scheduleChanged = true
	}
	if scheduleChanged {
		if err := scheduler.ValidateSchedule(schedule, timezone); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		next, _ := scheduler.NextRun(schedule, timezone, time.Now())
		in.Schedule = &schedule
		in.Timezone = &timezone
		in.NextRunAt = &next
	}
	if req.Command != nil {
		in.Command = &req.Command
	}
	if strings.TrimSpace(req.ExecMode) != "" {
		execMode, ok := normExecMode(req.ExecMode)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "exec_mode must be 'run' or 'exec'"})
			return
		}
		in.ExecMode = &execMode
	}
	if strings.TrimSpace(req.ConcurrencyPolicy) != "" {
		policy, ok := normConcurrency(req.ConcurrencyPolicy)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "concurrency_policy must be 'forbid' or 'allow'"})
			return
		}
		in.ConcurrencyPolicy = &policy
	}
	if req.TimeoutSeconds > 0 {
		timeout := req.TimeoutSeconds
		if timeout > 86400 {
			timeout = 86400
		}
		in.TimeoutSeconds = &timeout
	}
	if req.Enabled != nil {
		in.Enabled = req.Enabled
	}
	job, err := s.db.UpdateScheduledJob(r.Context(), projectSlug, jobSlug, in)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "scheduled_job.update", "scheduled_job", projectSlug+"/"+jobSlug, map[string]any{"schedule_changed": scheduleChanged})
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleDeleteScheduledJob(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	jobSlug := r.PathValue("job")
	if err := s.db.DeleteScheduledJob(r.Context(), projectSlug, jobSlug); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scheduled job not found"})
		return
	}
	s.auditLog(r, "scheduled_job.delete", "scheduled_job", projectSlug+"/"+jobSlug, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleSetScheduledJobEnabled toggles a job. Enabling realigns next_run_at
// to the next future boundary so a long-disabled job doesn't fire a stale
// catch-up the instant it's switched back on.
func (s *Server) handleSetScheduledJobEnabled(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	jobSlug := r.PathValue("job")
	existing, err := s.db.GetScheduledJob(r.Context(), projectSlug, jobSlug)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scheduled job not found"})
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	in := db.UpdateScheduledJobInput{Enabled: &req.Enabled}
	if req.Enabled {
		if next, nerr := scheduler.NextRun(existing.Schedule, existing.Timezone, time.Now()); nerr == nil {
			in.NextRunAt = &next
		}
	}
	job, err := s.db.UpdateScheduledJob(r.Context(), projectSlug, jobSlug, in)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "scheduled_job.enable", "scheduled_job", projectSlug+"/"+jobSlug, map[string]any{"enabled": req.Enabled})
	writeJSON(w, http.StatusOK, job)
}

// handleTriggerJobRun enqueues a manual run that the deployer claims like
// any scheduled one. Manual runs bypass the (job_id, scheduled_for)
// uniqueness so repeated clicks each enqueue a fresh run.
func (s *Server) handleTriggerJobRun(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	jobSlug := r.PathValue("job")
	job, err := s.db.GetScheduledJob(r.Context(), projectSlug, jobSlug)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scheduled job not found"})
		return
	}
	if _, err := s.db.EnqueueJobRun(r.Context(), job.ID, job.AgentID, time.Now(), "manual"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "scheduled_job.run", "scheduled_job", projectSlug+"/"+jobSlug, nil)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "enqueued"})
}

func (s *Server) handleListJobRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := s.db.ListJobRuns(r.Context(), r.PathValue("slug"), r.PathValue("job"), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if runs == nil {
		runs = []db.ScheduledJobRun{}
	}
	writeJSON(w, http.StatusOK, runs)
}
