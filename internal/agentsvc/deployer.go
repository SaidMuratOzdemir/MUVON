package agentsvc

import (
	"encoding/json"
	"net/http"
	"time"

	"muvon/internal/db"
)

// HTTP-backed mirror of internal/deployer.State for agent-side deployers.
// Each handler authenticates via AuthMiddleware (X-Api-Key) and uses the
// agent ID from context as the deployment owner filter.

// writeJSON sends a typed body with the right Content-Type header. The
// admin package has its own copy; duplicating here avoids a cross-package
// import cycle (agentsvc is a dependency of admin, not the other way).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// agentDeployerCtx pulls the agent ID stamped by AuthMiddleware. Bare
// callers without an agent context get rejected by 401 upstream — this
// returns "" so the deployer claim query still composes a valid filter.
func agentDeployerCtx(r *http.Request) string {
	id, _ := r.Context().Value(agentIDKey).(string)
	return id
}

// HandleClaim returns the next pending deployment owned by this agent,
// or 204 No Content when the queue is empty.
// POST /api/v1/agent/deployer/claim
func (s *Service) HandleClaim(w http.ResponseWriter, r *http.Request) {
	agentID := agentDeployerCtx(r)
	dep, ok, err := s.db.ClaimNextDeployment(r.Context(), agentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, dep)
}

// HandleLoadPlan returns everything the deployer needs to execute one
// deployment: the project, the release, and each pending component.
// GET /api/v1/agent/deployer/plan/{id}
func (s *Service) HandleLoadPlan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	plan, err := s.db.LoadDeploymentPlan(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	// Enforce ownership — an agent must not load a plan that belongs to
	// the central deployer or another agent, even if it guesses the ID.
	agentID := agentDeployerCtx(r)
	if plan.Deployment.AgentID != agentID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "deployment is not owned by this agent"})
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// HandleAddEvent records one deployment_events row.
// POST /api/v1/agent/deployer/event
func (s *Service) HandleAddEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeploymentID string          `json:"deployment_id"`
		EventType    string          `json:"event_type"`
		Message      string          `json:"message"`
		Detail       json.RawMessage `json:"detail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !s.agentOwnsDeployment(r, req.DeploymentID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "deployment is not owned by this agent"})
		return
	}
	// AddDeploymentEvent re-marshals the detail; passing the raw bytes
	// through json.RawMessage keeps the shape the agent sent.
	var detail any = req.Detail
	if len(req.Detail) == 0 {
		detail = nil
	}
	if err := s.db.AddDeploymentEvent(r.Context(), req.DeploymentID, req.EventType, req.Message, detail); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleFail flips a deployment to "failed" with an error message.
// POST /api/v1/agent/deployer/fail
func (s *Service) HandleFail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeploymentID string `json:"deployment_id"`
		Message      string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !s.agentOwnsDeployment(r, req.DeploymentID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "deployment is not owned by this agent"})
		return
	}
	if err := s.db.FailDeployment(r.Context(), req.DeploymentID, req.Message); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleCreateInstance records a fresh candidate container.
// POST /api/v1/agent/deployer/instance
func (s *Service) HandleCreateInstance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ComponentID   int    `json:"component_id"`
		ReleaseUUID   string `json:"release_uuid"`
		ContainerID   string `json:"container_id"`
		ContainerName string `json:"container_name"`
		BackendURL    string `json:"backend_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !s.agentOwnsComponent(r, req.ComponentID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "component is not owned by this agent"})
		return
	}
	inst, err := s.db.CreateDeployInstance(r.Context(), req.ComponentID, req.ReleaseUUID, req.ContainerID, req.ContainerName, req.BackendURL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, inst)
}

// HandleInstanceUnhealthy marks an instance unhealthy with a reason.
// POST /api/v1/agent/deployer/instance/unhealthy
func (s *Service) HandleInstanceUnhealthy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InstanceID string `json:"instance_id"`
		Message    string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !s.agentOwnsInstance(r, req.InstanceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "instance is not owned by this agent"})
		return
	}
	if err := s.db.MarkDeployInstanceUnhealthy(r.Context(), req.InstanceID, req.Message); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleInstanceStopped is the final state transition once Docker has
// confirmed a drained container is gone.
// POST /api/v1/agent/deployer/instance/stopped
func (s *Service) HandleInstanceStopped(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InstanceID string `json:"instance_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !s.agentOwnsInstance(r, req.InstanceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "instance is not owned by this agent"})
		return
	}
	if err := s.db.MarkDeployInstanceStopped(r.Context(), req.InstanceID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandlePromote runs the atomic promote transaction.
// POST /api/v1/agent/deployer/promote
func (s *Service) HandlePromote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeploymentID string   `json:"deployment_id"`
		CandidateIDs []string `json:"candidate_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !s.agentOwnsDeployment(r, req.DeploymentID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "deployment is not owned by this agent"})
		return
	}
	if err := s.db.PromoteDeployInstances(r.Context(), req.DeploymentID, req.CandidateIDs); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleResetStaleRunning recovers crash-stuck deployments back to pending.
// POST /api/v1/agent/deployer/reset-stale  body: {older_than_seconds: int}
func (s *Service) HandleResetStaleRunning(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OlderThanSeconds int `json:"older_than_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.OlderThanSeconds < 60 {
		req.OlderThanSeconds = 60
	}
	// Only resets deployments owned by this agent.
	agentID := agentDeployerCtx(r)
	n, err := s.db.ResetStaleRunningDeploymentsForAgent(r.Context(), agentID, time.Duration(req.OlderThanSeconds)*time.Second)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"reset": n})
}

// HandleCleanupStaleWarming releases warming rows attached to deployments
// that have since finished.
// POST /api/v1/agent/deployer/cleanup-warming
func (s *Service) HandleCleanupStaleWarming(w http.ResponseWriter, r *http.Request) {
	agentID := agentDeployerCtx(r)
	n, err := s.db.CleanupStaleWarmingInstancesForAgent(r.Context(), agentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"cleaned": n})
}

// HandleListDrainable returns instances ready to stop.
// GET /api/v1/agent/deployer/drainable
func (s *Service) HandleListDrainable(w http.ResponseWriter, r *http.Request) {
	agentID := agentDeployerCtx(r)
	insts, err := s.db.ListDrainableDeployInstancesForAgent(r.Context(), agentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if insts == nil {
		insts = []db.DeployInstance{}
	}
	writeJSON(w, http.StatusOK, insts)
}

// HandleListLiveContainers returns the set of container IDs the central
// state still considers alive for this agent's components — used by
// dockerwatch / orphan reconcile.
// GET /api/v1/agent/deployer/live-containers
func (s *Service) HandleListLiveContainers(w http.ResponseWriter, r *http.Request) {
	agentID := agentDeployerCtx(r)
	live, err := s.db.ListLiveManagedContainerIDsForAgent(r.Context(), agentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ids := make([]string, 0, len(live))
	for id := range live {
		ids = append(ids, id)
	}
	writeJSON(w, http.StatusOK, map[string][]string{"container_ids": ids})
}

// HandleListPrunableImages returns image refs the edge deployer can drop
// from its local Docker daemon. Ownership is enforced by the SQL: the
// query joins through deploy_components and filters by agent_id, so an
// agent submitting somebody else's component_id gets an empty list.
// POST /api/v1/agent/deployer/prunable-images  body: {component_id, keep_n}
func (s *Service) HandleListPrunableImages(w http.ResponseWriter, r *http.Request) {
	agentID := agentDeployerCtx(r)
	var req struct {
		ComponentID int `json:"component_id"`
		KeepN       int `json:"keep_n"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.ComponentID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "component_id is required"})
		return
	}
	refs, err := s.db.ListPrunableImageRefsForAgent(r.Context(), agentID, req.ComponentID, req.KeepN)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if refs == nil {
		refs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string][]string{"image_refs": refs})
}

// ── Ownership checks ────────────────────────────────────────────────────

func (s *Service) agentOwnsDeployment(r *http.Request, deploymentID string) bool {
	agentID := agentDeployerCtx(r)
	dep, err := s.db.GetDeployment(r.Context(), deploymentID)
	if err != nil {
		return false
	}
	return dep.AgentID == agentID
}

func (s *Service) agentOwnsComponent(r *http.Request, componentID int) bool {
	agentID := agentDeployerCtx(r)
	owner, err := s.db.GetDeployComponentAgentID(r.Context(), componentID)
	if err != nil {
		return false
	}
	return owner == agentID
}

func (s *Service) agentOwnsInstance(r *http.Request, instanceID string) bool {
	agentID := agentDeployerCtx(r)
	owner, err := s.db.GetDeployInstanceAgentID(r.Context(), instanceID)
	if err != nil {
		return false
	}
	return owner == agentID
}
