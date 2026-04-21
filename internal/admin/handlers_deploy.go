package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"muvon/internal/db"
)

type deployRequest struct {
	Project    string                          `json:"project"`
	ReleaseID  string                          `json:"release_id"`
	Repo       string                          `json:"repo"`
	Branch     string                          `json:"branch"`
	CommitSHA  string                          `json:"commit_sha"`
	Components map[string]deployComponentInput `json:"components"`
}

type deployComponentInput struct {
	ImageRef    string `json:"image_ref"`
	ImageDigest string `json:"image_digest"`
}

func (s *Server) handleDeployWebhook(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload too large or unreadable"})
		return
	}

	req, err := parseDeployRequest(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	project, err := s.db.GetDeployProjectBySlug(r.Context(), req.Project)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "deploy project not found"})
		return
	}
	if project.WebhookSecret == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "deploy project has no webhook secret configured"})
		return
	}
	if !validDeploySignature(raw, project.WebhookSecret, r.Header.Get("X-Muvon-Signature-256"), r.Header.Get("X-Hub-Signature-256")) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid deploy signature"})
		return
	}

	deployment, idempotent, err := s.enqueueDeployRequest(r, req, raw, "webhook")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	status := http.StatusAccepted
	if idempotent {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"deployment": deployment, "idempotent": idempotent})
}

func (s *Server) handleListDeployProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.db.ListDeployProjects(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if projects == nil {
		projects = []db.DeployProjectSummary{}
	}
	writeJSON(w, http.StatusOK, projects)
}

func (s *Server) handleUpdateDeployProject(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	existing, err := s.db.GetDeployProjectBySlug(r.Context(), slug)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "deploy project not found"})
		return
	}
	var req struct {
		Name          *string `json:"name"`
		SourceRepo    *string `json:"source_repo"`
		WebhookSecret *string `json:"webhook_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	name := existing.Name
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	sourceRepo := existing.SourceRepo
	if req.SourceRepo != nil {
		sourceRepo = strings.TrimSpace(*req.SourceRepo)
	}
	webhookSecret := existing.WebhookSecret
	if req.WebhookSecret != nil {
		webhookSecret = *req.WebhookSecret
	}
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	updated, err := s.db.UpdateDeployProject(r.Context(), slug, name, sourceRepo, webhookSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "deploy_project.update", "deploy_project", slug, map[string]any{"name": name, "source_repo": sourceRepo, "webhook_secret_changed": req.WebhookSecret != nil})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleListDeployments(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	deployments, err := s.db.ListDeployments(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if deployments == nil {
		deployments = []db.Deployment{}
	}
	writeJSON(w, http.StatusOK, deployments)
}

func (s *Server) handleListDeploymentEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	events, err := s.db.ListDeploymentEvents(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = []db.DeploymentEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleManualDeploy(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload too large or unreadable"})
		return
	}
	req, err := parseDeployRequest(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Project == "" {
		req.Project = projectSlug
	}
	if req.Project != projectSlug {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "project in URL and body do not match"})
		return
	}
	normalized, _ := json.Marshal(req)
	deployment, idempotent, err := s.enqueueDeployRequest(r, req, normalized, "manual")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "deployment.enqueue", "deployment", deployment.ID, map[string]any{"project": req.Project, "release_id": req.ReleaseID, "idempotent": idempotent})
	writeJSON(w, http.StatusAccepted, map[string]any{"deployment": deployment, "idempotent": idempotent})
}

func (s *Server) handleGetDeployProjectSecret(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	project, err := s.db.GetDeployProjectBySlug(r.Context(), slug)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": project.WebhookSecret})
}

func (s *Server) handleRerunDeployment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dep, err := s.db.GetDeployment(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "deployment not found"})
		return
	}
	req, err := parseDeployRequest(dep.Payload)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "original payload is malformed: " + err.Error()})
		return
	}
	req.Project = dep.ProjectSlug
	normalized, _ := json.Marshal(req)
	deployment, idempotent, err := s.enqueueDeployRequest(r, req, normalized, "manual")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "deployment.rerun", "deployment", deployment.ID, map[string]any{"original_id": id, "project": req.Project, "release_id": req.ReleaseID, "idempotent": idempotent})
	writeJSON(w, http.StatusAccepted, map[string]any{"deployment": deployment, "idempotent": idempotent})
}

func parseDeployRequest(raw []byte) (deployRequest, error) {
	var req deployRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, fmt.Errorf("invalid JSON")
	}
	req.Project = strings.TrimSpace(req.Project)
	req.ReleaseID = strings.TrimSpace(req.ReleaseID)
	req.Repo = strings.TrimSpace(req.Repo)
	req.Branch = strings.TrimSpace(req.Branch)
	req.CommitSHA = strings.TrimSpace(req.CommitSHA)
	if req.Project == "" {
		return req, fmt.Errorf("project is required")
	}
	if req.ReleaseID == "" {
		req.ReleaseID = req.CommitSHA
	}
	if req.ReleaseID == "" {
		return req, fmt.Errorf("release_id or commit_sha is required")
	}
	if len(req.Components) == 0 {
		return req, fmt.Errorf("at least one component image is required")
	}
	for slug, component := range req.Components {
		if strings.TrimSpace(slug) == "" {
			return req, fmt.Errorf("component slug is required")
		}
		if strings.TrimSpace(component.ImageRef) == "" {
			return req, fmt.Errorf("image_ref is required for component %s", slug)
		}
	}
	return req, nil
}

func (s *Server) enqueueDeployRequest(r *http.Request, req deployRequest, raw []byte, trigger string) (db.Deployment, bool, error) {
	components := make([]db.EnqueueDeploymentComponent, 0, len(req.Components))
	for slug, component := range req.Components {
		components = append(components, db.EnqueueDeploymentComponent{
			Slug:        slug,
			ImageRef:    component.ImageRef,
			ImageDigest: component.ImageDigest,
		})
	}
	return s.db.EnqueueDeployment(r.Context(), db.EnqueueDeploymentInput{
		ProjectSlug: req.Project,
		ReleaseID:   req.ReleaseID,
		Repo:        req.Repo,
		Branch:      req.Branch,
		CommitSHA:   req.CommitSHA,
		Trigger:     trigger,
		Payload:     raw,
		Components:  components,
	})
}

func validDeploySignature(payload []byte, secret string, signatures ...string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	for _, sig := range signatures {
		sig = strings.TrimSpace(sig)
		if sig == "" {
			continue
		}
		if hmac.Equal([]byte(expected), []byte(sig)) {
			return true
		}
		if strings.HasPrefix(sig, "sha256=") {
			continue
		}
		if hmac.Equal([]byte(strings.TrimPrefix(expected, "sha256=")), []byte(sig)) {
			return true
		}
	}
	return false
}
