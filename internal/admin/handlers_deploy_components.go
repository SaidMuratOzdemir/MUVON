package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"muvon/internal/db"
	"muvon/internal/secret"
)

// validSlug accepts lowercase alphanumerics, hyphens and underscores.
// Slugs travel through URLs and Docker labels — keeping them strict
// prevents shell escaping surprises in the deployer.
var validSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$|^[a-z0-9]$`)

const envSecretMask = "********"

// generateWebhookSecret returns a hex-encoded 32-byte random string.
// Used for CI/CD HMAC signature verification when a project is created
// without an explicit secret.
func generateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// maskComponentSecrets masks the value of every key listed in
// EnvSecretKeys with a fixed placeholder, so API responses never leak
// ciphertext or plaintext for secret env vars.
func maskComponentSecrets(c db.DeployComponent) db.DeployComponent {
	if len(c.EnvSecretKeys) == 0 || len(c.Env) == 0 {
		return c
	}
	out := make(map[string]string, len(c.Env))
	secretSet := make(map[string]struct{}, len(c.EnvSecretKeys))
	for _, k := range c.EnvSecretKeys {
		secretSet[k] = struct{}{}
	}
	for k, v := range c.Env {
		if _, ok := secretSet[k]; ok {
			out[k] = envSecretMask
		} else {
			out[k] = v
		}
	}
	c.Env = out
	return c
}

// encryptComponentEnv walks the requested env map and encrypts the
// values of keys listed in secretKeys. Already-encrypted ("enc:") values
// pass through. For update flows, the mask placeholder means "keep the
// existing ciphertext" — callers pre-merge it with the existing record.
func (s *Server) encryptComponentEnv(env map[string]string, secretKeys []string) (map[string]string, error) {
	if len(env) == 0 {
		return map[string]string{}, nil
	}
	secretSet := make(map[string]struct{}, len(secretKeys))
	for _, k := range secretKeys {
		secretSet[k] = struct{}{}
	}
	out := make(map[string]string, len(env))
	for k, v := range env {
		if _, isSecret := secretSet[k]; !isSecret {
			out[k] = v
			continue
		}
		if secret.IsEncrypted(v) {
			out[k] = v
			continue
		}
		enc, err := s.secretBox.Encrypt(v)
		if err != nil {
			return nil, fmt.Errorf("encrypt env %s: %w", k, err)
		}
		out[k] = enc
	}
	return out, nil
}

// mergeEnvForUpdate keeps the previously-stored ciphertext when the
// client submits the mask placeholder for a secret key. Anything else
// (plaintext, new ciphertext, deleted key) is taken from the request.
func mergeEnvForUpdate(existing, incoming map[string]string, secretKeys []string) map[string]string {
	secretSet := make(map[string]struct{}, len(secretKeys))
	for _, k := range secretKeys {
		secretSet[k] = struct{}{}
	}
	out := make(map[string]string, len(incoming))
	for k, v := range incoming {
		if _, isSecret := secretSet[k]; isSecret && v == envSecretMask {
			if prev, ok := existing[k]; ok {
				out[k] = prev
				continue
			}
		}
		out[k] = v
	}
	return out
}

// componentRequest is the JSON shape accepted by both create and update
// endpoints. Pointer fields let updates omit values to mean "leave as is";
// non-pointer fields are required on create and replaced on update.
type componentRequest struct {
	Slug                    string             `json:"slug"`
	Name                    *string            `json:"name"`
	SourceRepo              *string            `json:"source_repo"`
	ImageRepo               *string            `json:"image_repo"`
	InternalPort            *int               `json:"internal_port"`
	HealthPath              *string            `json:"health_path"`
	HealthExpectedStatus    *int               `json:"health_expected_status"`
	MigrationCommand        *[]string          `json:"migration_command"`
	RestartRetries          *int               `json:"restart_retries"`
	DrainTimeoutSeconds     *int               `json:"drain_timeout_seconds"`
	LongDrainTimeoutSeconds *int               `json:"long_drain_timeout_seconds"`
	Networks                *[]string          `json:"networks"`
	EnvFilePath             *string            `json:"env_file_path"`
	Env                     *map[string]string `json:"env"`
	EnvSecretKeys           *[]string          `json:"env_secret_keys"`
	Mounts                  *[]db.Mount        `json:"mounts"`
	IsRoutable              *bool              `json:"is_routable"`
	// KeepReleases bounds how many recent succeeded releases keep their
	// images on the host (default 3 from the SQL DEFAULT). Min 1, max 50
	// — beyond that the disk savings invert and inspection gets painful.
	KeepReleases *int `json:"keep_releases"`
}

func validateComponentForCreate(req componentRequest) error {
	if !validSlug.MatchString(req.Slug) {
		return errors.New("slug must be lowercase alphanumerics (with - or _), 1–64 chars")
	}
	if req.Name == nil || strings.TrimSpace(*req.Name) == "" {
		return errors.New("name is required")
	}
	if req.ImageRepo == nil || strings.TrimSpace(*req.ImageRepo) == "" {
		return errors.New("image_repo is required")
	}
	if req.InternalPort == nil || *req.InternalPort <= 0 || *req.InternalPort > 65535 {
		return errors.New("internal_port must be between 1 and 65535")
	}
	if req.KeepReleases != nil && (*req.KeepReleases < 1 || *req.KeepReleases > 50) {
		return errors.New("keep_releases must be between 1 and 50")
	}
	return nil
}

// buildComponentInput fills a DeployComponentInput from a request,
// substituting fields from base whenever the request omits them. Used
// by both Create (base is the zero value with sensible defaults) and
// Update (base is the existing record).
func buildComponentInput(req componentRequest, base db.DeployComponent, projectID int) db.DeployComponentInput {
	in := db.DeployComponentInput{
		ProjectID:               projectID,
		Slug:                    req.Slug,
		Name:                    base.Name,
		SourceRepo:              base.SourceRepo,
		ImageRepo:               base.ImageRepo,
		InternalPort:            base.InternalPort,
		HealthPath:              base.HealthPath,
		HealthExpectedStatus:    base.HealthExpectedStatus,
		MigrationCommand:        base.MigrationCommand,
		RestartRetries:          base.RestartRetries,
		DrainTimeoutSeconds:     base.DrainTimeoutSeconds,
		LongDrainTimeoutSeconds: base.LongDrainTimeoutSeconds,
		Networks:                base.Networks,
		EnvFilePath:             base.EnvFilePath,
		Env:                     base.Env,
		EnvSecretKeys:           base.EnvSecretKeys,
		Mounts:                  base.Mounts,
		IsRoutable:              base.IsRoutable,
		AgentID:                 base.AgentID,
		Paused:                  base.Paused,
		KeepReleases:            base.KeepReleases,
	}
	if req.Name != nil {
		in.Name = strings.TrimSpace(*req.Name)
	}
	if req.SourceRepo != nil {
		in.SourceRepo = strings.TrimSpace(*req.SourceRepo)
	}
	if req.ImageRepo != nil {
		in.ImageRepo = strings.TrimSpace(*req.ImageRepo)
	}
	if req.InternalPort != nil {
		in.InternalPort = *req.InternalPort
	}
	if req.HealthPath != nil {
		in.HealthPath = *req.HealthPath
	}
	if req.HealthExpectedStatus != nil {
		in.HealthExpectedStatus = *req.HealthExpectedStatus
	}
	if req.MigrationCommand != nil {
		in.MigrationCommand = *req.MigrationCommand
	}
	if req.RestartRetries != nil {
		in.RestartRetries = *req.RestartRetries
	}
	if req.DrainTimeoutSeconds != nil {
		in.DrainTimeoutSeconds = *req.DrainTimeoutSeconds
	}
	if req.LongDrainTimeoutSeconds != nil {
		in.LongDrainTimeoutSeconds = *req.LongDrainTimeoutSeconds
	}
	if req.Networks != nil {
		in.Networks = *req.Networks
	}
	if req.EnvFilePath != nil {
		in.EnvFilePath = strings.TrimSpace(*req.EnvFilePath)
	}
	if req.Env != nil {
		in.Env = *req.Env
	}
	if req.EnvSecretKeys != nil {
		in.EnvSecretKeys = *req.EnvSecretKeys
	}
	if req.Mounts != nil {
		in.Mounts = *req.Mounts
	}
	if req.IsRoutable != nil {
		in.IsRoutable = *req.IsRoutable
	}
	if req.KeepReleases != nil {
		in.KeepReleases = *req.KeepReleases
	}
	return in
}

// componentDefaults returns the zero-value record used as the "base"
// when creating. Mirrors the SQL DEFAULTs so partial create requests
// behave the same as an INSERT that didn't list optional columns.
func componentDefaults() db.DeployComponent {
	return db.DeployComponent{
		HealthPath:              "/",
		HealthExpectedStatus:    200,
		RestartRetries:          1,
		DrainTimeoutSeconds:     30,
		LongDrainTimeoutSeconds: 300,
		MigrationCommand:        []string{},
		Networks:                []string{},
		Env:                     map[string]string{},
		EnvSecretKeys:           []string{},
		Mounts:                  []db.Mount{},
		IsRoutable:              true,
		KeepReleases:            3,
	}
}

// ── Project handlers ──

func (s *Server) handleCreateDeployProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Slug          string `json:"slug"`
		Name          string `json:"name"`
		SourceRepo    string `json:"source_repo"`
		WebhookSecret string `json:"webhook_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	req.Name = strings.TrimSpace(req.Name)
	if !validSlug.MatchString(req.Slug) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug must be lowercase alphanumerics (with - or _), 1–64 chars"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	secret := strings.TrimSpace(req.WebhookSecret)
	if secret == "" {
		gen, err := generateWebhookSecret()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate webhook secret"})
			return
		}
		secret = gen
	}
	project, err := s.db.CreateDeployProject(r.Context(), req.Slug, req.Name, strings.TrimSpace(req.SourceRepo), secret)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a deploy project with this slug already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "deploy_project.create", "deploy_project", project.Slug, map[string]any{"name": project.Name, "source_repo": project.SourceRepo})
	writeJSON(w, http.StatusCreated, project)
}

func (s *Server) handleDeleteDeployProject(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if err := s.db.DeleteDeployProject(r.Context(), slug); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "deploy project not found"})
		return
	}
	s.auditLog(r, "deploy_project.delete", "deploy_project", slug, nil)
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "deploy project deleted but config reload failed: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Component handlers ──

func (s *Server) handleGetDeployComponent(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	componentSlug := r.PathValue("component")
	c, err := s.db.GetDeployComponent(r.Context(), projectSlug, componentSlug)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "component not found"})
		return
	}
	writeJSON(w, http.StatusOK, maskComponentSecrets(c))
}

func (s *Server) handleCreateDeployComponent(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	project, err := s.db.GetDeployProjectBySlug(r.Context(), projectSlug)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "deploy project not found"})
		return
	}
	var req componentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if err := validateComponentForCreate(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	in := buildComponentInput(req, componentDefaults(), project.ID)
	encrypted, err := s.encryptComponentEnv(in.Env, in.EnvSecretKeys)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	in.Env = encrypted
	c, err := s.db.CreateDeployComponent(r.Context(), in)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a component with this slug already exists in this project"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "deploy_component.create", "deploy_component", fmt.Sprintf("%s/%s", projectSlug, c.Slug), map[string]any{"project": projectSlug, "image_repo": c.ImageRepo})
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "component created but config reload failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, maskComponentSecrets(c))
}

func (s *Server) handleUpdateDeployComponent(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	componentSlug := r.PathValue("component")
	existing, err := s.db.GetDeployComponent(r.Context(), projectSlug, componentSlug)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "component not found"})
		return
	}
	var req componentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	// Update never reassigns the slug — path is the source of truth.
	req.Slug = existing.Slug
	in := buildComponentInput(req, existing, existing.ProjectID)
	// Preserve existing ciphertext when the UI submits the mask for a
	// still-secret key. The user only re-enters secrets they want to rotate.
	in.Env = mergeEnvForUpdate(existing.Env, in.Env, existing.EnvSecretKeys)
	encrypted, err := s.encryptComponentEnv(in.Env, in.EnvSecretKeys)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	in.Env = encrypted
	c, err := s.db.UpdateDeployComponent(r.Context(), projectSlug, componentSlug, in)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "deploy_component.update", "deploy_component", fmt.Sprintf("%s/%s", projectSlug, componentSlug), map[string]any{"image_repo": c.ImageRepo})
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "component updated but config reload failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, maskComponentSecrets(c))
}

func (s *Server) handleDeleteDeployComponent(w http.ResponseWriter, r *http.Request) {
	projectSlug := r.PathValue("slug")
	componentSlug := r.PathValue("component")
	if err := s.db.DeleteDeployComponent(r.Context(), projectSlug, componentSlug); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "component not found"})
		return
	}
	s.auditLog(r, "deploy_component.delete", "deploy_component", fmt.Sprintf("%s/%s", projectSlug, componentSlug), nil)
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "component deleted but config reload failed: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
