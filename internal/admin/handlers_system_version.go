package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"muvon/internal/version"
)

// System version endpoints — operator-facing "what's running vs what's
// available" comparison that powers the Settings → Sistem upgrade UI.

type systemVersionResponse struct {
	// Running is the value compiled into this binary (set via ldflags).
	// Includes the short git SHA when available, e.g. "v0.1.0 (2cdaf07)".
	Running string `json:"running"`
	// Raw exposes the bare Version string without the commit suffix so
	// the UI can parse semver components for the tag selector.
	Tag string `json:"tag"`
}

func (s *Server) handleSystemVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, systemVersionResponse{
		Running: version.String(),
		Tag:     version.Version,
	})
}

// latestVersionResponse is what the UI shows for "available on the
// registry". We deliberately keep both the human-friendly tag *and*
// the immutable digest — digest is the one the operator pins for
// audit, tag is the one they pick from the dropdown.
type latestVersionResponse struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
	// FetchedAt is when this row was last pulled from GHCR — cached for
	// 5 minutes so opening the Settings page doesn't hammer the registry.
	FetchedAt string `json:"fetched_at"`
	// UpdateAvailable is a derived flag: true iff Digest differs from
	// the running container's image digest. UI uses this for the badge.
	UpdateAvailable bool `json:"update_available"`
	// Error surfaces transient registry failures (rate limit, DNS) so
	// the UI can show a degraded state instead of a misleading "you're
	// up to date" badge.
	Error string `json:"error,omitempty"`
}

// ghcrCache memoises the most recent registry probe. GHCR allows token-
// less reads for public images but each call costs ~300-500ms; caching
// 5 minutes is plenty for "is there a new version" UX.
type ghcrCache struct {
	mu        sync.RWMutex
	tag       string
	digest    string
	fetchedAt time.Time
	lastErr   string
}

var registryCache ghcrCache

const registryCacheTTL = 5 * time.Minute

// imageNameFor maps the service slug to its GHCR image. Hard-coded
// because the operator panel is built into the muvon binary; the agent
// binary has its own (different) self-update path and doesn't reach
// here. Mirrors the matrix in .github/workflows/release.yml.
func imageNameFor(service string) string {
	switch service {
	case "muvon", "dialog-siem", "muvon-deployer", "agent":
		return "ghcr.io/saidmuratozdemir/muvon/" + service
	default:
		return ""
	}
}

// fetchLatestDigest hits GHCR's anonymous manifest endpoint to discover
// the digest the :latest tag currently points at. Public images don't
// need OAuth; we only need a "scope=pull" token from GHCR's token
// service, which is also anonymous.
func fetchLatestDigest(ctx context.Context, service, tag string) (digest string, err error) {
	if tag == "" {
		tag = "latest"
	}
	image := imageNameFor(service)
	if image == "" {
		return "", fmt.Errorf("unknown service %q", service)
	}
	// Strip the registry prefix to get the repo path expected by GHCR.
	// "ghcr.io/saidmuratozdemir/muvon/muvon" → "saidmuratozdemir/muvon/muvon"
	repo := strings.TrimPrefix(image, "ghcr.io/")

	// Step 1: GHCR ister anonim bir token (scope=repository:repo:pull).
	tokenURL := "https://ghcr.io/token?scope=repository:" + repo + ":pull"
	tokReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("ghcr token request: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	tokResp, err := client.Do(tokReq)
	if err != nil {
		return "", fmt.Errorf("ghcr token fetch: %w", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ghcr token status %d", tokResp.StatusCode)
	}
	var tokBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tokBody); err != nil {
		return "", fmt.Errorf("ghcr token decode: %w", err)
	}
	if tokBody.Token == "" {
		return "", fmt.Errorf("ghcr token empty")
	}

	// Step 2: manifest HEAD — Docker-Content-Digest header'ı immutable
	// content addressini taşır; "v2 manifest" Accept header'ı şart yoksa
	// 404 döner çünkü GHCR default OCI'ye yöneliyor.
	manifestURL := "https://ghcr.io/v2/" + repo + "/manifests/" + tag
	mfReq, err := http.NewRequestWithContext(ctx, http.MethodHead, manifestURL, nil)
	if err != nil {
		return "", fmt.Errorf("manifest request: %w", err)
	}
	mfReq.Header.Set("Authorization", "Bearer "+tokBody.Token)
	mfReq.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))
	mfResp, err := client.Do(mfReq)
	if err != nil {
		return "", fmt.Errorf("manifest fetch: %w", err)
	}
	defer mfResp.Body.Close()
	if mfResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("manifest status %d", mfResp.StatusCode)
	}
	d := mfResp.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", fmt.Errorf("manifest missing Docker-Content-Digest header")
	}
	return d, nil
}

// runningImageDigest tries to extract the digest of the image the muvon
// container is currently running. Best-effort: we ask the deployer
// gRPC client (which already has Docker socket access) for the muvon
// container's image ID. When the deployer is unreachable we return ""
// — the UI degrades gracefully ("update_available" becomes "unknown").
func (s *Server) runningImageDigest(ctx context.Context) string {
	if s.deployerClient == nil {
		return ""
	}
	d, err := s.deployerClient.SelfImageDigest(ctx)
	if err != nil {
		return ""
	}
	return d
}

func (s *Server) handleSystemVersionLatest(w http.ResponseWriter, r *http.Request) {
	// Cache hit?
	registryCache.mu.RLock()
	if time.Since(registryCache.fetchedAt) < registryCacheTTL && registryCache.digest != "" {
		cached := latestVersionResponse{
			Tag:       registryCache.tag,
			Digest:    registryCache.digest,
			FetchedAt: registryCache.fetchedAt.UTC().Format(time.RFC3339),
		}
		registryCache.mu.RUnlock()
		// Compare against running digest fresh — host swap shouldn't
		// be hidden behind the cache.
		running := s.runningImageDigest(r.Context())
		cached.UpdateAvailable = running != "" && running != cached.Digest
		writeJSON(w, http.StatusOK, cached)
		return
	}
	registryCache.mu.RUnlock()

	// Cache miss — hit GHCR.
	// Bound the request so a slow registry doesn't tie up the admin
	// handler indefinitely.
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	digest, err := fetchLatestDigest(ctx, "muvon", "latest")

	registryCache.mu.Lock()
	defer registryCache.mu.Unlock()
	registryCache.fetchedAt = time.Now()
	if err != nil {
		registryCache.lastErr = err.Error()
		writeJSON(w, http.StatusOK, latestVersionResponse{
			Tag:       "latest",
			FetchedAt: registryCache.fetchedAt.UTC().Format(time.RFC3339),
			Error:     err.Error(),
		})
		return
	}
	registryCache.tag = "latest"
	registryCache.digest = digest
	registryCache.lastErr = ""

	running := s.runningImageDigest(r.Context())
	writeJSON(w, http.StatusOK, latestVersionResponse{
		Tag:             "latest",
		Digest:          digest,
		FetchedAt:       registryCache.fetchedAt.UTC().Format(time.RFC3339),
		UpdateAvailable: running != "" && running != digest,
	})
}
