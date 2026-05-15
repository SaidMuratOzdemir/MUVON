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
	// Tag is the highest semver release tag visible on GitHub (e.g. "v0.1.4").
	Tag string `json:"tag"`
	// Digest of the GHCR :latest image, kept for audit display only —
	// NOT used for UpdateAvailable comparison (two CI runs on the same
	// commit produce different digests, so digest equality is unreliable).
	Digest    string `json:"digest,omitempty"`
	FetchedAt string `json:"fetched_at"`
	// UpdateAvailable: semver(latest) > semver(running).
	UpdateAvailable bool `json:"update_available"`
	// Running is the binary's own ldflags-injected version, echoed back
	// so the UI can render both sides without a separate /version call.
	Running string `json:"running,omitempty"`
	Error   string `json:"error,omitempty"`
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

// fetchLatestSemverTag asks GitHub's anonymous repo-tags API for the
// highest-semver `vX.Y.Z` tag. This is more reliable than reading the
// :latest manifest digest because two CI runs on the same commit (main
// push + tag push) produce different digests, so digest equality
// constantly false-positives "update available".
func fetchLatestSemverTag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/SaidMuratOzdemir/MUVON/tags?per_page=50", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("github tags: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github tags status %d", resp.StatusCode)
	}
	var tags []struct{ Name string }
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("github tags decode: %w", err)
	}
	var best string
	for _, t := range tags {
		if !isStrictSemverTag(t.Name) {
			continue
		}
		if best == "" || compareSemverTags(t.Name, best) > 0 {
			best = t.Name
		}
	}
	if best == "" {
		return "", fmt.Errorf("no semver tags found")
	}
	return best, nil
}

func isStrictSemverTag(s string) bool {
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// compareSemverTags returns negative/zero/positive matching strings.Compare.
// Assumes both inputs already pass isStrictSemverTag.
func compareSemverTags(a, b string) int {
	pa := strings.Split(strings.TrimPrefix(a, "v"), ".")
	pb := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < 3; i++ {
		ai, bi := 0, 0
		fmt.Sscanf(pa[i], "%d", &ai)
		fmt.Sscanf(pb[i], "%d", &bi)
		if ai != bi {
			return ai - bi
		}
	}
	return 0
}

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
	runningTag := version.Version

	// Cache hit?
	registryCache.mu.RLock()
	if time.Since(registryCache.fetchedAt) < registryCacheTTL && registryCache.tag != "" {
		cached := latestVersionResponse{
			Tag:       registryCache.tag,
			Digest:    registryCache.digest,
			FetchedAt: registryCache.fetchedAt.UTC().Format(time.RFC3339),
			Running:   runningTag,
		}
		registryCache.mu.RUnlock()
		cached.UpdateAvailable = semverNewer(cached.Tag, runningTag)
		writeJSON(w, http.StatusOK, cached)
		return
	}
	registryCache.mu.RUnlock()

	// Cache miss — fetch from GitHub Tags API.
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	tag, err := fetchLatestSemverTag(ctx)

	registryCache.mu.Lock()
	defer registryCache.mu.Unlock()
	registryCache.fetchedAt = time.Now()
	if err != nil {
		registryCache.lastErr = err.Error()
		writeJSON(w, http.StatusOK, latestVersionResponse{
			FetchedAt: registryCache.fetchedAt.UTC().Format(time.RFC3339),
			Running:   runningTag,
			Error:     err.Error(),
		})
		return
	}
	// Best-effort: also fetch the :latest manifest digest for display.
	// Failure here doesn't surface as an error to the UI.
	digest, _ := fetchLatestDigest(ctx, "muvon", tag)
	registryCache.tag = tag
	registryCache.digest = digest
	registryCache.lastErr = ""

	writeJSON(w, http.StatusOK, latestVersionResponse{
		Tag:             tag,
		Digest:          digest,
		FetchedAt:       registryCache.fetchedAt.UTC().Format(time.RFC3339),
		Running:         runningTag,
		UpdateAvailable: semverNewer(tag, runningTag),
	})
}

// semverNewer returns true if `latest` is a strictly higher semver
// than `running`. Anything non-semver on either side returns false
// (no false-positive update prompt for `dev`, `latest`, etc.).
func semverNewer(latest, running string) bool {
	if !isStrictSemverTag(latest) || !isStrictSemverTag(running) {
		return false
	}
	return compareSemverTags(latest, running) > 0
}
