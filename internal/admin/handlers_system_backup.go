package admin

import (
	"net/http"
	"strconv"
	"time"
)

// Backups on demand. Until this existed the only way to get one was to start
// a system upgrade, so a backup could not be taken before risky work unless
// that work happened to be an upgrade.
//
//	POST /api/system/backup   → take one now (CSRF-protected, audited)
//	GET  /api/system/backups  → what is on disk

type backupResponse struct {
	Path      string `json:"path"`
	Bytes     int64  `json:"bytes"`
	CreatedAt string `json:"created_at"`
	// Verified reports that pg_restore -l read the finished archive. When it
	// is false the file was still written, but nothing has confirmed it can
	// be restored, and Note says why.
	Verified bool   `json:"verified"`
	Note     string `json:"note,omitempty"`
}

type backupListItem struct {
	Name      string `json:"name"`
	Bytes     int64  `json:"bytes"`
	CreatedAt string `json:"created_at"`
}

type backupListResponse struct {
	Backups []backupListItem `json:"backups"`
	// KeepLimit is how many are retained, so the panel can explain where the
	// older ones went instead of leaving it a mystery.
	KeepLimit int `json:"keep_limit"`
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	if s.deployerClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "deployer unavailable: backups run inside muvon-deployer, which owns the Docker socket",
		})
		return
	}

	start := time.Now()
	resp, err := s.deployerClient.CreateBackup(r.Context())
	if err != nil {
		s.auditLog(r, "create_backup", "system", "backup", map[string]string{"result": "failed", "error": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.auditLog(r, "create_backup", "system", resp.GetPath(), map[string]string{
		"bytes":       strconv.FormatInt(resp.GetBytes(), 10),
		"verified":    strconv.FormatBool(resp.GetVerified()),
		"duration_ms": strconv.FormatInt(time.Since(start).Milliseconds(), 10),
	})
	writeJSON(w, http.StatusOK, backupResponse{
		Path:      resp.GetPath(),
		Bytes:     resp.GetBytes(),
		CreatedAt: resp.GetCreatedAt(),
		Verified:  resp.GetVerified(),
		Note:      resp.GetNote(),
	})
}

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	if s.deployerClient == nil {
		writeJSON(w, http.StatusOK, backupListResponse{Backups: []backupListItem{}})
		return
	}
	resp, err := s.deployerClient.ListBackups(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, backupListResponse{Backups: []backupListItem{}})
		return
	}
	out := backupListResponse{
		Backups:   make([]backupListItem, 0, len(resp.GetBackups())),
		KeepLimit: int(resp.GetKeepLimit()),
	}
	for _, b := range resp.GetBackups() {
		out.Backups = append(out.Backups, backupListItem{
			Name:      b.GetName(),
			Bytes:     b.GetBytes(),
			CreatedAt: b.GetCreatedAt(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
