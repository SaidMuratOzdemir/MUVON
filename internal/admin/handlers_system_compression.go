package admin

import (
	"net/http"

	"muvon/internal/db"
)

// Compression read-back, the twin of the retention one: the settings rows
// state intent, Timescale's job catalog states what is enforced, and diaLOG
// reconciles the two. The panel shows the catalog so the input box can never
// imply a window that is not installed.

type compressionStatusResponse struct {
	// SettingDays and SettingBodiesDays are the operator's intent from
	// muvon.settings. Bodies carry their own value because compressing that
	// table is what stops body search from using its trigram indexes.
	SettingDays       int `json:"setting_days"`
	SettingBodiesDays int `json:"setting_bodies_days"`
	// Policies is what Timescale enforces per hypertable right now, with the
	// chunk counts that say how much is already columnar.
	Policies []db.CompressionPolicy `json:"policies"`
	// InSync is false while diaLOG has not applied the settings yet, or
	// cannot. Either way the operator needs to see it rather than assume.
	InSync bool `json:"in_sync"`
	// Unavailable reports that the catalog could not be read at all, which on
	// a MUVON-only install is expected.
	Unavailable bool   `json:"unavailable,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (s *Server) handleCompressionStatus(w http.ResponseWriter, r *http.Request) {
	g := s.configHolder.Get().Global
	resp := compressionStatusResponse{
		SettingDays:       g.CompressionDays,
		SettingBodiesDays: g.CompressionBodiesDays,
	}

	policies, err := s.db.GetCompressionPolicies(r.Context())
	if err != nil {
		resp.Unavailable = true
		resp.Error = err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp.Policies = policies
	resp.InSync = len(policies) > 0
	for _, p := range policies {
		want := resp.SettingDays
		if p.Table == db.BodiesTable {
			want = resp.SettingBodiesDays
		}
		enforced := 0
		if p.HasPolicy {
			enforced = p.Days
		}
		if enforced != want {
			resp.InSync = false
			break
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
