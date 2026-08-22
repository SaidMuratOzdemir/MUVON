package admin

import (
	"net/http"

	"muvon/internal/db"
)

// Retention read-back. The settings row states intent; Timescale's job
// catalog states what is actually enforced, and diaLOG is what reconciles
// the two. Exposing the catalog lets the panel show the enforced value
// instead of implying that whatever sits in the input box is in effect.

type retentionStatusResponse struct {
	// SettingDays is the operator's intent from muvon.settings.
	SettingDays int `json:"setting_days"`
	// Policies is what Timescale enforces per hypertable right now.
	Policies []db.RetentionPolicy `json:"policies"`
	// InSync is false while diaLOG has not applied the setting yet, or when
	// it cannot (diaLOG down, apply failing). Either way the operator needs
	// to see it rather than assume.
	InSync bool `json:"in_sync"`
	// Unavailable reports that the policy catalog could not be read at all,
	// which on a MUVON-only install (no diaLOG schema) is expected.
	Unavailable bool   `json:"unavailable,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (s *Server) handleRetentionStatus(w http.ResponseWriter, r *http.Request) {
	resp := retentionStatusResponse{
		SettingDays: s.configHolder.Get().Global.RetentionDays,
	}

	policies, err := s.db.GetRetentionPolicies(r.Context())
	if err != nil {
		resp.Unavailable = true
		resp.Error = err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp.Policies = policies
	resp.InSync = len(policies) > 0
	for _, p := range policies {
		enforced := 0
		if p.HasPolicy {
			enforced = p.Days
		}
		if enforced != resp.SettingDays {
			resp.InSync = false
			break
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
