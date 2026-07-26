package admin

import (
	"testing"

	"muvon/internal/db"
)

// buildComponentInput must read `paused` from the request body. It previously
// did not (the struct lacked the field), so the pause API silently no-op'd: the
// DB value could never change from its create-time default. These tests pin the
// pointer semantics that fix carries.
func TestBuildComponentInput_PausedPointer(t *testing.T) {
	tru, fls := true, false

	cases := []struct {
		name string
		req  *bool
		base bool
		want bool
	}{
		{"omitted keeps paused", nil, true, true},
		{"omitted keeps running", nil, false, false},
		{"set true pauses a running component", &tru, false, true},
		{"set false resumes a paused component", &fls, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := buildComponentInput(
				componentRequest{Paused: tc.req},
				db.DeployComponent{Paused: tc.base},
				1,
			)
			if in.Paused != tc.want {
				t.Errorf("Paused = %v, want %v", in.Paused, tc.want)
			}
		})
	}
}
