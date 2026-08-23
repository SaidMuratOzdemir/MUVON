package admin

import (
	"testing"

	"muvon/internal/db"
)

// A signed, unexpired token is not sufficient on its own. These cases are the
// reason authMiddleware reads the user row on every request.
func TestSessionAccepted(t *testing.T) {
	cases := []struct {
		name  string
		user  db.AdminUser
		token int
		want  bool
	}{
		{
			name:  "active user, matching version",
			user:  db.AdminUser{IsActive: true, TokenVersion: 3},
			token: 3,
			want:  true,
		},
		{
			name:  "password changed since the token was issued",
			user:  db.AdminUser{IsActive: true, TokenVersion: 4},
			token: 3,
			want:  false,
		},
		{
			name:  "account disabled",
			user:  db.AdminUser{IsActive: false, TokenVersion: 3},
			token: 3,
			want:  false,
		},
		{
			name:  "token from a newer version than the row (rolled back user)",
			user:  db.AdminUser{IsActive: true, TokenVersion: 2},
			token: 3,
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sessionAccepted(tc.user, &Claims{TokenVersion: tc.token})
			if got != tc.want {
				t.Fatalf("sessionAccepted = %v, want %v", got, tc.want)
			}
		})
	}
}

// The version travels in the token, so a password change has to produce a
// token that the old row would reject and the new row accepts.
func TestAccessTokenCarriesTokenVersion(t *testing.T) {
	a := NewAuth("test-secret-do-not-use")

	before, _, err := a.GenerateAccessToken(7, "alice", 1)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	after, _, err := a.GenerateAccessToken(7, "alice", 2)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	oldClaims, err := a.ValidateAccessToken(before)
	if err != nil {
		t.Fatalf("validate old: %v", err)
	}
	newClaims, err := a.ValidateAccessToken(after)
	if err != nil {
		t.Fatalf("validate new: %v", err)
	}

	bumped := db.AdminUser{IsActive: true, TokenVersion: 2}
	if sessionAccepted(bumped, oldClaims) {
		t.Fatal("token issued before the bump is still accepted")
	}
	if !sessionAccepted(bumped, newClaims) {
		t.Fatal("token issued after the bump was rejected")
	}
}
