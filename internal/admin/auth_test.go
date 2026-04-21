package admin

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestAccessTokenRoundTrip(t *testing.T) {
	a := NewAuth("test-secret-do-not-use")
	tok, exp, err := a.GenerateAccessToken(42, "alice", 3)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if time.Until(exp) > accessTokenTTL+time.Second || time.Until(exp) < accessTokenTTL-time.Second {
		t.Fatalf("expiration outside expected window: %v", time.Until(exp))
	}
	claims, err := a.ValidateAccessToken(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.UserID != 42 || claims.Username != "alice" || claims.TokenVersion != 3 {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestAccessTokenRejectsTamperedSignature(t *testing.T) {
	a := NewAuth("real-secret")
	tok, _, err := a.GenerateAccessToken(1, "bob", 0)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Flip the last character of the signature.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a valid JWT")
	}
	bad := parts[0] + "." + parts[1] + "." + flipLast(parts[2])

	b := NewAuth("real-secret")
	if _, err := b.ValidateAccessToken(bad); err == nil {
		t.Fatal("expected tampered token to fail validation")
	}
}

func TestAccessTokenRejectsWrongSecret(t *testing.T) {
	a := NewAuth("secret-one")
	tok, _, err := a.GenerateAccessToken(1, "bob", 0)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b := NewAuth("secret-two")
	if _, err := b.ValidateAccessToken(tok); err == nil {
		t.Fatal("expected different secret to fail validation")
	}
}

func TestGenerateRefreshTokenIsUniqueAndLongEnough(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		tok, hash, err := GenerateRefreshToken()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(tok) < 40 {
			t.Fatalf("token looks too short (%d chars)", len(tok))
		}
		if seen[tok] {
			t.Fatalf("duplicate token in 100 iterations: %s", tok)
		}
		seen[tok] = true
		if len(hash) != 32 {
			t.Fatalf("hash length = %d, want 32 (sha256)", len(hash))
		}
	}
}

func TestHashRefreshTokenIsDeterministic(t *testing.T) {
	tok, hash, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	again := HashRefreshToken(tok)
	if !bytes.Equal(hash, again) {
		t.Fatal("HashRefreshToken must be deterministic for the same input")
	}
	different := HashRefreshToken(tok + "x")
	if bytes.Equal(hash, different) {
		t.Fatal("HashRefreshToken must change with input")
	}
}

func TestCSRFTokenUniqueness(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		tok, err := generateCSRFToken()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(tok) < 40 {
			t.Fatalf("csrf token too short: %s", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate csrf token")
		}
		seen[tok] = true
	}
}

func flipLast(s string) string {
	if s == "" {
		return s
	}
	last := s[len(s)-1]
	var repl byte = 'A'
	if last == 'A' {
		repl = 'B'
	}
	return s[:len(s)-1] + string(repl)
}
