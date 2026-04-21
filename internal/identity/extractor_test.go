package identity

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func makeToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return "Bearer " + signed
}

func cfg(secret string) Config {
	return Config{
		Enabled: true,
		Secret:  secret,
		Claims:  []string{"sub", "email", "role"},
	}
}

func TestExtractVerifiedTokenPopulatesClaims(t *testing.T) {
	ex := &Extractor{}
	tok := makeToken(t, "s3cret", jwt.MapClaims{
		"sub":   "user-1",
		"email": "a@b.c",
		"role":  "admin",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	id := ex.ExtractFromBearer(tok, cfg("s3cret"))
	if id == nil {
		t.Fatal("expected identity")
	}
	if !id.Verified || id.ExpExpired {
		t.Errorf("expected Verified=true ExpExpired=false, got %+v", id)
	}
	if id.Source != "jwt_verify" {
		t.Errorf("source = %q, want jwt_verify", id.Source)
	}
	if id.Claims["sub"] != "user-1" || id.Claims["email"] != "a@b.c" || id.Claims["role"] != "admin" {
		t.Errorf("claims not extracted: %+v", id.Claims)
	}
}

// An expired token with a valid signature must surface as "signature was
// fine, but the token is stale" — Verified=false so authorization code
// never mistakes it for a live session, but ExpExpired=true so UIs can tell
// this case apart from a forged token.
func TestExtractExpiredVerifiedTokenSurfacesExpired(t *testing.T) {
	ex := &Extractor{}
	tok := makeToken(t, "s3cret", jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	id := ex.ExtractFromBearer(tok, cfg("s3cret"))
	if id == nil {
		t.Fatal("expected identity even when expired")
	}
	if id.Verified {
		t.Error("expired token must not be marked Verified=true")
	}
	if !id.ExpExpired {
		t.Error("expected ExpExpired=true")
	}
	if id.Source != "jwt_expired" {
		t.Errorf("source = %q, want jwt_expired", id.Source)
	}
}

func TestExtractWrongSecretFallsBackToDecode(t *testing.T) {
	ex := &Extractor{}
	tok := makeToken(t, "real-secret", jwt.MapClaims{
		"sub": "user-2",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	id := ex.ExtractFromBearer(tok, cfg("wrong-secret"))
	if id == nil {
		t.Fatal("expected identity from decode fallback")
	}
	if id.Verified {
		t.Error("wrong secret must not verify")
	}
	if id.Source != "jwt_decode" {
		t.Errorf("source = %q, want jwt_decode", id.Source)
	}
	if id.ExpExpired {
		t.Error("unexpired decoded token must not be marked ExpExpired")
	}
}

func TestExtractDisabledReturnsNil(t *testing.T) {
	ex := &Extractor{}
	tok := makeToken(t, "s3cret", jwt.MapClaims{"sub": "u"})
	id := ex.ExtractFromBearer(tok, Config{Enabled: false})
	if id != nil {
		t.Fatal("disabled config should return nil identity")
	}
}

func TestExtractNoBearerPrefixReturnsNil(t *testing.T) {
	ex := &Extractor{}
	id := ex.ExtractFromBearer("NotBearer abc.def.ghi", cfg("s3cret"))
	if id != nil {
		t.Fatal("missing Bearer prefix must produce nil")
	}
}
