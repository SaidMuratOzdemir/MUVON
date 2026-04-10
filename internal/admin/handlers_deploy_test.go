package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestValidDeploySignature(t *testing.T) {
	payload := []byte(`{"project":"cevik","release_id":"abc"}`)
	secret := "deploy-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !validDeploySignature(payload, secret, signature) {
		t.Fatal("expected signature to validate")
	}
	if !validDeploySignature(payload, secret, signature, "") {
		t.Fatal("expected signature to validate when one of multiple headers is valid")
	}
	if validDeploySignature(payload, secret, "sha256=bad") {
		t.Fatal("expected invalid signature to fail")
	}
}

func TestParseDeployRequestDefaultsReleaseIDFromCommit(t *testing.T) {
	req, err := parseDeployRequest([]byte(`{
		"project":"cevik",
		"commit_sha":"abcdef",
		"components":{"backend":{"image_ref":"ghcr.io/example/backend:abcdef"}}
	}`))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	if req.ReleaseID != "abcdef" {
		t.Fatalf("expected release id from commit sha, got %q", req.ReleaseID)
	}
}
