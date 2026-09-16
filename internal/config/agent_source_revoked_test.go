package config

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"muvon/internal/agentctrl"
)

func centralAnswering(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, body, http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestAgentSourceRecognisesARevokedKey(t *testing.T) {
	src := NewAgentSource(centralAnswering(t, `{"error":"agent revoked"}`), "key")
	if _, err := src.Load(context.Background()); !errors.Is(err, agentctrl.ErrRevoked) {
		t.Fatalf("Load error = %v, want ErrRevoked", err)
	}
	if err := src.watchOnce(context.Background(), func() {}); !errors.Is(err, agentctrl.ErrRevoked) {
		t.Fatalf("watch error = %v, want ErrRevoked", err)
	}
}

// A wrong key is an ordinary failure: it must keep the normal retry pace.
func TestAgentSourceDoesNotMistakeAnUnknownKeyForRevocation(t *testing.T) {
	src := NewAgentSource(centralAnswering(t, `{"error":"invalid api key"}`), "key")
	if _, err := src.Load(context.Background()); err == nil || errors.Is(err, agentctrl.ErrRevoked) {
		t.Fatalf("Load error = %v, want a failure that is not ErrRevoked", err)
	}
	if err := src.watchOnce(context.Background(), func() {}); err == nil || errors.Is(err, agentctrl.ErrRevoked) {
		t.Fatalf("watch error = %v, want a failure that is not ErrRevoked", err)
	}
}
