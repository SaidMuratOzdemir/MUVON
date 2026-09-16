package agentctrl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPollRecognisesARevokedKey(t *testing.T) {
	for _, tc := range []struct {
		body    string
		revoked bool
	}{
		{`{"error":"agent revoked"}`, true},
		{`{"error":"invalid api key"}`, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, tc.body, http.StatusUnauthorized)
		}))
		c := NewPollClient(srv.URL, "key", []byte("signing-key"), NewRegistry(10))
		_, status, err := c.pollOnce(context.Background())
		srv.Close()
		if status != http.StatusUnauthorized || err == nil {
			t.Fatalf("%s: status %d err %v, want 401 with an error", tc.body, status, err)
		}
		if errors.Is(err, ErrRevoked) != tc.revoked {
			t.Fatalf("%s: revoked = %v, want %v", tc.body, errors.Is(err, ErrRevoked), tc.revoked)
		}
	}
}
