package agentsvc

import (
	"context"
	"testing"
	"time"
)

func TestSessionsCloseEndsOpenRequests(t *testing.T) {
	var s sessions
	ctx, done := s.start(context.Background(), "a1", time.Now())
	defer done()
	other, otherDone := s.start(context.Background(), "a2", time.Now())
	defer otherDone()

	if n := s.close("a1"); n != 1 {
		t.Fatalf("close ended %d requests, want 1", n)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("request of the closed agent is still running")
	}
	if other.Err() != nil {
		t.Fatal("closing one agent ended another agent's request")
	}
}

// A request whose key was looked up before the close may have read the row
// before the revocation committed, so it must not start.
func TestSessionsRefuseRequestsAdmittedBeforeClose(t *testing.T) {
	var s sessions
	admitted := time.Now()
	s.close("a1")

	ctx, done := s.start(context.Background(), "a1", admitted)
	defer done()
	if ctx.Err() == nil {
		t.Fatal("request admitted before the close was allowed to run")
	}

	later, laterDone := s.start(context.Background(), "a1", time.Now().Add(time.Millisecond))
	defer laterDone()
	if later.Err() != nil {
		t.Fatal("request admitted after the close was refused")
	}
}

func TestSessionsFinishedRequestIsForgotten(t *testing.T) {
	var s sessions
	_, done := s.start(context.Background(), "a1", time.Now())
	done()
	if n := s.close("a1"); n != 0 {
		t.Fatalf("close found %d requests after they finished, want 0", n)
	}
}
