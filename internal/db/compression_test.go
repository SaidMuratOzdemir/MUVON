package db

import "testing"

func TestPlanCompression(t *testing.T) {
	current := []CompressionPolicy{
		{Table: "http_logs", JobID: 1, Days: 7, HasPolicy: true},
		{Table: "http_log_bodies", JobID: 2, Days: 7, HasPolicy: true},
		{Table: "container_logs", HasPolicy: false},
	}

	t.Run("steady state plans nothing", func(t *testing.T) {
		got := planCompression(current, map[string]int{"http_logs": 7, "http_log_bodies": 7})
		if len(got) != 0 {
			t.Fatalf("expected no actions, got %+v", got)
		}
	})

	t.Run("bodies move independently of the rest", func(t *testing.T) {
		got := planCompression(current, map[string]int{"http_logs": 7, "http_log_bodies": 30})
		if len(got) != 1 {
			t.Fatalf("expected one action, got %+v", got)
		}
		if got[0].Table != "http_log_bodies" || got[0].Verb != compressionAlter || got[0].Days != 30 {
			t.Fatalf("unexpected action %+v", got[0])
		}
		if got[0].JobID != 2 {
			t.Fatalf("alter must keep the job id, got %d", got[0].JobID)
		}
	})

	t.Run("zero removes the policy", func(t *testing.T) {
		got := planCompression(current, map[string]int{"http_log_bodies": 0})
		if len(got) != 1 || got[0].Verb != compressionRemove {
			t.Fatalf("expected a remove, got %+v", got)
		}
	})

	t.Run("a table without a policy gets one", func(t *testing.T) {
		got := planCompression(current, map[string]int{"container_logs": 14})
		if len(got) != 1 || got[0].Verb != compressionAdd || got[0].Days != 14 {
			t.Fatalf("expected an add of 14 days, got %+v", got)
		}
	})

	t.Run("zero on a table that has no policy is already correct", func(t *testing.T) {
		got := planCompression(current, map[string]int{"container_logs": 0})
		if len(got) != 0 {
			t.Fatalf("expected no actions, got %+v", got)
		}
	})

	t.Run("tables not asked about are left alone", func(t *testing.T) {
		got := planCompression(current, map[string]int{})
		if len(got) != 0 {
			t.Fatalf("expected no actions, got %+v", got)
		}
	})
}
