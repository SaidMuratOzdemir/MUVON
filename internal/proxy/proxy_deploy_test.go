package proxy

import (
	"testing"

	"muvon/internal/config"
	"muvon/internal/db"
)

func TestPickBackendPrefersManagedActiveInstances(t *testing.T) {
	legacyURL := "http://legacy:8000"
	route := &config.RouteRule{
		Route: db.Route{
			ID:         10,
			BackendURL: &legacyURL,
		},
		ManagedBackends: []db.ManagedBackend{
			{InstanceID: "inst-1", BackendURL: "http://candidate:8000"},
		},
	}

	backend := pickBackend(route)
	if backend.URL != "http://candidate:8000" {
		t.Fatalf("expected managed backend, got %q", backend.URL)
	}
	if backend.InstanceID != "inst-1" {
		t.Fatalf("expected managed instance id, got %q", backend.InstanceID)
	}
}

func TestPickBackendFallsBackWhenNoManagedInstanceIsActive(t *testing.T) {
	legacyURL := "http://legacy:8000"
	route := &config.RouteRule{
		Route: db.Route{
			ID:         11,
			BackendURL: &legacyURL,
		},
	}

	backend := pickBackend(route)
	if backend.URL != legacyURL {
		t.Fatalf("expected legacy backend, got %q", backend.URL)
	}
	if backend.InstanceID != "" {
		t.Fatalf("expected no instance id, got %q", backend.InstanceID)
	}
}
