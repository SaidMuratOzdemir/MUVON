package db

import (
	"encoding/json"
	"testing"
)

func baseComponent() DeployComponent {
	return DeployComponent{
		Slug:          "api",
		Command:       []string{"gunicorn", "app:main"},
		EnvFilePath:   "/opt/envfiles/api.env",
		Networks:      []string{"muvon-agent_default", "project-db"},
		Env:           map[string]string{"SERVER_API_URL": "http://api:8000", "TZ": "Europe/Istanbul"},
		EnvSecretKeys: []string{"SECRET_KEY"},
		Mounts:        []Mount{{Type: "bind", Source: "/opt/project/media", Target: "/media"}},
	}
}

func TestSpecHashIsStable(t *testing.T) {
	a, b := baseComponent(), baseComponent()
	if a.SpecHash() != b.SpecHash() {
		t.Fatalf("identical components hashed differently: %s vs %s", a.SpecHash(), b.SpecHash())
	}
}

// Map iteration order must not leak into the hash, or every deploy would look
// like drift.
func TestSpecHashIgnoresEnvOrdering(t *testing.T) {
	a := baseComponent()
	b := baseComponent()
	b.Env = map[string]string{"TZ": "Europe/Istanbul", "SERVER_API_URL": "http://api:8000"}
	if a.SpecHash() != b.SpecHash() {
		t.Fatal("hash changed with map ordering")
	}
}

// Everything Docker bakes into the container at creation has to move the hash,
// because that is exactly the set of edits a running container never sees.
func TestSpecHashReactsToBakedInFields(t *testing.T) {
	cases := map[string]func(*DeployComponent){
		"env value changed":   func(c *DeployComponent) { c.Env["SERVER_API_URL"] = "http://example-app-api:8000" },
		"env key added":       func(c *DeployComponent) { c.Env["NEW"] = "1" },
		"env key removed":     func(c *DeployComponent) { delete(c.Env, "TZ") },
		"secret key declared": func(c *DeployComponent) { c.EnvSecretKeys = append(c.EnvSecretKeys, "DB_PASSWORD") },
		"network added":       func(c *DeployComponent) { c.Networks = append(c.Networks, "extra") },
		"network reordered":   func(c *DeployComponent) { c.Networks = []string{"project-db", "muvon-agent_default"} },
		"command changed":     func(c *DeployComponent) { c.Command = []string{"celery", "worker"} },
		"env file changed":    func(c *DeployComponent) { c.EnvFilePath = "/opt/envfiles/other.env" },
		"mount added":         func(c *DeployComponent) { c.Mounts = append(c.Mounts, Mount{Type: "volume", Source: "v", Target: "/v"}) },
		"mount target moved":  func(c *DeployComponent) { c.Mounts[0].Target = "/srv/media" },
		"mount made readonly": func(c *DeployComponent) { c.Mounts[0].ReadOnly = true },
	}
	base := baseComponent().SpecHash()
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := baseComponent()
			mutate(&c)
			if c.SpecHash() == base {
				t.Fatal("edit did not change the fingerprint, so the drift would stay invisible")
			}
		})
	}
}

// Fields the deployer re-reads on the next deployment must NOT move the hash,
// or the panel would nag for a redeploy that changes nothing.
func TestSpecHashIgnoresFieldsAppliedWithoutRecreation(t *testing.T) {
	base := baseComponent().SpecHash()
	cases := map[string]func(*DeployComponent){
		"health path":        func(c *DeployComponent) { c.HealthPath = "/healthz" },
		"restart retries":    func(c *DeployComponent) { c.RestartRetries = 5 },
		"drain timeout":      func(c *DeployComponent) { c.DrainTimeoutSeconds = 60 },
		"keep releases":      func(c *DeployComponent) { c.KeepReleases = 10 },
		"paused":             func(c *DeployComponent) { c.Paused = true },
		"migration command":  func(c *DeployComponent) { c.MigrationCommand = []string{"migrate"} },
		"internal port only": func(c *DeployComponent) { c.InternalPort = 9000 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := baseComponent()
			mutate(&c)
			if c.SpecHash() != base {
				t.Fatal("fingerprint moved for a field that applies without recreating the container")
			}
		})
	}
}

// Two different specs must not collapse into one hash just because their
// pieces concatenate to the same string.
func TestSpecHashSeparatesAdjacentFields(t *testing.T) {
	a := baseComponent()
	a.Networks = []string{"ab", "c"}
	b := baseComponent()
	b.Networks = []string{"a", "bc"}
	if a.SpecHash() == b.SpecHash() {
		t.Fatal("field boundaries are not encoded in the hash")
	}
}

func TestComponentJSONCarriesSpecHash(t *testing.T) {
	c := baseComponent()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["spec_hash"] != c.SpecHash() {
		t.Fatalf("spec_hash missing or wrong in JSON: %v", out["spec_hash"])
	}
	// The stored fields must survive the custom marshaller.
	if out["slug"] != "api" {
		t.Fatalf("stored fields lost in JSON: %v", out["slug"])
	}
}
