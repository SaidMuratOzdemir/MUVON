package tls

import "testing"

func TestHardenedTLSConfigIncludesACMEALPN(t *testing.T) {
	cfg := HardenedTLSConfig(nil)

	found := false
	for _, proto := range cfg.NextProtos {
		if proto == "acme-tls/1" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("expected HardenedTLSConfig to advertise acme-tls/1")
	}
}
