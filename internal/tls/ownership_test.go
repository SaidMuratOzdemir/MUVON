package tls

import "testing"

// The whole renewal defect reduces to this classification: a certificate
// autocert issued must be recognised as autocert's, or something else answers
// for it on the serving path and its renewal timer is never armed.
func TestCentralCertOwnership(t *testing.T) {
	cases := []struct {
		issuer   string
		operator bool
		why      string
	}{
		{"manual", true, "uploaded through the admin panel"},
		{"Manual", true, "issuer casing must not change the answer"},
		{"  manual  ", true, "stored values can carry whitespace"},
		{"cloudflare-origin-ca", true, "an unknown issuer was put there by a human"},
		{"", true, "no issuer recorded: treat as operator's, never override it"},
		{"letsencrypt", false, "central's own autocert mirror"},
		{"letsencrypt:agent:019ecbfc", false, "an agent's backup upload"},
		{"LETSENCRYPT:agent:x", false, "casing again"},
	}
	for _, tc := range cases {
		t.Run(tc.issuer, func(t *testing.T) {
			got := (&CentralCert{Issuer: tc.issuer}).OperatorManaged()
			if got != tc.operator {
				t.Fatalf("issuer %q: operator-managed = %v, want %v (%s)", tc.issuer, got, tc.operator, tc.why)
			}
			// The two sides must agree; central and the agent make the same
			// call from the same string.
			if stored := (storedCert{issuer: tc.issuer}).operatorManaged(); stored != got {
				t.Fatalf("issuer %q: CertStore says %v, CentralCert says %v", tc.issuer, stored, got)
			}
		})
	}
}

func TestCentralCertOwnershipNilIsNotOperator(t *testing.T) {
	var c *CentralCert
	if c.OperatorManaged() {
		t.Fatal("a missing certificate must not be treated as an operator override")
	}
}

// certKeyPEM builds the blob autocert expects in its cache: private key first,
// then the chain. Getting the order wrong would make the seeded cache
// unreadable and quietly send every cold start back to ACME.
func TestCertKeyPEMOrdersKeyBeforeChain(t *testing.T) {
	key := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	cert := "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"

	blob := string(certKeyPEM(key, cert))
	keyAt := indexOf(blob, "BEGIN PRIVATE KEY")
	certAt := indexOf(blob, "BEGIN CERTIFICATE")
	if keyAt < 0 || certAt < 0 {
		t.Fatalf("blob lost a PEM block: %q", blob)
	}
	if keyAt > certAt {
		t.Fatalf("certificate precedes the key; autocert cannot read this")
	}
	// splitPEM is what reads such a blob back; it must recover both halves.
	gotCert, gotKey := splitPEM([]byte(blob))
	if len(gotCert) == 0 || len(gotKey) == 0 {
		t.Fatalf("round trip lost a half: cert=%d key=%d", len(gotCert), len(gotKey))
	}
}

func TestCertKeyPEMEmptyInputs(t *testing.T) {
	if certKeyPEM("", "x") != nil || certKeyPEM("x", "") != nil {
		t.Fatal("a half-populated response must not produce a seed blob")
	}
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
