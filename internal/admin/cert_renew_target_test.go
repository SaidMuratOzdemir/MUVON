package admin

import (
	"encoding/json"
	"testing"
)

// A forced renewal deletes the stored certificate, so the parser must never
// report force for a payload that did not ask for it.
func TestCertRenewTarget(t *testing.T) {
	cases := []struct {
		name       string
		payload    string
		wantDomain string
		wantForce  bool
	}{
		{"plain renew", `{"domain":"example.com"}`, "example.com", false},
		{"forced renew", `{"domain":"example.com","force":true}`, "example.com", true},
		{"force false", `{"domain":"example.com","force":false}`, "example.com", false},
		{"uppercase and spaces", `{"domain":"  Example.COM  ","force":true}`, "example.com", true},
		{"no domain", `{"force":true}`, "", true},
		{"empty object", `{}`, "", false},
		{"malformed", `{"domain":`, "", false},
		{"force as string is not force", `{"domain":"example.com","force":"true"}`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			domain, force := certRenewTarget(json.RawMessage(tc.payload))
			if domain != tc.wantDomain || force != tc.wantForce {
				t.Fatalf("got (%q, %v), want (%q, %v)", domain, force, tc.wantDomain, tc.wantForce)
			}
		})
	}
}
