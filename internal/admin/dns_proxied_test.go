package admin

import "testing"

// A domain behind Cloudflare resolves to Cloudflare, not to the origin. Calling
// that "wrong IP" is how a panel teaches its operator to ignore it, which is
// exactly what happened here: the warning sat on a working host for weeks.
func TestAllCloudflare(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string
		want  bool
	}{
		{"cloudflare v4 pair", []string{"104.21.36.17", "172.67.183.18"}, true},
		{"single cloudflare address", []string{"104.16.5.5"}, true},
		{"origin address", []string{"37.27.204.145"}, false},
		{"mixed answer is not proxied", []string{"104.21.36.17", "37.27.204.145"}, false},
		{"empty answer", nil, false},
		{"garbage does not count as cloudflare", []string{"not-an-ip"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := allCloudflare(tc.addrs); got != tc.want {
				t.Fatalf("allCloudflare(%v) = %v, want %v", tc.addrs, got, tc.want)
			}
		})
	}
}
