package deployer

import "testing"

func TestApplyEdgeIP_ResolvesPlaceholder(t *testing.T) {
	env := map[string]string{
		"FORWARDED_ALLOW_IPS": "${MUVON_EDGE_IP}",
		"TRUSTED_PROXIES":     "${MUVON_EDGE_IP},10.0.0.1",
		"UNRELATED":           "keep-me",
	}
	applyEdgeIP(env, "172.18.0.2")

	if got := env["FORWARDED_ALLOW_IPS"]; got != "172.18.0.2" {
		t.Errorf("FORWARDED_ALLOW_IPS=%q, want 172.18.0.2", got)
	}
	if got := env["TRUSTED_PROXIES"]; got != "172.18.0.2,10.0.0.1" {
		t.Errorf("TRUSTED_PROXIES=%q, want 172.18.0.2,10.0.0.1", got)
	}
	if got := env["UNRELATED"]; got != "keep-me" {
		t.Errorf("UNRELATED altered: %q", got)
	}
	if got := env[edgeIPVar]; got != "172.18.0.2" {
		t.Errorf("%s=%q, want 172.18.0.2", edgeIPVar, got)
	}
}

// An unresolved edge IP must leave the placeholder alone. Substituting an empty
// string would silently turn a proxy allow-list into "trust nobody", which is the
// exact silent failure this feature exists to prevent.
func TestApplyEdgeIP_EmptyLeavesPlaceholder(t *testing.T) {
	env := map[string]string{"FORWARDED_ALLOW_IPS": "${MUVON_EDGE_IP}"}
	applyEdgeIP(env, "")

	if got := env["FORWARDED_ALLOW_IPS"]; got != "${MUVON_EDGE_IP}" {
		t.Errorf("placeholder rewritten to %q, want it untouched", got)
	}
	if _, ok := env[edgeIPVar]; ok {
		t.Errorf("%s should not be set when the edge IP is unknown", edgeIPVar)
	}
}

// Substitution is a literal token replace, never shell-style expansion, so secret
// values containing "$" survive untouched.
func TestApplyEdgeIP_DoesNotManglePlainDollarValues(t *testing.T) {
	env := map[string]string{
		"DB_PASSWORD": "p$ssw0rd$MUVON_EDGE_IP",
		"SHELLISH":    "$HOME/bin:${PATH}",
	}
	applyEdgeIP(env, "172.19.0.2")

	if got := env["DB_PASSWORD"]; got != "p$ssw0rd$MUVON_EDGE_IP" {
		t.Errorf("DB_PASSWORD mangled: %q", got)
	}
	if got := env["SHELLISH"]; got != "$HOME/bin:${PATH}" {
		t.Errorf("SHELLISH mangled: %q", got)
	}
}

func TestApplyEdgeIP_MultipleOccurrences(t *testing.T) {
	env := map[string]string{"LIST": "${MUVON_EDGE_IP},${MUVON_EDGE_IP}"}
	applyEdgeIP(env, "172.20.0.2")

	if got := env["LIST"]; got != "172.20.0.2,172.20.0.2" {
		t.Errorf("LIST=%q, want both occurrences replaced", got)
	}
}

// The trusted-proxy address often lives on the command line, where it overrides
// the env var, so the token must resolve there too.
func TestApplyEdgeIPToArgs(t *testing.T) {
	args := []string{"gunicorn", "--forwarded-allow-ips", "${MUVON_EDGE_IP}", "app:main"}
	got := applyEdgeIPToArgs(args, "172.18.0.2")

	if got[2] != "172.18.0.2" {
		t.Errorf("args[2]=%q, want 172.18.0.2", got[2])
	}
	if got[0] != "gunicorn" || got[3] != "app:main" {
		t.Errorf("unrelated args altered: %v", got)
	}
	if args[2] != "${MUVON_EDGE_IP}" {
		t.Errorf("input slice mutated: %v", args)
	}
}

func TestApplyEdgeIPToArgs_UnresolvedLeavesArgsAlone(t *testing.T) {
	args := []string{"gunicorn", "--forwarded-allow-ips", "${MUVON_EDGE_IP}"}
	got := applyEdgeIPToArgs(args, "")

	if got[2] != "${MUVON_EDGE_IP}" {
		t.Errorf("args[2]=%q, want placeholder untouched", got[2])
	}
}

// A component is normally attached to an isolated database network plus the
// shared routing network, and the proxy joins only the routing one. Looking at
// networks[0] alone missed it and left the token unresolved.
func TestPickNetworkIP_FindsSharedNetworkNotListedFirst(t *testing.T) {
	proxy := map[string]string{"muvon-agent_default": "172.19.0.2"}
	component := []string{"app-db", "muvon-agent_default"}

	if got := pickNetworkIP(proxy, component); got != "172.19.0.2" {
		t.Errorf("pickNetworkIP=%q, want 172.19.0.2 from the second network", got)
	}
}

func TestPickNetworkIP_NoSharedNetwork(t *testing.T) {
	proxy := map[string]string{"muvon-agent_default": "172.19.0.2"}
	if got := pickNetworkIP(proxy, []string{"app-db"}); got != "" {
		t.Errorf("pickNetworkIP=%q, want empty when the proxy shares no network", got)
	}
}

// An unresolved token must fail the deployment, not reach the container. Passing
// the literal through hands the app an invalid address and crash-loops it.
func TestCheckEdgeIPResolved(t *testing.T) {
	if err := checkEdgeIPResolved(map[string]string{"FORWARDED_ALLOW_IPS": "172.19.0.2"}, []string{"gunicorn"}); err != nil {
		t.Errorf("resolved config rejected: %v", err)
	}
	if err := checkEdgeIPResolved(map[string]string{"FORWARDED_ALLOW_IPS": "${MUVON_EDGE_IP}"}, nil); err == nil {
		t.Error("unresolved env token accepted, want error")
	}
	if err := checkEdgeIPResolved(nil, []string{"gunicorn", "--forwarded-allow-ips", "${MUVON_EDGE_IP}"}); err == nil {
		t.Error("unresolved command token accepted, want error")
	}
}
