package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SpecHash fingerprints the parts of a component that Docker bakes into a
// container when it is created. Editing any of them changes what the next
// container will be, but leaves every running one exactly as it was: the
// operator sees the new value in the panel while the old one keeps serving
// traffic. Recording this hash on the instance is what lets the panel say so.
//
// Fields read per deploy rather than baked in (health mode, path, command,
// restart retries, drain timeouts, keep_releases) are deliberately excluded:
// they already apply to the next deployment without recreating anything, so
// including them would report drift that does not exist.
func (c DeployComponent) SpecHash() string {
	h := sha256.New()

	write := func(label, value string) {
		// Length-prefixed so no combination of values can be rearranged into
		// the same byte stream.
		fmt.Fprintf(h, "%s:%d:%s\n", label, len(value), value)
	}

	write("command", strings.Join(c.Command, "\x00"))
	write("env_file_path", c.EnvFilePath)
	write("networks", strings.Join(c.Networks, "\x00"))

	for i, m := range c.Mounts {
		write(fmt.Sprintf("mount.%d", i), fmt.Sprintf("%s|%s|%s|%t|%+v|%+v",
			m.Type, m.Source, m.Target, m.ReadOnly, m.BindOptions, m.VolumeOptions))
	}

	keys := make([]string, 0, len(c.Env))
	for k := range c.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		write("env."+k, c.Env[k])
	}

	secretKeys := append([]string(nil), c.EnvSecretKeys...)
	sort.Strings(secretKeys)
	write("env_secret_keys", strings.Join(secretKeys, "\x00"))

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// MarshalJSON publishes the computed fingerprint alongside the stored fields.
// The panel compares it with each instance's spec_hash to tell whether a
// running container was built from what the form now shows, and doing it here
// keeps the hashing rules in one place instead of restating them in the UI.
func (c DeployComponent) MarshalJSON() ([]byte, error) {
	type stored DeployComponent
	return json.Marshal(struct {
		stored
		SpecHash string `json:"spec_hash"`
	}{stored(c), c.SpecHash()})
}
