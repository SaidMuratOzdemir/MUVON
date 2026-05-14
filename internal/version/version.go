// Package version exposes the binary version string injected at build
// time via -ldflags "-X muvon/internal/version.Version=v0.1.0".
//
// Single source of truth is the repository's VERSION file; Makefile
// reads it and passes the value to every cmd/* main.go through go
// build's -X linker flag. Builds without the ldflags (e.g. a developer
// running `go run`) fall back to "dev" so the binary still reports a
// recognisable string instead of an empty one.
package version

import "runtime/debug"

// Version is set at build time via -ldflags "-X .Version=...".
// "dev" is the development fallback when the binary is built without
// the linker flag — e.g. `go run ./cmd/muvon`. Production images
// always carry a real value because the Makefile injects it.
var Version = "dev"

// Commit is the short git SHA, injected the same way as Version.
// Empty when not set; callers should treat that as "unknown".
var Commit = ""

// String returns "v0.1.0 (abc1234)" when both are set, "v0.1.0" when
// only Version is known, or "dev" for unflagged builds. Keep the shape
// stable — install.sh greps `<binary> --version` output to detect the
// running release.
func String() string {
	if Version == "dev" && Commit == "" {
		// Fall back to Go module info when neither -X was passed —
		// `go install muvon/cmd/muvon@vX` users land here.
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
		return "dev"
	}
	if Commit == "" {
		return Version
	}
	return Version + " (" + Commit + ")"
}
