// Package clientlib embeds the built MUVON RUM browser bundle so the edge can
// serve it at /__muvon/rum.js. The bundle is a generated artifact committed to
// the repo (like the proto .pb.go files) and regenerated with `make clientlib`,
// so the proxy package always builds without a Node toolchain present.
package clientlib

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

//go:embed dist/rum.js
var Bundle []byte

// ETag is the content hash of the bundle, computed once at startup, for
// conditional GETs (browsers cache rum.js aggressively between releases).
var ETag = func() string {
	sum := sha256.Sum256(Bundle)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}()
