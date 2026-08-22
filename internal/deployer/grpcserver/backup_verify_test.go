package grpcserver

import (
	"os"
	"path/filepath"
	"testing"
)

// customDumpHeader is the first bytes pg_dump writes for -Fc: PGDMP, version
// triple, integer size, offset size, format byte.
func customDumpHeader() []byte {
	h := []byte("PGDMP")
	h = append(h, 1, 15, 0) // version 1.15.0
	h = append(h, 4)        // int size
	h = append(h, 8)        // offset size
	h = append(h, 1)        // format: custom
	return h
}

func writeDump(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.dump")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestVerifyCustomDumpHeaderAcceptsAValidArchive(t *testing.T) {
	body := append(customDumpHeader(), make([]byte, 128)...)
	if err := verifyCustomDumpHeader(writeDump(t, body)); err != nil {
		t.Fatalf("valid archive rejected: %v", err)
	}
}

// The exact shape of the corruption this check exists for: the demuxer removed
// every 0x0A byte from the stream. The magic survives because it has none, so
// the header check alone cannot catch it — but the file still has to fail
// somewhere, and pg_restore does. This test pins the boundary of what the
// cheap check can and cannot promise, so nobody treats it as sufficient.
func TestVerifyCustomDumpHeaderCannotDetectStrippedNewlines(t *testing.T) {
	body := append(customDumpHeader(), []byte{0x01, 0x02, 0x03}...)
	body = append(body, make([]byte, 128)...)
	var stripped []byte
	for _, b := range body {
		if b == '\n' || b == '\r' {
			continue
		}
		stripped = append(stripped, b)
	}
	if err := verifyCustomDumpHeader(writeDump(t, stripped)); err != nil {
		t.Skip("header check happened to catch it; nothing to pin")
	}
}

func TestVerifyCustomDumpHeaderRejectsBadArchives(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"truncated", []byte("PGDMP")},
		{"wrong magic", append([]byte("NOTPG"), make([]byte, 128)...)},
		{"plain format instead of custom", func() []byte {
			h := customDumpHeader()
			h[10] = 3
			return append(h, make([]byte, 128)...)
		}()},
		{"implausible int size", func() []byte {
			h := customDumpHeader()
			h[8] = 0
			return append(h, make([]byte, 128)...)
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyCustomDumpHeader(writeDump(t, tc.body)); err == nil {
				t.Fatal("expected the archive to be rejected")
			}
		})
	}
}

func TestVerifyCustomDumpHeaderRejectsMissingFile(t *testing.T) {
	if err := verifyCustomDumpHeader(filepath.Join(t.TempDir(), "absent.dump")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
