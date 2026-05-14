package agentctrl

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// signingKey derives a command-signing secret from MUVON_ENCRYPTION_KEY
// via HKDF with a fixed label so the same encryption key can be reused
// for multiple distinct purposes (env-var encryption, command signing,
// future uses) without one purpose's secret being valid for another.
//
// Label is versioned ("-v1") so a future protocol-breaking change can
// rotate the derived key without touching MUVON_ENCRYPTION_KEY itself.
const signingKeyLabel = "muvon-agent-command-v1"

// DeriveSigningKey returns the 32-byte HMAC key for command signatures
// from the operator's MUVON_ENCRYPTION_KEY. Returns an error when the
// passphrase is empty because unsigned commands are unsafe.
func DeriveSigningKey(passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("agentctrl: MUVON_ENCRYPTION_KEY required to sign commands")
	}
	// Hash the passphrase to produce a uniform input keying material
	// for HKDF, mirroring secret.Box's derivation.
	ikm := sha256.Sum256([]byte(passphrase))
	// HKDF-Extract handles a nil salt by using a zero-string, which is
	// fine here because ikm is already high-entropy.
	r := hkdf.New(sha256.New, ikm[:], nil, []byte(signingKeyLabel))
	out := make([]byte, 32)
	if _, err := r.Read(out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}

// NewNonce returns a 16-byte cryptographically random value used to
// guarantee that two commands with otherwise-identical contents (same
// kind, same payload, same expiry) still produce distinct signatures
// and distinct DB rows.
func NewNonce() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Sign computes the HMAC-SHA256 signature of the canonical encoding
// of the command. The canonical form is JSON of {id, kind, payload,
// expires_at_unix, nonce} — using Unix seconds rather than RFC3339
// dodges time-zone serialisation drift between agent and server.
func Sign(cmd Command, key []byte) ([]byte, error) {
	canon, err := canonical(cmd)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write(canon)
	return m.Sum(nil), nil
}

// Verify recomputes the signature and compares in constant time.
// Returns nil on match, error otherwise. Callers should reject any
// command for which Verify returns an error before doing anything
// else — a forged signature is the only reliable signal that the
// admin layer's signing pipeline was bypassed.
func Verify(cmd Command, key []byte) error {
	want, err := Sign(cmd, key)
	if err != nil {
		return err
	}
	if !hmac.Equal(cmd.Signature, want) {
		return errors.New("command signature mismatch")
	}
	return nil
}

// canonical produces the deterministic byte sequence that Sign and
// Verify both compute their HMAC over. The order of fields is fixed;
// JSON's lexicographic key ordering is enforced via json.Marshal on a
// struct (Go's encoding/json emits struct fields in declaration order,
// which is what we want).
type signedFields struct {
	ID        string          `json:"id"`
	Kind      CommandKind     `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt int64           `json:"expires_at"` // Unix seconds — locale-free
	Nonce     []byte          `json:"nonce"`
}

func canonical(cmd Command) ([]byte, error) {
	payload := cmd.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	return json.Marshal(signedFields{
		ID:        cmd.ID,
		Kind:      cmd.Kind,
		Payload:   payload,
		ExpiresAt: cmd.ExpiresAt.Unix(),
		Nonce:     cmd.Nonce,
	})
}
