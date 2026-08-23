package secret

import (
	"errors"
	"testing"
)

// An empty passphrase must be an error, not a Box that quietly stores
// plaintext. This is the whole point of the type.
func TestNewBoxRejectsEmptyPassphrase(t *testing.T) {
	box, err := NewBox("")
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("NewBox(\"\") error = %v, want ErrNoKey", err)
	}
	if box != nil {
		t.Fatal("NewBox(\"\") returned a usable Box")
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	box, err := NewBox("test-passphrase")
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}

	const plain = "smtp-password"
	enc, err := box.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc == plain {
		t.Fatal("Encrypt returned the plaintext unchanged")
	}
	if !IsEncrypted(enc) {
		t.Fatalf("Encrypt output %q has no enc: prefix", enc)
	}

	got, err := box.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("Decrypt = %q, want %q", got, plain)
	}
}

// The nonce is random, so the same input never produces the same ciphertext.
func TestEncryptIsNotDeterministic(t *testing.T) {
	box, _ := NewBox("test-passphrase")
	a, _ := box.Encrypt("same")
	b, _ := box.Encrypt("same")
	if a == b {
		t.Fatal("two encryptions of the same value are identical")
	}
}

func TestEmptyValueStaysEmpty(t *testing.T) {
	box, _ := NewBox("test-passphrase")
	got, err := box.Encrypt("")
	if err != nil || got != "" {
		t.Fatalf("Encrypt(\"\") = %q, %v; want \"\", nil", got, err)
	}
}

// A value that was never encrypted (an env var the operator did not mark
// secret) passes through Decrypt untouched.
func TestDecryptPassesThroughUnprefixedValue(t *testing.T) {
	box, _ := NewBox("test-passphrase")
	got, err := box.Decrypt("plain-value")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "plain-value" {
		t.Fatalf("Decrypt = %q, want the value unchanged", got)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	writer, _ := NewBox("key-one")
	reader, _ := NewBox("key-two")

	enc, err := writer.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := reader.Decrypt(enc); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt with the wrong key error = %v, want ErrDecrypt", err)
	}
}

func TestDecryptRejectsTruncatedCiphertext(t *testing.T) {
	box, _ := NewBox("test-passphrase")
	if _, err := box.Decrypt(encPrefix + "AAAA"); !errors.Is(err, ErrShortCipher) {
		t.Fatalf("Decrypt of a short ciphertext error = %v, want ErrShortCipher", err)
	}
}

func TestDecryptRejectsMalformedBase64(t *testing.T) {
	box, _ := NewBox("test-passphrase")
	if _, err := box.Decrypt(encPrefix + "not base64!"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt of malformed base64 error = %v, want ErrDecrypt", err)
	}
}
