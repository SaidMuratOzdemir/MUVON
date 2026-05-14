package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const encPrefix = "enc:"

var (
	ErrNoKey       = errors.New("secret: encryption key not configured")
	ErrDecrypt     = errors.New("secret: decryption failed")
	ErrShortCipher = errors.New("secret: ciphertext too short")
)

// Box performs AES-256-GCM encryption and decryption.
// A zero-value Box (empty key) is valid — Encrypt/Decrypt become no-ops
// for backward compatibility with deployments that haven't set a key yet.
type Box struct {
	key [32]byte
	ok  bool // true if a real key was provided
}

// NewBox derives a 256-bit key from the provided passphrase using SHA-256.
// If passphrase is empty, the Box operates in passthrough mode.
func NewBox(passphrase string) *Box {
	b := &Box{}
	if passphrase == "" {
		return b
	}
	b.key = sha256.Sum256([]byte(passphrase))
	b.ok = true
	return b
}

// HasKey reports whether an encryption key is configured.
func (b *Box) HasKey() bool {
	return b.ok
}

// Encrypt encrypts plaintext and returns "enc:" + base64(nonce + ciphertext).
// If no key is configured, returns plaintext unchanged.
func (b *Box) Encrypt(plaintext string) (string, error) {
	if !b.ok || plaintext == "" {
		return plaintext, nil
	}

	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a value. If the value doesn't have the "enc:" prefix,
// it's treated as legacy plaintext and returned as-is.
// If no key is configured but the value is encrypted, returns empty string.
func (b *Box) Decrypt(value string) (string, error) {
	if !strings.HasPrefix(value, encPrefix) {
		// Legacy plaintext — return as-is
		return value, nil
	}

	if !b.ok {
		// Encrypted value but no key configured
		return "", ErrNoKey
	}

	encoded := value[len(encPrefix):]
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", ErrDecrypt
	}

	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", ErrShortCipher
	}

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", ErrDecrypt
	}
	return string(plaintext), nil
}

// IsEncrypted reports whether the value carries the "enc:" prefix.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, encPrefix)
}
