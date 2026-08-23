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

// Box performs AES-256-GCM encryption and decryption. A Box always holds a
// key: there is no passthrough mode. One used to exist, and it turned a
// missing MUVON_ENCRYPTION_KEY into secrets written to the database in the
// clear while the panel kept masking them, so the operator saw "********"
// over a readable row. A service that cannot encrypt now refuses to start
// instead.
type Box struct {
	key [32]byte
}

// NewBox derives a 256-bit key from the passphrase using SHA-256. An empty
// passphrase is an error the caller is expected to treat as fatal.
//
// No minimum length is enforced. The key is not recoverable from anything
// else, so rejecting a short one at startup would lock an operator out of
// data that key already encrypted.
func NewBox(passphrase string) (*Box, error) {
	if passphrase == "" {
		return nil, ErrNoKey
	}
	return &Box{key: sha256.Sum256([]byte(passphrase))}, nil
}

// Encrypt returns "enc:" + base64(nonce + ciphertext). An empty input stays
// empty: there is nothing to protect and callers store it as "unset".
func (b *Box) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return plaintext, nil
	}

	gcm, err := b.gcm()
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

// Decrypt reverses Encrypt. A value without the "enc:" prefix was never
// encrypted (an env var the operator did not mark secret, or a row written
// before the key existed) and is returned unchanged.
func (b *Box) Decrypt(value string) (string, error) {
	if !strings.HasPrefix(value, encPrefix) {
		return value, nil
	}

	data, err := base64.StdEncoding.DecodeString(value[len(encPrefix):])
	if err != nil {
		return "", ErrDecrypt
	}

	gcm, err := b.gcm()
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

func (b *Box) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// IsEncrypted reports whether the value carries the "enc:" prefix.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, encPrefix)
}
