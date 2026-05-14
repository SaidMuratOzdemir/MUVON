package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Token lifetimes. Access tokens are short — if one leaks, the window of abuse
// is bounded. Refresh tokens are long and live server-side so they can be
// revoked (see db.admin_refresh_tokens).
const (
	accessTokenTTL   = 15 * time.Minute
	RefreshTokenTTL  = 30 * 24 * time.Hour // 30 days
	refreshTokenSize = 32                  // bytes of entropy
)

type Auth struct {
	secret []byte
}

// Claims is the JWT payload for access tokens.
//
// TokenVersion lets us invalidate all outstanding access tokens for a user
// (e.g. on password change) by bumping admin_users.token_version. It is not
// checked yet by the middleware — the column exists and is threaded through so
// the feature can be enabled in a single follow-up without a schema change.
type Claims struct {
	UserID       int    `json:"uid"`
	Username     string `json:"usr"`
	TokenVersion int    `json:"tv"`
	jwt.RegisteredClaims
}

func NewAuth(secret string) *Auth {
	return &Auth{secret: []byte(secret)}
}

// GenerateAccessToken signs a short-lived JWT for the given user.
func (a *Auth) GenerateAccessToken(userID int, username string, tokenVersion int) (string, time.Time, error) {
	expiresAt := time.Now().Add(accessTokenTTL)
	claims := Claims{
		UserID:       userID,
		Username:     username,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "muvon-admin",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(a.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (a *Auth) ValidateAccessToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// GenerateRefreshToken returns a new opaque refresh token (URL-safe, 32 bytes
// of entropy) along with its SHA-256 hash for database storage. The plaintext
// is only ever returned to the caller once — it goes straight into the cookie
// and is never logged or persisted.
func GenerateRefreshToken() (token string, hash []byte, err error) {
	buf := make([]byte, refreshTokenSize)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(token))
	return token, h[:], nil
}

// HashRefreshToken recomputes the SHA-256 hash of a presented token so callers
// can look it up in the database without ever storing the plaintext.
//
// SHA-256 (not bcrypt) is intentional: refresh is on the hot auth path and the
// token already has 256 bits of raw entropy, so key-stretching adds cost
// without increasing security.
func HashRefreshToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
