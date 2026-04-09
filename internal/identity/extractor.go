package identity

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"muvon/internal/logger"
)

// Extractor extracts JWT identity from requests.
// It is safe for concurrent use — all mutable state comes from
// the config snapshot passed to Extract.
type Extractor struct{}

// Config holds the JWT extraction settings, typically loaded from the atomic config holder.
type Config struct {
	Enabled bool
	Secret  string   // HS256 HMAC secret
	Claims  []string // claim keys to extract (e.g. "sub", "email", "role")
}

// Extract reads the Authorization header from the request and extracts JWT identity.
func (ex *Extractor) Extract(r *http.Request, cfg Config) *logger.UserIdentity {
	return ex.ExtractFromBearer(r.Header.Get("Authorization"), cfg)
}

// ExtractFromBearer extracts JWT identity from a raw Authorization header value.
// Used by the log pipeline to enrich entries centrally without an http.Request.
func (ex *Extractor) ExtractFromBearer(authHeader string, cfg Config) *logger.UserIdentity {
	if !cfg.Enabled || cfg.Secret == "" {
		return nil
	}

	raw := ""
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
		raw = authHeader[7:]
	}
	if raw == "" {
		return nil
	}

	// Try verify first
	claims, err := verifyHS256(raw, cfg.Secret)
	if err == nil {
		return buildIdentity(claims, cfg.Claims, true, "jwt_verify")
	}

	slog.Debug("jwt verify failed, falling back to decode", "error", err)

	// Fallback: decode without verification
	claims, err = decodeUnverified(raw)
	if err != nil {
		slog.Debug("jwt decode failed", "error", err)
		return nil
	}

	return buildIdentity(claims, cfg.Claims, false, "jwt_decode")
}

func verifyHS256(tokenStr, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

func decodeUnverified(tokenStr string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

func buildIdentity(allClaims jwt.MapClaims, wantedKeys []string, verified bool, source string) *logger.UserIdentity {
	extracted := make(map[string]string, len(wantedKeys))
	for _, key := range wantedKeys {
		v, ok := allClaims[key]
		if !ok {
			continue
		}
		switch val := v.(type) {
		case string:
			extracted[key] = val
		case float64:
			if val == float64(int64(val)) {
				extracted[key] = strconv.FormatInt(int64(val), 10)
			} else {
				extracted[key] = strconv.FormatFloat(val, 'f', -1, 64)
			}
		case bool:
			extracted[key] = strconv.FormatBool(val)
		default:
			// Skip complex types (arrays, objects)
		}
	}

	if len(extracted) == 0 {
		return nil
	}

	return &logger.UserIdentity{
		Claims:   extracted,
		Verified: verified,
		Source:   source,
	}
}
