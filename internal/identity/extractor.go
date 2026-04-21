package identity

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

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

	// Check signature first, ignoring exp — we want to report signature and
	// expiry as separate observations. An expired-but-signed token is a
	// different class of event (likely a stale but legitimate client) from
	// a forged token, and collapsing both into "verify failed → fall back
	// to decode" hides that distinction.
	claims, err := verifyHS256Signature(raw, cfg.Secret)
	if err == nil {
		expired := isExpired(claims)
		if expired {
			return buildIdentity(claims, cfg.Claims, false, "jwt_expired", true)
		}
		return buildIdentity(claims, cfg.Claims, true, "jwt_verify", false)
	}

	slog.Debug("jwt verify failed, falling back to decode", "error", err)

	// Fallback: decode without verification. The claims may be forged; we
	// still capture them (for observability) and pass exp state through so
	// the UI can distinguish "forged" from "forged AND expired".
	claims, err = decodeUnverified(raw)
	if err != nil {
		slog.Debug("jwt decode failed", "error", err)
		return nil
	}
	return buildIdentity(claims, cfg.Claims, false, "jwt_decode", isExpired(claims))
}

// verifyHS256Signature parses a token, enforces the HMAC algorithm, and
// verifies the signature but explicitly skips claim validation (including
// exp/nbf) so we can report expiry as its own signal.
func verifyHS256Signature(tokenStr, secret string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
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

// isExpired reads the exp claim and returns whether it lies in the past.
// Missing or unparseable exp → treated as not expired (matches JWT spec:
// exp is optional, and we do not want to drop tokens that legitimately do
// not set it).
func isExpired(claims jwt.MapClaims) bool {
	raw, ok := claims["exp"]
	if !ok {
		return false
	}
	var exp int64
	switch v := raw.(type) {
	case float64:
		exp = int64(v)
	case int64:
		exp = v
	case int:
		exp = int64(v)
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return false
		}
		exp = n
	default:
		return false
	}
	return time.Now().Unix() >= exp
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

func buildIdentity(allClaims jwt.MapClaims, wantedKeys []string, verified bool, source string, expExpired bool) *logger.UserIdentity {
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

	// An expired token with no extracted claims is still worth recording —
	// the expiry signal itself matters for audit/correlation. An unverified
	// decode with zero extracted claims can be dropped.
	if len(extracted) == 0 && !expExpired {
		return nil
	}

	return &logger.UserIdentity{
		Claims:     extracted,
		Verified:   verified,
		Source:     source,
		ExpExpired: expExpired,
	}
}
