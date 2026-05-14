package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"muvon/internal/db"
)

// --- Auth handlers -----------------------------------------------------------
//
// The admin panel uses a standard access + refresh token flow:
//
//   • Access JWT (15 min) in an HttpOnly __Host- cookie, scoped to "/".
//   • Refresh token (30 days) in an HttpOnly cookie, scoped to /api/auth.
//   • CSRF token in a JS-readable cookie; the SPA echoes it in X-CSRF-Token.
//
// Every refresh rotates the refresh token: the old row is marked revoked and a
// new row is inserted in the same family. If a revoked token is ever
// presented again we treat it as theft and revoke the whole family at once
// (enterprise pattern, same as Auth0).

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	User db.AdminUser `json:"user"`
}

// handleLogin verifies credentials and issues a fresh session. Mismatched
// username and wrong password return the same error so an attacker cannot
// enumerate valid usernames.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	user, err := s.db.GetAdminByUsername(r.Context(), req.Username)
	if err != nil || !user.IsActive || !CheckPassword(user.PasswordHash, req.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if err := s.issueSession(w, r, user, ""); err != nil {
		slog.Error("login: issue session failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "login failed"})
		return
	}
	writeJSON(w, http.StatusOK, authResponse{User: user})
}

// handleSetup creates the first admin user. Enabled only when no admin exists.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	exists, err := s.db.AdminExists(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if exists {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "admin already exists"})
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Username == "" || len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required, password min 8 chars"})
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password hashing failed"})
		return
	}
	user, err := s.db.CreateAdmin(r.Context(), req.Username, hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.issueSession(w, r, user, ""); err != nil {
		slog.Error("setup: issue session failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "setup failed"})
		return
	}
	writeJSON(w, http.StatusCreated, authResponse{User: user})
}

// handleRefresh rotates the refresh token and issues a new access + CSRF
// cookie pair. The refresh cookie must be present; its value is hashed and
// handed to the DB layer, which handles rotation, expiry, and reuse detection
// atomically.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieRefresh)
	if err != nil || cookie.Value == "" {
		clearAuthCookies(w)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no refresh token"})
		return
	}

	presentedHash := HashRefreshToken(cookie.Value)
	newToken, newHash, err := GenerateRefreshToken()
	if err != nil {
		slog.Error("refresh: generate token failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "refresh failed"})
		return
	}
	newExpires := time.Now().Add(RefreshTokenTTL)

	row, err := s.db.RotateRefreshToken(r.Context(), presentedHash, newHash, newExpires,
		r.UserAgent(), extractClientIP(r))
	if err != nil {
		clearAuthCookies(w)
		switch {
		case errors.Is(err, db.ErrRefreshTokenReuse):
			// Security incident — likely a stolen token. Family already revoked in DB.
			slog.Warn("refresh token reuse detected", "ip", extractClientIP(r), "user_agent", r.UserAgent())
		case errors.Is(err, db.ErrRefreshTokenExpired):
			// Normal — just tell the client to log in again.
		case errors.Is(err, db.ErrRefreshTokenNotFound):
			// Unknown token — could be an old token from before deploy, or fabricated.
		default:
			slog.Error("refresh: rotate failed", "error", err)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid refresh token"})
		return
	}

	user, err := s.db.GetAdminByID(r.Context(), row.UserID)
	if err != nil || !user.IsActive {
		// User deleted or disabled mid-session — revoke everything and bail.
		_ = s.db.RevokeUserRefreshTokens(r.Context(), row.UserID)
		clearAuthCookies(w)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user no longer active"})
		return
	}

	if err := s.emitSessionCookies(w, user, newToken, newExpires); err != nil {
		slog.Error("refresh: emit cookies failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "refresh failed"})
		return
	}
	writeJSON(w, http.StatusOK, authResponse{User: user})
}

// handleLogout revokes the current refresh token (not the whole family — other
// devices stay logged in) and clears all three cookies. Safe to call without
// an active session; cookies are cleared either way.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(cookieRefresh); err == nil && cookie.Value != "" {
		hash := HashRefreshToken(cookie.Value)
		if row, err := s.db.FindRefreshTokenByHash(r.Context(), hash); err == nil {
			_ = s.db.RevokeRefreshToken(r.Context(), row.ID)
		}
	}
	clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleMe returns the currently authenticated user.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(userIDKey).(int)
	user, err := s.db.GetAdminByID(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// issueSession generates a fresh refresh token, inserts it as the root of a
// new family (or continues the supplied one), and writes all three cookies.
// Used by login and setup; rotation goes through RotateRefreshToken directly
// because it needs transactional reuse detection.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, user db.AdminUser, familyID string) error {
	refreshToken, refreshHash, err := GenerateRefreshToken()
	if err != nil {
		return err
	}
	refreshExpires := time.Now().Add(RefreshTokenTTL)
	if _, err := s.db.CreateRefreshToken(r.Context(), user.ID, refreshHash, familyID, nil,
		refreshExpires, r.UserAgent(), extractClientIP(r)); err != nil {
		return err
	}
	return s.emitSessionCookies(w, user, refreshToken, refreshExpires)
}

// emitSessionCookies writes the access, refresh and CSRF cookies together.
// Called by both issueSession (new session) and handleRefresh (rotation).
func (s *Server) emitSessionCookies(w http.ResponseWriter, user db.AdminUser, refreshToken string, refreshExpires time.Time) error {
	access, accessExpires, err := s.auth.GenerateAccessToken(user.ID, user.Username, user.TokenVersion)
	if err != nil {
		return err
	}
	csrfToken, err := generateCSRFToken()
	if err != nil {
		return err
	}
	setAccessCookie(w, access, accessExpires)
	setRefreshCookie(w, refreshToken, refreshExpires)
	setCSRFCookie(w, csrfToken, refreshExpires)
	return nil
}

// StartRefreshTokenCleanup launches a goroutine that deletes expired refresh
// tokens on a fixed interval. Returning a cancel that the caller blocks on
// keeps the lifecycle explicit in main().
func (s *Server) StartRefreshTokenCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := s.db.DeleteExpiredRefreshTokens(ctx)
				if err != nil {
					slog.Warn("refresh token cleanup failed", "error", err)
					continue
				}
				if n > 0 {
					slog.Info("refresh token cleanup", "deleted", n)
				}
			}
		}
	}()
}
