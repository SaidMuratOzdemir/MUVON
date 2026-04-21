package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RefreshToken represents a row in admin_refresh_tokens.
//
// Rotation chains share the same FamilyID. When a client refreshes, the current
// token row is marked revoked, a new row is inserted with ParentID set to the
// previous row, and the new token string is returned to the client. If a token
// that has already been revoked is presented again, the whole family is revoked
// immediately (reuse detection — likely a stolen token).
type RefreshToken struct {
	ID         string     // UUIDv7
	UserID     int
	FamilyID   string     // UUIDv7
	ParentID   *string    // nil for the first token in a family
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time // nil = active
	LastUsedAt *time.Time
	UserAgent  string
	IPAddress  string
}

var ErrRefreshTokenNotFound = errors.New("refresh token not found")

// CreateRefreshToken inserts a new refresh token row. Pass an empty familyID to
// start a new family (login/setup); pass an existing family during rotation.
func (d *DB) CreateRefreshToken(
	ctx context.Context,
	userID int,
	tokenHash []byte,
	familyID string,
	parentID *string,
	expiresAt time.Time,
	userAgent, ipAddress string,
) (RefreshToken, error) {
	var rt RefreshToken
	var fam string
	if familyID == "" {
		// Let Postgres assign a UUIDv7 family id when starting a new family.
		err := d.Pool.QueryRow(ctx, `SELECT gen_uuidv7()::text`).Scan(&fam)
		if err != nil {
			return rt, fmt.Errorf("create refresh token: new family id: %w", err)
		}
	} else {
		fam = familyID
	}
	err := d.Pool.QueryRow(ctx, `
		INSERT INTO admin_refresh_tokens
			(user_id, token_hash, family_id, parent_id, expires_at, user_agent, ip_address)
		VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7)
		RETURNING id::text, user_id, family_id::text, parent_id::text, issued_at, expires_at,
		          revoked_at, last_used_at, COALESCE(user_agent,''), COALESCE(ip_address,'')`,
		userID, tokenHash, fam, parentID, expiresAt, userAgent, ipAddress,
	).Scan(&rt.ID, &rt.UserID, &rt.FamilyID, &rt.ParentID, &rt.IssuedAt, &rt.ExpiresAt,
		&rt.RevokedAt, &rt.LastUsedAt, &rt.UserAgent, &rt.IPAddress)
	if err != nil {
		return rt, fmt.Errorf("create refresh token: %w", err)
	}
	return rt, nil
}

// FindRefreshTokenByHash looks up a refresh token by its SHA-256 hash.
// Returns ErrRefreshTokenNotFound if no row matches; the row may be expired or
// revoked — callers must inspect those fields themselves.
func (d *DB) FindRefreshTokenByHash(ctx context.Context, tokenHash []byte) (RefreshToken, error) {
	var rt RefreshToken
	err := d.Pool.QueryRow(ctx, `
		SELECT id::text, user_id, family_id::text, parent_id::text, issued_at, expires_at,
		       revoked_at, last_used_at, COALESCE(user_agent,''), COALESCE(ip_address,'')
		FROM admin_refresh_tokens
		WHERE token_hash = $1`, tokenHash,
	).Scan(&rt.ID, &rt.UserID, &rt.FamilyID, &rt.ParentID, &rt.IssuedAt, &rt.ExpiresAt,
		&rt.RevokedAt, &rt.LastUsedAt, &rt.UserAgent, &rt.IPAddress)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rt, ErrRefreshTokenNotFound
		}
		return rt, fmt.Errorf("find refresh token: %w", err)
	}
	return rt, nil
}

// MarkRefreshTokenUsed updates last_used_at to now(). Best-effort; errors are
// logged by the caller but do not fail the refresh.
func (d *DB) MarkRefreshTokenUsed(ctx context.Context, id string) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE admin_refresh_tokens SET last_used_at = now() WHERE id = $1::uuid`, id)
	if err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}
	return nil
}

// RevokeRefreshToken marks a single token as revoked.
func (d *DB) RevokeRefreshToken(ctx context.Context, id string) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE admin_refresh_tokens SET revoked_at = now() WHERE id = $1::uuid AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

// RevokeRefreshTokenFamily marks every token in a family as revoked.
// Called when reuse of a revoked token is detected (suspected theft).
func (d *DB) RevokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE admin_refresh_tokens SET revoked_at = now()
		 WHERE family_id = $1::uuid AND revoked_at IS NULL`, familyID)
	if err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}

// RevokeUserRefreshTokens marks every active token for a user as revoked.
// Used by password-change flows (not implemented yet) and test helpers.
func (d *DB) RevokeUserRefreshTokens(ctx context.Context, userID int) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE admin_refresh_tokens SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("revoke user refresh tokens: %w", err)
	}
	return nil
}

// DeleteExpiredRefreshTokens removes rows whose expires_at is in the past.
// Returns the number of deleted rows.
func (d *DB) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	tag, err := d.Pool.Exec(ctx,
		`DELETE FROM admin_refresh_tokens WHERE expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RotateRefreshToken performs the full enterprise rotation dance in a single
// transaction:
//
//  1. Look up the presented token by hash.
//  2. If it does not exist → return ErrRefreshTokenNotFound (invalid token).
//  3. If expired → revoke it and return ErrRefreshTokenExpired.
//  4. If already revoked → revoke the entire family (reuse attack) and return
//     ErrRefreshTokenReuse. Any outstanding access tokens for this family are
//     already short-lived (15 min) so the window of damage is bounded.
//  5. Otherwise, mark the current row revoked and insert a new row in the same
//     family with parent_id = current.id. Return the new RefreshToken row so
//     the caller can emit a fresh cookie.
//
// The newTokenHash must be computed by the caller (SHA-256 of the new random
// token bytes). The new token's expiration is the caller's responsibility too
// (typically `now() + refresh TTL`).
func (d *DB) RotateRefreshToken(
	ctx context.Context,
	presentedHash []byte,
	newTokenHash []byte,
	newExpiresAt time.Time,
	userAgent, ipAddress string,
) (RefreshToken, error) {
	var newRow RefreshToken

	err := pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		var (
			id        string
			userID    int
			familyID  string
			expiresAt time.Time
			revokedAt *time.Time
		)
		err := tx.QueryRow(ctx, `
			SELECT id::text, user_id, family_id::text, expires_at, revoked_at
			FROM admin_refresh_tokens
			WHERE token_hash = $1
			FOR UPDATE`, presentedHash,
		).Scan(&id, &userID, &familyID, &expiresAt, &revokedAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrRefreshTokenNotFound
			}
			return fmt.Errorf("rotate: lookup: %w", err)
		}

		now := time.Now()
		if now.After(expiresAt) {
			if _, err := tx.Exec(ctx,
				`UPDATE admin_refresh_tokens SET revoked_at = now()
				 WHERE id = $1::uuid AND revoked_at IS NULL`, id); err != nil {
				return fmt.Errorf("rotate: revoke expired: %w", err)
			}
			return ErrRefreshTokenExpired
		}

		if revokedAt != nil {
			// Reuse attack — revoke the whole family.
			if _, err := tx.Exec(ctx,
				`UPDATE admin_refresh_tokens SET revoked_at = now()
				 WHERE family_id = $1::uuid AND revoked_at IS NULL`, familyID); err != nil {
				return fmt.Errorf("rotate: revoke family: %w", err)
			}
			return ErrRefreshTokenReuse
		}

		// Happy path: mark current revoked, insert successor in the same family.
		if _, err := tx.Exec(ctx,
			`UPDATE admin_refresh_tokens SET revoked_at = now(), last_used_at = now()
			 WHERE id = $1::uuid`, id); err != nil {
			return fmt.Errorf("rotate: revoke current: %w", err)
		}

		err = tx.QueryRow(ctx, `
			INSERT INTO admin_refresh_tokens
				(user_id, token_hash, family_id, parent_id, expires_at, user_agent, ip_address)
			VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7)
			RETURNING id::text, user_id, family_id::text, parent_id::text, issued_at, expires_at,
			          revoked_at, last_used_at, COALESCE(user_agent,''), COALESCE(ip_address,'')`,
			userID, newTokenHash, familyID, id, newExpiresAt, userAgent, ipAddress,
		).Scan(&newRow.ID, &newRow.UserID, &newRow.FamilyID, &newRow.ParentID,
			&newRow.IssuedAt, &newRow.ExpiresAt, &newRow.RevokedAt, &newRow.LastUsedAt,
			&newRow.UserAgent, &newRow.IPAddress)
		if err != nil {
			return fmt.Errorf("rotate: insert successor: %w", err)
		}
		return nil
	})
	if err != nil {
		return newRow, err
	}
	return newRow, nil
}

var (
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	ErrRefreshTokenReuse   = errors.New("refresh token reuse detected")
)
