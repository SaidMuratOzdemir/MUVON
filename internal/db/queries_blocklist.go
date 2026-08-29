package db

import (
	"context"
	"time"

	"muvon/internal/blocklist"
)

// ListBlocklistPatterns returns every pattern row, enabled or not. The caller
// compiles the enabled ones; the panel needs the disabled ones too so the
// operator can see what they switched off.
func (db *DB) ListBlocklistPatterns(ctx context.Context) ([]blocklist.Pattern, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT kind, pattern, score, rule, enabled, builtin, note
		FROM blocklist_patterns
		ORDER BY score DESC, kind, pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []blocklist.Pattern
	for rows.Next() {
		var p blocklist.Pattern
		if err := rows.Scan(&p.Kind, &p.Pattern, &p.Score, &p.Rule, &p.Enabled, &p.Builtin, &p.Note); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SyncBuiltinPatterns inserts the shipped defaults that are not in the table
// yet and reports how many were added.
//
// It deliberately does NOT update existing rows. A builtin pattern the operator
// disabled stays disabled, and a score they tuned stays tuned; upgrades add
// coverage, they do not undo local decisions. That is also why the panel offers
// disable rather than delete for builtin rows: a deleted one would come back on
// the next boot.
func (db *DB) SyncBuiltinPatterns(ctx context.Context, defaults []blocklist.Pattern) (int, error) {
	added := 0
	for _, p := range defaults {
		tag, err := db.Pool.Exec(ctx, `
			INSERT INTO blocklist_patterns (kind, pattern, score, rule, enabled, builtin, note)
			VALUES ($1, $2, $3, $4, TRUE, TRUE, $5)
			ON CONFLICT (kind, pattern) DO NOTHING`,
			p.Kind, p.Pattern, p.Score, p.Rule, p.Note)
		if err != nil {
			return added, err
		}
		added += int(tag.RowsAffected())
	}
	return added, nil
}

// UpsertBlocklistPattern creates or edits an operator-owned pattern. Builtin
// rows can have their score, enabled flag and note changed but keep builtin=true
// so the panel can still tell them apart.
func (db *DB) UpsertBlocklistPattern(ctx context.Context, p blocklist.Pattern) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO blocklist_patterns (kind, pattern, score, rule, enabled, builtin, note)
		VALUES ($1, $2, $3, $4, $5, FALSE, $6)
		ON CONFLICT (kind, pattern) DO UPDATE
		SET score = EXCLUDED.score,
		    rule = EXCLUDED.rule,
		    enabled = EXCLUDED.enabled,
		    note = EXCLUDED.note,
		    updated_at = now()`,
		p.Kind, p.Pattern, p.Score, p.Rule, p.Enabled, p.Note)
	return err
}

// DeleteBlocklistPattern removes an operator-added pattern. Builtin rows are
// refused: deleting one would only last until the next boot, so the panel
// disables them instead.
func (db *DB) DeleteBlocklistPattern(ctx context.Context, kind, pattern string) (bool, error) {
	tag, err := db.Pool.Exec(ctx,
		`DELETE FROM blocklist_patterns WHERE kind = $1 AND pattern = $2 AND builtin = FALSE`,
		kind, pattern)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ListActiveIPBlocks returns blocks that are still in force. Loaded at startup
// so a restart does not hand every blocked scanner a clean slate.
func (db *DB) ListActiveIPBlocks(ctx context.Context) ([]blocklist.Block, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT block_key, rule, pattern, score, ban_count, permanent, created_at, expires_at
		FROM ip_blocks
		WHERE permanent OR expires_at > now()
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []blocklist.Block
	for rows.Next() {
		var b blocklist.Block
		if err := rows.Scan(&b.Key, &b.Rule, &b.Pattern, &b.Score,
			&b.BanCount, &b.Permanent, &b.CreatedAt, &b.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// UpsertIPBlock persists a block. sourceHost records which edge decided it,
// which matters in a fleet: the operator needs to know where a block came from
// before lifting it.
func (db *DB) UpsertIPBlock(ctx context.Context, b blocklist.Block, sourceHost, createdBy string) error {
	if createdBy == "" {
		createdBy = "auto"
	}
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO ip_blocks
		  (block_key, rule, pattern, score, ban_count, permanent, source_host, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (block_key) DO UPDATE
		SET rule = EXCLUDED.rule,
		    pattern = EXCLUDED.pattern,
		    score = EXCLUDED.score,
		    ban_count = EXCLUDED.ban_count,
		    permanent = EXCLUDED.permanent,
		    source_host = EXCLUDED.source_host,
		    expires_at = EXCLUDED.expires_at`,
		b.Key, b.Rule, b.Pattern, b.Score, b.BanCount, b.Permanent,
		sourceHost, createdBy, b.CreatedAt, b.ExpiresAt)
	return err
}

// DeleteIPBlock lifts one block. Reports false when there was nothing to lift.
func (db *DB) DeleteIPBlock(ctx context.Context, key string) (bool, error) {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM ip_blocks WHERE block_key = $1`, key)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// FlushIPBlocks clears every block. This is the panic button behind the panel's
// "release everything" action, for when a block is cutting real traffic.
func (db *DB) FlushIPBlocks(ctx context.Context) (int, error) {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM ip_blocks`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// PurgeExpiredIPBlocks drops lapsed rows so the table tracks live state only.
// Permanent blocks are never purged.
func (db *DB) PurgeExpiredIPBlocks(ctx context.Context) (int, error) {
	tag, err := db.Pool.Exec(ctx,
		`DELETE FROM ip_blocks WHERE NOT permanent AND expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// BlocklistSettings is the tunable set the proxy reads through the config
// holder. Kept here so the settings keys have exactly one definition.
type BlocklistSettings struct {
	Enabled    bool
	Threshold  int
	Window     time.Duration
	BaseTTL    time.Duration
	MaxTTL     time.Duration
	MaxEntries int
	Allowlist  []string
}
