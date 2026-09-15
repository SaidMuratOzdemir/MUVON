package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"muvon/internal/alertrules"
)

// Alert rules and channels live in the muvon schema, which the admin API
// edits, and are read by dialog-siem. Every query names the schema so both
// search paths reach the same tables.

const alertChannelCols = `id::text, name, kind, enabled, slack_webhook, email_to,
	digest_hour, digest_timezone, created_at, updated_at`

func scanAlertChannel(scan func(...any) error) (alertrules.Channel, error) {
	var c alertrules.Channel
	var hour int16
	err := scan(&c.ID, &c.Name, &c.Kind, &c.Enabled, &c.SlackWebhook, &c.EmailTo,
		&hour, &c.DigestTimezone, &c.CreatedAt, &c.UpdatedAt)
	c.DigestHour = int(hour)
	if c.EmailTo == nil {
		c.EmailTo = []string{}
	}
	return c, err
}

// ListAlertChannels returns every channel. SlackWebhook is the stored
// ciphertext.
func (d *DB) ListAlertChannels(ctx context.Context) ([]alertrules.Channel, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+alertChannelCols+` FROM muvon.alert_channels ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list alert channels: %w", err)
	}
	defer rows.Close()
	out := []alertrules.Channel{}
	for rows.Next() {
		c, err := scanAlertChannel(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan alert channel: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetAlertChannel returns one channel, or pgx.ErrNoRows.
func (d *DB) GetAlertChannel(ctx context.Context, id string) (alertrules.Channel, error) {
	return scanAlertChannel(d.Pool.QueryRow(ctx,
		`SELECT `+alertChannelCols+` FROM muvon.alert_channels WHERE id = $1::uuid`, id).Scan)
}

// CreateAlertChannel stores a channel. The webhook must already be encrypted.
func (d *DB) CreateAlertChannel(ctx context.Context, c alertrules.Channel) (alertrules.Channel, error) {
	return scanAlertChannel(d.Pool.QueryRow(ctx, `
		INSERT INTO muvon.alert_channels (name, kind, enabled, slack_webhook, email_to, digest_hour, digest_timezone)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+alertChannelCols,
		c.Name, c.Kind, c.Enabled, c.SlackWebhook, nonNilStrings(c.EmailTo), c.DigestHour, c.DigestTimezone).Scan)
}

// UpdateAlertChannel replaces a channel's editable fields. Kind is fixed at
// creation: a rule routed to a Slack channel should not start receiving
// email because the row was edited.
func (d *DB) UpdateAlertChannel(ctx context.Context, c alertrules.Channel) (alertrules.Channel, error) {
	return scanAlertChannel(d.Pool.QueryRow(ctx, `
		UPDATE muvon.alert_channels
		SET name = $2, enabled = $3, slack_webhook = $4, email_to = $5,
		    digest_hour = $6, digest_timezone = $7, updated_at = now()
		WHERE id = $1::uuid
		RETURNING `+alertChannelCols,
		c.ID, c.Name, c.Enabled, c.SlackWebhook, nonNilStrings(c.EmailTo), c.DigestHour, c.DigestTimezone).Scan)
}

// DeleteAlertChannel removes a channel and, through the join tables, every
// route to it. Reports false when there was nothing to delete.
func (d *DB) DeleteAlertChannel(ctx context.Context, id string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM muvon.alert_channels WHERE id = $1::uuid`, id)
	if err != nil {
		return false, fmt.Errorf("delete alert channel: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

const alertRuleSelect = `
SELECT r.id::text, r.kind, COALESCE(r.builtin_key, ''), r.name, r.description, r.enabled,
       r.project_id, COALESCE(p.slug, ''), r.component, r.match, r.group_by, r.tiers,
       r.notify_fields, r.delivery, r.remind_minutes,
       COALESCE(array_agg(rc.channel_id::text ORDER BY rc.channel_id) FILTER (WHERE rc.channel_id IS NOT NULL), '{}'),
       r.created_at, r.updated_at
FROM muvon.alert_rules r
LEFT JOIN muvon.deploy_projects p ON p.id = r.project_id
LEFT JOIN muvon.alert_rule_channels rc ON rc.rule_id = r.id`

const alertRuleGroupBy = ` GROUP BY r.id, p.slug`

func scanAlertRule(scan func(...any) error) (alertrules.Rule, error) {
	var r alertrules.Rule
	var projectID *int32
	var matchRaw, tiersRaw []byte
	err := scan(&r.ID, &r.Kind, &r.BuiltinKey, &r.Name, &r.Description, &r.Enabled,
		&projectID, &r.ProjectSlug, &r.Component, &matchRaw, &r.GroupBy, &tiersRaw,
		&r.NotifyFields, &r.Delivery, &r.RemindMinutes, &r.ChannelIDs,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	if projectID != nil {
		v := int(*projectID)
		r.ProjectID = &v
	}
	if len(matchRaw) > 0 {
		if err := json.Unmarshal(matchRaw, &r.Match); err != nil {
			return r, fmt.Errorf("rule %s match: %w", r.ID, err)
		}
	}
	if len(tiersRaw) > 0 {
		if err := json.Unmarshal(tiersRaw, &r.Tiers); err != nil {
			return r, fmt.Errorf("rule %s tiers: %w", r.ID, err)
		}
	}
	if r.Match.Any == nil {
		r.Match.Any = []alertrules.MatchClause{}
	}
	for i := range r.Match.Any {
		if r.Match.Any[i].Events == nil {
			r.Match.Any[i].Events = []string{}
		}
		if r.Match.Any[i].Fields == nil {
			r.Match.Any[i].Fields = []alertrules.FieldCondition{}
		}
	}
	if r.Tiers == nil {
		r.Tiers = []alertrules.Tier{}
	}
	if r.NotifyFields == nil {
		r.NotifyFields = []string{}
	}
	if r.ChannelIDs == nil {
		r.ChannelIDs = []string{}
	}
	return r, nil
}

// ListAlertRules returns builtin rules first, then event rules by project and
// name.
func (d *DB) ListAlertRules(ctx context.Context) ([]alertrules.Rule, error) {
	rows, err := d.Pool.Query(ctx, alertRuleSelect+alertRuleGroupBy+
		` ORDER BY r.kind = 'event', p.slug NULLS FIRST, r.name`)
	if err != nil {
		return nil, fmt.Errorf("list alert rules: %w", err)
	}
	defer rows.Close()
	out := []alertrules.Rule{}
	for rows.Next() {
		r, err := scanAlertRule(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan alert rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAlertRule returns one rule, or pgx.ErrNoRows.
func (d *DB) GetAlertRule(ctx context.Context, id string) (alertrules.Rule, error) {
	return scanAlertRule(d.Pool.QueryRow(ctx,
		alertRuleSelect+` WHERE r.id = $1::uuid`+alertRuleGroupBy, id).Scan)
}

// CreateEventRule stores an event rule and its channels in one transaction.
// The caller validates it first.
func (d *DB) CreateEventRule(ctx context.Context, r alertrules.Rule) (alertrules.Rule, error) {
	matchJSON, tiersJSON, err := ruleJSON(r)
	if err != nil {
		return r, err
	}
	var id string
	err = pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO muvon.alert_rules
			  (kind, name, description, enabled, project_id, component, match, group_by,
			   tiers, notify_fields, delivery, remind_minutes)
			VALUES ('event', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			RETURNING id::text`,
			r.Name, r.Description, r.Enabled, r.ProjectID, r.Component, matchJSON, r.GroupBy,
			tiersJSON, nonNilStrings(r.NotifyFields), r.Delivery, r.RemindMinutes).Scan(&id); err != nil {
			return fmt.Errorf("insert alert rule: %w", err)
		}
		return setRuleChannels(ctx, tx, id, r.ChannelIDs)
	})
	if err != nil {
		return r, err
	}
	return d.GetAlertRule(ctx, id)
}

// UpdateEventRule replaces an event rule. Kind is fixed.
func (d *DB) UpdateEventRule(ctx context.Context, r alertrules.Rule) (alertrules.Rule, error) {
	matchJSON, tiersJSON, err := ruleJSON(r)
	if err != nil {
		return r, err
	}
	err = pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE muvon.alert_rules
			SET name = $2, description = $3, enabled = $4, project_id = $5, component = $6,
			    match = $7, group_by = $8, tiers = $9, notify_fields = $10, delivery = $11,
			    remind_minutes = $12, updated_at = now()
			WHERE id = $1::uuid AND kind = 'event'`,
			r.ID, r.Name, r.Description, r.Enabled, r.ProjectID, r.Component, matchJSON, r.GroupBy,
			tiersJSON, nonNilStrings(r.NotifyFields), r.Delivery, r.RemindMinutes)
		if err != nil {
			return fmt.Errorf("update alert rule: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return setRuleChannels(ctx, tx, r.ID, r.ChannelIDs)
	})
	if err != nil {
		return r, err
	}
	return d.GetAlertRule(ctx, r.ID)
}

// UpdateBuiltinRule changes what the operator owns on a builtin rule: whether
// it runs and where it notifies. Its name and logic belong to the release.
func (d *DB) UpdateBuiltinRule(ctx context.Context, id string, enabled bool, delivery string, remindMinutes int, channelIDs []string) (alertrules.Rule, error) {
	err := pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE muvon.alert_rules
			SET enabled = $2, delivery = $3, remind_minutes = $4, updated_at = now()
			WHERE id = $1::uuid AND kind = 'builtin'`,
			id, enabled, delivery, remindMinutes)
		if err != nil {
			return fmt.Errorf("update builtin rule: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return setRuleChannels(ctx, tx, id, channelIDs)
	})
	if err != nil {
		return alertrules.Rule{}, err
	}
	return d.GetAlertRule(ctx, id)
}

// DeleteEventRule removes an event rule. Builtin rules are refused: the next
// boot would restore them, so they are disabled instead.
func (d *DB) DeleteEventRule(ctx context.Context, id string) (bool, error) {
	tag, err := d.Pool.Exec(ctx,
		`DELETE FROM muvon.alert_rules WHERE id = $1::uuid AND kind = 'event'`, id)
	if err != nil {
		return false, fmt.Errorf("delete alert rule: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func setRuleChannels(ctx context.Context, tx pgx.Tx, ruleID string, channelIDs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM muvon.alert_rule_channels WHERE rule_id = $1::uuid`, ruleID); err != nil {
		return fmt.Errorf("clear rule channels: %w", err)
	}
	if len(channelIDs) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO muvon.alert_rule_channels (rule_id, channel_id)
		SELECT $1::uuid, c::uuid FROM unnest($2::text[]) AS c
		ON CONFLICT DO NOTHING`, ruleID, channelIDs); err != nil {
		return fmt.Errorf("set rule channels: %w", err)
	}
	return nil
}

func ruleJSON(r alertrules.Rule) (matchJSON, tiersJSON []byte, err error) {
	if matchJSON, err = json.Marshal(r.Match); err != nil {
		return nil, nil, fmt.Errorf("encode match: %w", err)
	}
	if tiersJSON, err = json.Marshal(r.Tiers); err != nil {
		return nil, nil, fmt.Errorf("encode tiers: %w", err)
	}
	return matchJSON, tiersJSON, nil
}

// ListProjectAlertChannels maps a project slug to its default channel ids.
func (d *DB) ListProjectAlertChannels(ctx context.Context) (map[string][]string, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT p.slug, pc.channel_id::text
		FROM muvon.project_alert_channels pc
		JOIN muvon.deploy_projects p ON p.id = pc.project_id
		ORDER BY p.slug, pc.channel_id`)
	if err != nil {
		return nil, fmt.Errorf("list project alert channels: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var slug, channelID string
		if err := rows.Scan(&slug, &channelID); err != nil {
			return nil, fmt.Errorf("scan project alert channel: %w", err)
		}
		out[slug] = append(out[slug], channelID)
	}
	return out, rows.Err()
}

// SetProjectAlertChannels replaces a project's default channels.
func (d *DB) SetProjectAlertChannels(ctx context.Context, projectID int, channelIDs []string) error {
	return pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM muvon.project_alert_channels WHERE project_id = $1`, projectID); err != nil {
			return fmt.Errorf("clear project alert channels: %w", err)
		}
		if len(channelIDs) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO muvon.project_alert_channels (project_id, channel_id)
			SELECT $1, c::uuid FROM unnest($2::text[]) AS c
			ON CONFLICT DO NOTHING`, projectID, channelIDs); err != nil {
			return fmt.Errorf("set project alert channels: %w", err)
		}
		return nil
	})
}

// SyncBuiltinAlertRules inserts builtin rules that are missing and refreshes
// the name and description of existing ones, reporting how many were added.
// A new builtin records alerts without notifying until the operator routes
// it; enabled, delivery, reminders and channels are never overwritten.
func (d *DB) SyncBuiltinAlertRules(ctx context.Context, builtins []alertrules.Builtin) (int, error) {
	added := 0
	for _, b := range builtins {
		var inserted bool
		err := d.Pool.QueryRow(ctx, `
			INSERT INTO muvon.alert_rules (kind, builtin_key, name, description, delivery)
			VALUES ('builtin', $1, $2, $3, 'none')
			ON CONFLICT (builtin_key) DO UPDATE
			SET name = EXCLUDED.name, description = EXCLUDED.description
			WHERE (alert_rules.name, alert_rules.description) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.description)
			RETURNING xmax = 0`, b.Key, b.Name, b.Description).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // unchanged
		}
		if err != nil {
			return added, fmt.Errorf("sync builtin rule %s: %w", b.Key, err)
		}
		if inserted {
			added++
		}
	}
	return added, nil
}

// legacyAlertingKeys are the settings replaced by named channels and per-rule
// routing.
var legacyAlertingKeys = []string{
	"alerting_enabled",
	"alerting_slack_webhook",
	"alerting_smtp_to",
	"alerting_cooldown_seconds",
}

// MigrateLegacyAlertingSettings turns the single global Slack webhook and
// recipient list into named channels, then removes the old keys. An install
// that had notifications on keeps them: its channels are routed from every
// builtin rule, which is what the global switch meant. Run after
// SyncBuiltinAlertRules; a no-op once the keys are gone. encrypt protects the
// webhook, which the old setting stored in plaintext.
func (d *DB) MigrateLegacyAlertingSettings(ctx context.Context, encrypt func(string) (string, error)) (migrated bool, err error) {
	settings, err := d.GetAllSettings(ctx)
	if err != nil {
		return false, err
	}
	present := false
	for _, k := range legacyAlertingKeys {
		if _, ok := settings[k]; ok {
			present = true
		}
	}
	if !present {
		return false, nil
	}

	str := func(key string) string {
		var s string
		if raw, ok := settings[key]; ok {
			if json.Unmarshal(raw, &s) != nil {
				s = string(raw)
			}
		}
		return strings.TrimSpace(s)
	}
	enabled := str("alerting_enabled") == "true"
	webhook := str("alerting_slack_webhook")
	var recipients []string
	for _, r := range strings.Split(str("alerting_smtp_to"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			recipients = append(recipients, r)
		}
	}

	encWebhook := ""
	if webhook != "" {
		if encWebhook, err = encrypt(webhook); err != nil {
			return false, fmt.Errorf("encrypt legacy slack webhook: %w", err)
		}
	}

	err = pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		var channelIDs []string
		insert := func(name, kind, webhook string, to []string) error {
			var id string
			err := tx.QueryRow(ctx, `
				INSERT INTO muvon.alert_channels (name, kind, slack_webhook, email_to)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (name) DO NOTHING
				RETURNING id::text`, name, kind, webhook, nonNilStrings(to)).Scan(&id)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // a channel by that name already exists; leave it
			}
			if err != nil {
				return fmt.Errorf("create legacy %s channel: %w", kind, err)
			}
			channelIDs = append(channelIDs, id)
			return nil
		}
		if encWebhook != "" {
			if err := insert("Slack", "slack", encWebhook, nil); err != nil {
				return err
			}
		}
		if len(recipients) > 0 {
			if err := insert("E-posta", "email", "", recipients); err != nil {
				return err
			}
		}
		if enabled && len(channelIDs) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE muvon.alert_rules SET delivery = 'instant', updated_at = now() WHERE kind = 'builtin'`); err != nil {
				return fmt.Errorf("route builtin rules: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO muvon.alert_rule_channels (rule_id, channel_id)
				SELECT r.id, c::uuid FROM muvon.alert_rules r, unnest($1::text[]) AS c
				WHERE r.kind = 'builtin'
				ON CONFLICT DO NOTHING`, channelIDs); err != nil {
				return fmt.Errorf("route builtin rules to channels: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM muvon.settings WHERE key = ANY($1)`, legacyAlertingKeys); err != nil {
			return fmt.Errorf("delete legacy alerting settings: %w", err)
		}
		return nil
	})
	return err == nil, err
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
