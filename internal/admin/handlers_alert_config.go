package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"muvon/internal/alerting"
	"muvon/internal/alertrules"
	"muvon/internal/db"
)

// Alert rules and channels. The admin API edits them; dialog-siem reloads
// them within seconds. A Slack webhook is a credential: it is encrypted
// before it is stored and no response carries it back.

// channelResponse is a channel as the panel sees it.
type channelResponse struct {
	alertrules.Channel
	HasWebhook  bool   `json:"has_webhook"`
	WebhookHost string `json:"webhook_host,omitempty"`
}

type channelRequest struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	Enabled        *bool    `json:"enabled"`
	SlackWebhook   string   `json:"slack_webhook"`
	EmailTo        []string `json:"email_to"`
	DigestHour     *int     `json:"digest_hour"`
	DigestTimezone string   `json:"digest_timezone"`
}

func (s *Server) channelView(c alertrules.Channel) channelResponse {
	out := channelResponse{Channel: c}
	if c.SlackWebhook != "" {
		out.HasWebhook = true
		if plain, err := s.secretBox.Decrypt(c.SlackWebhook); err == nil {
			if u, err := url.Parse(plain); err == nil {
				out.WebhookHost = u.Host
			}
		}
	}
	out.SlackWebhook = ""
	return out
}

func writeError(w http.ResponseWriter, status int, err error) {
	body := map[string]string{"error": err.Error()}
	var ve *alertrules.ValidationError
	if errors.As(err, &ve) {
		body["field"] = ve.Field
	}
	writeJSON(w, status, body)
}

func decodeStrict(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid JSON: " + err.Error())
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Server) handleListAlertChannels(w http.ResponseWriter, r *http.Request) {
	channels, err := s.db.ListAlertChannels(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]channelResponse, 0, len(channels))
	for _, c := range channels {
		out = append(out, s.channelView(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateAlertChannel(w http.ResponseWriter, r *http.Request) {
	var req channelRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	c := alertrules.Channel{
		Name:           strings.TrimSpace(req.Name),
		Kind:           req.Kind,
		Enabled:        req.Enabled == nil || *req.Enabled,
		SlackWebhook:   strings.TrimSpace(req.SlackWebhook),
		EmailTo:        trimAll(req.EmailTo),
		DigestTimezone: req.DigestTimezone,
		DigestHour:     9,
	}
	if req.DigestHour != nil {
		c.DigestHour = *req.DigestHour
	}
	if c.DigestTimezone == "" {
		c.DigestTimezone = "UTC"
	}
	if err := alertrules.ValidateChannel(c, true); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.encryptWebhook(&c); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	created, err := s.db.CreateAlertChannel(r.Context(), c)
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, errors.New("a channel with this name already exists"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditLog(r, "alert.channel.create", "alert_channel", created.ID, map[string]any{"name": created.Name, "kind": created.Kind})
	writeJSON(w, http.StatusCreated, s.channelView(created))
}

// handleUpdateAlertChannel replaces a channel's settings. An empty webhook
// keeps the stored one, so editing a channel does not require the credential
// to be typed again. The kind cannot change.
func (s *Server) handleUpdateAlertChannel(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.loadChannel(w, r)
	if !ok {
		return
	}
	var req channelRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Kind != "" && req.Kind != existing.Kind {
		writeError(w, http.StatusBadRequest, &alertrules.ValidationError{Field: "kind", Reason: "cannot change; create a new channel instead"})
		return
	}
	c := existing
	c.Name = strings.TrimSpace(req.Name)
	if req.Enabled != nil {
		c.Enabled = *req.Enabled
	}
	c.EmailTo = trimAll(req.EmailTo)
	if req.DigestHour != nil {
		c.DigestHour = *req.DigestHour
	}
	if req.DigestTimezone != "" {
		c.DigestTimezone = req.DigestTimezone
	}
	newWebhook := strings.TrimSpace(req.SlackWebhook)
	c.SlackWebhook = newWebhook
	if err := alertrules.ValidateChannel(c, false); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if newWebhook == "" {
		c.SlackWebhook = existing.SlackWebhook
	} else if err := s.encryptWebhook(&c); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	updated, err := s.db.UpdateAlertChannel(r.Context(), c)
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, errors.New("a channel with this name already exists"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditLog(r, "alert.channel.update", "alert_channel", updated.ID, map[string]any{
		"name": updated.Name, "enabled": updated.Enabled, "webhook_changed": newWebhook != "",
	})
	writeJSON(w, http.StatusOK, s.channelView(updated))
}

func (s *Server) handleDeleteAlertChannel(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.loadChannel(w, r)
	if !ok {
		return
	}
	if _, err := s.db.DeleteAlertChannel(r.Context(), existing.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditLog(r, "alert.channel.delete", "alert_channel", existing.ID, map[string]any{"name": existing.Name})
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// handleTestAlertChannel sends a sample notification now and reports the
// outcome, so a wrong webhook or SMTP account shows up here instead of on the
// day an alert matters. Nothing is stored.
func (s *Server) handleTestAlertChannel(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.loadChannel(w, r)
	if !ok {
		return
	}
	if existing.SlackWebhook != "" {
		plain, err := s.secretBox.Decrypt(existing.SlackWebhook)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("the stored webhook cannot be decrypted with the current encryption key"))
			return
		}
		existing.SlackWebhook = plain
	}
	sender, ok := s.alertSenders()[existing.Kind]
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("no sender for channel kind "+existing.Kind))
		return
	}

	user, _ := r.Context().Value(usernameKey).(string)
	now := time.Now()
	msg := alerting.Message{
		Kind:    db.DeliveryTest,
		Channel: existing,
		Alerts: []db.Alert{{
			ID:          uuid.NewString(),
			RuleName:    "Kanal testi",
			Severity:    alertrules.SeverityInfo,
			Title:       "MUVON kanal testi: " + existing.Name,
			Occurrences: 1,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := sender.Send(ctx, existing, msg)
	s.auditLog(r, "alert.channel.test", "alert_channel", existing.ID, map[string]any{"success": err == nil, "by": user})
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Server) loadChannel(w http.ResponseWriter, r *http.Request) (alertrules.Channel, bool) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeError(w, http.StatusNotFound, errors.New("channel not found"))
		return alertrules.Channel{}, false
	}
	c, err := s.db.GetAlertChannel(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, errors.New("channel not found"))
		return c, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return c, false
	}
	return c, true
}

func (s *Server) encryptWebhook(c *alertrules.Channel) error {
	if c.SlackWebhook == "" {
		return nil
	}
	enc, err := s.secretBox.Encrypt(c.SlackWebhook)
	if err != nil {
		return errors.New("encryption failed")
	}
	c.SlackWebhook = enc
	return nil
}

// alertSenders returns the senders channel tests use. Tests replace them.
func (s *Server) alertSenders() map[string]alerting.Sender {
	if s.testAlertSenders != nil {
		return s.testAlertSenders
	}
	return map[string]alerting.Sender{
		alertrules.ChannelSlack: alerting.NewSlackSender(),
		alertrules.ChannelEmail: &alerting.EmailSender{Config: func() alerting.SMTPConfig {
			g := s.configHolder.Get().Global
			return alerting.SMTPConfig{
				Host: g.AlertingSMTPHost, Port: g.AlertingSMTPPort,
				Username: g.AlertingSMTPUsername, Password: g.AlertingSMTPPassword, From: g.AlertingSMTPFrom,
			}
		}},
	}
}

type ruleRequest struct {
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Enabled       *bool             `json:"enabled"`
	Project       string            `json:"project"`
	Component     string            `json:"component"`
	Match         alertrules.Match  `json:"match"`
	GroupBy       string            `json:"group_by"`
	Tiers         []alertrules.Tier `json:"tiers"`
	NotifyFields  []string          `json:"notify_fields"`
	Delivery      string            `json:"delivery"`
	RemindMinutes *int              `json:"remind_minutes"`
	ChannelIDs    []string          `json:"channel_ids"`
}

func (s *Server) handleListAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.db.ListAlertRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleGetAlertRule(w http.ResponseWriter, r *http.Request) {
	rule, ok := s.loadRule(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleCreateAlertRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rule := alertrules.Rule{Kind: alertrules.KindEvent, RemindMinutes: 240}
	if err := s.applyEventRuleRequest(r.Context(), &rule, req); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	created, err := s.db.CreateEventRule(r.Context(), rule)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditLog(r, "alert.rule.create", "alert_rule", created.ID, map[string]any{"name": created.Name, "project": created.ProjectSlug})
	writeJSON(w, http.StatusCreated, created)
}

// handleUpdateAlertRule replaces an event rule. On a builtin rule only what
// the operator owns applies: whether it runs, how it is delivered, reminders
// and channels.
func (s *Server) handleUpdateAlertRule(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.loadRule(w, r)
	if !ok {
		return
	}
	var req ruleRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if existing.Kind == alertrules.KindBuiltin {
		enabled := existing.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		remind := existing.RemindMinutes
		if req.RemindMinutes != nil {
			remind = *req.RemindMinutes
		}
		delivery := req.Delivery
		if delivery == "" {
			delivery = existing.Delivery
		}
		channels := nonNil(req.ChannelIDs)
		if err := alertrules.ValidateRouting(delivery, remind, channels); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.checkChannelsExist(r.Context(), channels); err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		updated, err := s.db.UpdateBuiltinRule(r.Context(), existing.ID, enabled, delivery, remind, channels)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.auditLog(r, "alert.rule.update", "alert_rule", updated.ID, map[string]any{
			"builtin": updated.BuiltinKey, "enabled": enabled, "delivery": delivery, "channels": len(channels),
		})
		writeJSON(w, http.StatusOK, updated)
		return
	}

	rule := existing
	if err := s.applyEventRuleRequest(r.Context(), &rule, req); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	updated, err := s.db.UpdateEventRule(r.Context(), rule)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditLog(r, "alert.rule.update", "alert_rule", updated.ID, map[string]any{"name": updated.Name, "enabled": updated.Enabled})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteAlertRule(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.loadRule(w, r)
	if !ok {
		return
	}
	if existing.Kind == alertrules.KindBuiltin {
		writeError(w, http.StatusConflict, errors.New("built-in rules can be disabled but not deleted, because the next restart would restore them"))
		return
	}
	if _, err := s.db.DeleteEventRule(r.Context(), existing.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditLog(r, "alert.rule.delete", "alert_rule", existing.ID, map[string]any{"name": existing.Name})
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// handleTestAlertRule opens a test alert for the rule and queues a test
// notification to every channel it routes to, whatever its delivery mode.
// dialog-siem sends it within seconds; the alert's deliveries show whether
// each channel took it.
func (s *Server) handleTestAlertRule(w http.ResponseWriter, r *http.Request) {
	rule, ok := s.loadRule(w, r)
	if !ok {
		return
	}
	snap, err := s.alertSnapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	channels := snap.ChannelsFor(rule)
	if len(channels) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("the rule notifies no enabled channel; add a channel to the rule or to its project"))
		return
	}

	severity := alertrules.SeverityInfo
	if len(rule.Tiers) > 0 {
		severity = rule.Tiers[len(rule.Tiers)-1].Severity
	}
	user, _ := r.Context().Value(usernameKey).(string)
	detail, _ := json.Marshal(map[string]string{"triggered_by": user})
	ev := db.AlertEvent{
		Rule:        alertrules.KindEvent,
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    severity,
		Title:       rule.Name,
		Detail:      detail,
		Project:     rule.ProjectSlug,
		Fingerprint: "test:" + rule.ID + ":" + uuid.NewString(),
		Delivery:    rule.Delivery,
		IsTest:      true,
		Occurrences: 1,
		At:          time.Now(),
	}
	if rule.Kind == alertrules.KindBuiltin {
		ev.Rule = rule.BuiltinKey
	}

	var res db.RaiseResult
	err = pgx.BeginFunc(r.Context(), s.db.Pool, func(tx pgx.Tx) error {
		var err error
		if res, err = db.RaiseAlert(r.Context(), tx, ev); err != nil {
			return err
		}
		return db.QueueAlertDeliveries(r.Context(), tx, []string{res.AlertID}, channels, db.DeliveryTest, severity)
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	names := make([]string, 0, len(channels))
	for _, c := range channels {
		names = append(names, c.Name)
	}
	s.auditLog(r, "alert.rule.test", "alert_rule", rule.ID, map[string]any{"alert_id": res.AlertID, "channels": names})
	writeJSON(w, http.StatusAccepted, map[string]any{"alert_id": res.AlertID, "channels": names})
}

func (s *Server) loadRule(w http.ResponseWriter, r *http.Request) (alertrules.Rule, bool) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeError(w, http.StatusNotFound, errors.New("rule not found"))
		return alertrules.Rule{}, false
	}
	rule, err := s.db.GetAlertRule(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, errors.New("rule not found"))
		return rule, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return rule, false
	}
	return rule, true
}

// errNotFound marks a referenced object that does not exist, which is the
// caller's mistake rather than a server failure.
type errNotFound struct{ msg string }

func (e errNotFound) Error() string { return e.msg }

func statusFor(err error) int {
	var nf errNotFound
	switch {
	case alertrules.IsValidationError(err), errors.As(err, &nf):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// applyEventRuleRequest copies a request onto a rule, resolves its project
// and checks every reference before anything is stored.
func (s *Server) applyEventRuleRequest(ctx context.Context, rule *alertrules.Rule, req ruleRequest) error {
	rule.Name = strings.TrimSpace(req.Name)
	rule.Description = strings.TrimSpace(req.Description)
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	} else if rule.ID == "" {
		rule.Enabled = true
	}
	rule.Component = strings.TrimSpace(req.Component)
	rule.Match = req.Match
	rule.GroupBy = strings.TrimSpace(req.GroupBy)
	rule.Tiers = req.Tiers
	rule.NotifyFields = nonNil(req.NotifyFields)
	rule.Delivery = req.Delivery
	if req.RemindMinutes != nil {
		rule.RemindMinutes = *req.RemindMinutes
	}
	rule.ChannelIDs = nonNil(req.ChannelIDs)

	project := strings.TrimSpace(req.Project)
	if project == "" {
		return &alertrules.ValidationError{Field: "project", Reason: "is required"}
	}
	p, err := s.db.GetDeployProjectBySlug(ctx, project)
	if errors.Is(err, pgx.ErrNoRows) {
		return &alertrules.ValidationError{Field: "project", Reason: "no active project named " + project}
	}
	if err != nil {
		return err
	}
	rule.ProjectID = &p.ID
	rule.ProjectSlug = p.Slug

	if err := alertrules.ValidateEventRule(*rule); err != nil {
		return err
	}
	if rule.Component != "" {
		components, err := s.db.ListDeployComponents(ctx, p.ID)
		if err != nil {
			return err
		}
		found := false
		for _, c := range components {
			if c.Slug == rule.Component {
				found = true
				break
			}
		}
		if !found {
			return &alertrules.ValidationError{Field: "component", Reason: "project " + p.Slug + " has no component " + rule.Component}
		}
	}
	return s.checkChannelsExist(ctx, rule.ChannelIDs)
}

func (s *Server) checkChannelsExist(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	channels, err := s.db.ListAlertChannels(ctx)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, c := range channels {
		known[c.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return &alertrules.ValidationError{Field: "channel_ids", Reason: "no channel " + id}
		}
	}
	return nil
}

func (s *Server) alertSnapshot(ctx context.Context) (*alertrules.Snapshot, error) {
	channels, err := s.db.ListAlertChannels(ctx)
	if err != nil {
		return nil, err
	}
	rules, err := s.db.ListAlertRules(ctx)
	if err != nil {
		return nil, err
	}
	projects, err := s.db.ListProjectAlertChannels(ctx)
	if err != nil {
		return nil, err
	}
	return alertrules.NewSnapshot(channels, rules, projects), nil
}

type projectChannelsResponse struct {
	Project    string   `json:"project"`
	Name       string   `json:"name"`
	ChannelIDs []string `json:"channel_ids"`
}

func (s *Server) handleListAlertProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.db.ListDeployProjects(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defaults, err := s.db.ListProjectAlertChannels(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]projectChannelsResponse, 0, len(projects))
	for _, p := range projects {
		out = append(out, projectChannelsResponse{
			Project: p.Project.Slug, Name: p.Project.Name, ChannelIDs: nonNil(defaults[p.Project.Slug]),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetAlertProjectChannels(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	p, err := s.db.GetDeployProjectBySlug(r.Context(), slug)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, errors.New("project not found"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var req struct {
		ChannelIDs []string `json:"channel_ids"`
	}
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ids := nonNil(req.ChannelIDs)
	if err := alertrules.ValidateRouting(alertrules.DeliveryInstant, 0, ids); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.checkChannelsExist(r.Context(), ids); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	if err := s.db.SetProjectAlertChannels(r.Context(), p.ID, ids); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditLog(r, "alert.project.channels", "deploy_project", p.Slug, map[string]any{"channels": len(ids)})
	writeJSON(w, http.StatusOK, projectChannelsResponse{Project: p.Slug, Name: p.Name, ChannelIDs: ids})
}

// handleListProjectEvents lists what a project's applications have logged as
// events recently, so a rule is written against real event and field names.
func (s *Server) handleListProjectEvents(w http.ResponseWriter, r *http.Request) {
	project := strings.TrimSpace(r.URL.Query().Get("project"))
	if project == "" {
		writeError(w, http.StatusBadRequest, errors.New("project is required"))
		return
	}
	events, err := s.db.ListProjectEvents(r.Context(), project, strings.TrimSpace(r.URL.Query().Get("component")), time.Now().Add(-7*24*time.Hour))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
