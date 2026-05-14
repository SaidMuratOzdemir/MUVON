package admin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"muvon/internal/alerting"
	"muvon/internal/correlation"
)

// sendTestAlert fires a synthetic correlation.Alert through the same
// notifier implementation the production engine uses. We do not go through
// the correlation engine itself — that would require hitting the log
// pipeline and waiting for a sliding-window threshold — but we DO reuse
// the notifier's real rendering and transport so a pass here means a real
// alert would also reach the channel.
//
// The audit log records who triggered the test so misuse (spamming the
// Slack channel) is traceable.
func sendTestAlert(r *http.Request, channel, webhook string, s *Server) error {
	cfg := s.configHolder.Get().Global
	user, _ := r.Context().Value(usernameKey).(string)
	if user == "" {
		user = "unknown"
	}

	alert := correlation.Alert{
		Rule:        "test",
		Severity:    "info",
		Title:       "MUVON test alert",
		Detail:      map[string]any{"triggered_by": user, "channel": channel, "timestamp": time.Now().UTC().Format(time.RFC3339)},
		Fingerprint: "test:" + user,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var err error
	switch channel {
	case "slack":
		n := alerting.NewSlackNotifier(func() string { return webhook })
		err = n.Send(ctx, alert)
	case "smtp":
		n := alerting.NewEmailNotifier(func() alerting.Config {
			return alerting.Config{
				SMTPHost:     cfg.AlertingSMTPHost,
				SMTPPort:     cfg.AlertingSMTPPort,
				SMTPUsername: cfg.AlertingSMTPUsername,
				SMTPPassword: cfg.AlertingSMTPPassword,
				SMTPFrom:     cfg.AlertingSMTPFrom,
				SMTPTo:       cfg.AlertingSMTPTo,
			}
		})
		err = n.Send(ctx, alert)
	default:
		return fmt.Errorf("unknown channel: %s", channel)
	}

	s.auditLog(r, "alerting.test", "alerting", channel, map[string]any{"success": err == nil})
	return err
}
