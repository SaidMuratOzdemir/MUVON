package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"muvon/internal/correlation"
)

// SlackNotifier sends alerts to a Slack webhook.
type SlackNotifier struct {
	webhookFn func() string // returns current webhook URL from config
	client    *http.Client
}

func NewSlackNotifier(webhookFn func() string) *SlackNotifier {
	return &SlackNotifier{
		webhookFn: webhookFn,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *SlackNotifier) Name() string { return "slack" }

func (s *SlackNotifier) Send(ctx context.Context, alert correlation.Alert) error {
	webhook := s.webhookFn()
	if webhook == "" {
		return nil
	}

	icon := ":information_source:"
	switch alert.Severity {
	case "warning":
		icon = ":warning:"
	case "critical":
		icon = ":rotating_light:"
	}

	text := fmt.Sprintf("%s *[%s] %s*\n%s", icon, alert.Severity, alert.Title, alert.Rule)
	if alert.SourceIP != "" {
		text += fmt.Sprintf("\nIP: `%s`", alert.SourceIP)
	}
	if alert.Host != "" {
		text += fmt.Sprintf("\nHost: `%s`", alert.Host)
	}

	payload, _ := json.Marshal(map[string]string{"text": text})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("slack: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: send: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack: unexpected status %d", resp.StatusCode)
	}
	return nil
}
