package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"muvon/internal/alertrules"
)

// Sender delivers a message to one channel.
type Sender interface {
	Send(ctx context.Context, ch alertrules.Channel, m Message) error
}

// SlackSender posts to a channel's incoming webhook.
type SlackSender struct {
	Client *http.Client
}

// NewSlackSender returns a sender with a bounded HTTP client.
func NewSlackSender() *SlackSender {
	return &SlackSender{Client: &http.Client{Timeout: 10 * time.Second}}
}

func (s *SlackSender) Send(ctx context.Context, ch alertrules.Channel, m Message) error {
	if ch.SlackWebhook == "" {
		return errors.New("slack: channel has no usable webhook")
	}
	payload, err := json.Marshal(map[string]string{"text": m.SlackText()})
	if err != nil {
		return fmt.Errorf("slack: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.SlackWebhook, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("slack: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		// The URL carries the credential; do not echo it into an error that
		// ends up on the panel.
		var urlErr interface{ Unwrap() error }
		if errors.As(err, &urlErr) {
			return fmt.Errorf("slack: send: %w", urlErr.Unwrap())
		}
		return errors.New("slack: send failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack: status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}
