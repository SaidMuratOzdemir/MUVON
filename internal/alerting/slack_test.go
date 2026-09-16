package alerting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"muvon/internal/alertrules"
	"muvon/internal/db"
)

func TestSlackSenderPostsRenderedMessage(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request = %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ch := alertrules.Channel{Name: "ops", Kind: alertrules.ChannelSlack, SlackWebhook: srv.URL + "/services/T/B/secret"}
	msg := Message{Kind: db.DeliveryOpened, Alerts: []db.Alert{sampleAlert()}, Channel: ch}
	if err := NewSlackSender().Send(context.Background(), ch, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(got["text"], "[KRİTİK] Mühürleme başarısız") {
		t.Fatalf("posted text = %q", got["text"])
	}
}

// Slack answers a revoked webhook with an error status and a short reason;
// the reason is what the panel should show.
func TestSlackSenderReportsStatusWithoutLeakingWebhook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("no_service"))
	}))
	defer srv.Close()

	ch := alertrules.Channel{Kind: alertrules.ChannelSlack, SlackWebhook: srv.URL + "/services/T/B/secret"}
	err := NewSlackSender().Send(context.Background(), ch, Message{Kind: db.DeliveryTest, Alerts: []db.Alert{sampleAlert()}})
	if err == nil || !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "no_service") {
		t.Fatalf("error = %v, want the status and Slack's reason", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaks the webhook: %v", err)
	}

	// An unreachable host fails too, still without the credential in the text.
	srv.Close()
	err = NewSlackSender().Send(context.Background(), ch, Message{Kind: db.DeliveryTest, Alerts: []db.Alert{sampleAlert()}})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unreachable webhook error = %v", err)
	}
}
