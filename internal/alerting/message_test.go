package alerting

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"muvon/internal/alertrules"
	"muvon/internal/db"
)

func sampleAlert() db.Alert {
	evidence, _ := json.Marshal([]db.AlertEvidence{
		{LogID: "1", Line: "full line with personal data", Fields: map[string]string{"job_family": "seal"}},
	})
	return db.Alert{
		ID:          "0192a000-0000-7000-8000-000000000001",
		RuleName:    "Mühürleme başarısız",
		Severity:    alertrules.SeverityCritical,
		Title:       "Mühürleme başarısız",
		Project:     "shop",
		Component:   "worker",
		GroupKey:    "job_id=42",
		Occurrences: 3,
		FirstSeenAt: time.Date(2026, 9, 15, 6, 20, 0, 0, time.UTC),
		LastSeenAt:  time.Date(2026, 9, 15, 6, 25, 0, 0, time.UTC),
		Evidence:    evidence,
	}
}

func TestMessageRendersTurkishFactsAndLink(t *testing.T) {
	m := Message{
		Kind:     db.DeliveryOpened,
		Alerts:   []db.Alert{sampleAlert()},
		Channel:  alertrules.Channel{Name: "ops", DigestTimezone: "Europe/Istanbul"},
		PanelURL: "https://panel.example.com/",
	}
	text := m.SlackText()
	for _, want := range []string{
		"[KRİTİK] Mühürleme başarısız",
		"Proje: shop / worker",
		"Grup: job_id=42",
		"Tekrar: 3",
		"15.09.2026 09:20 Europe/Istanbul",
		"job_family: seal",
		"<https://panel.example.com/alerts?id=0192a000-0000-7000-8000-000000000001|Panelde aç>",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("slack text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "personal data") {
		t.Error("the raw log line left the server; only chosen fields may")
	}
	if got := m.Subject(); got != "[KRİTİK] Mühürleme başarısız (shop)" {
		t.Errorf("subject = %q", got)
	}
}

func TestMessageKindLabels(t *testing.T) {
	m := Message{Kind: db.DeliveryReminder, Alerts: []db.Alert{sampleAlert()}}
	if !strings.HasPrefix(m.Subject(), "Hatırlatma") {
		t.Errorf("reminder subject = %q", m.Subject())
	}
	m.Kind = db.DeliveryTest
	if !strings.Contains(m.PlainText(), "TEST bildirimi") {
		t.Errorf("test body lacks its label:\n%s", m.PlainText())
	}
}

// A field value comes from an application log. It must not become a Slack
// link or mention.
func TestSlackTextEscapesMarkup(t *testing.T) {
	a := sampleAlert()
	a.Title = "<!channel> <https://evil.example|click>"
	m := Message{Kind: db.DeliveryOpened, Alerts: []db.Alert{a}}
	text := m.SlackText()
	if strings.Contains(text, "<!channel>") || strings.Contains(text, "<https://evil.example") {
		t.Errorf("markup survived:\n%s", text)
	}
}

func TestDigestListsAndCounts(t *testing.T) {
	var alerts []db.Alert
	for i := 0; i < digestLimit+3; i++ {
		alerts = append(alerts, sampleAlert())
	}
	m := Message{Kind: db.DeliveryDigest, Alerts: alerts, Period: "15.09.2026", Channel: alertrules.Channel{Name: "ops"}}
	if !strings.Contains(m.PlainText(), "ve 3 alarm daha") {
		t.Errorf("digest does not count what it left out:\n%s", m.PlainText())
	}
	if !strings.Contains(m.Subject(), "53 alarm") {
		t.Errorf("digest subject = %q", m.Subject())
	}
}

// Titles can come from log content, so a line break must not reach the
// header block.
func TestBuildEmailRejectsHeaderInjection(t *testing.T) {
	msg, err := buildEmail("alerts@example.com", []string{"team@example.com"},
		"Mühürleme\r\nBcc: victim@example.com", "body", time.Now())
	if err != nil {
		t.Fatalf("buildEmail: %v", err)
	}
	headers := strings.SplitN(string(msg), "\r\n\r\n", 2)[0]
	if strings.Contains(headers, "\r\nBcc:") {
		t.Fatalf("injected header present:\n%s", headers)
	}
	if !strings.Contains(headers, "Subject: =?utf-8?q?") {
		t.Fatalf("non-ASCII subject not encoded:\n%s", headers)
	}
	if _, err := buildEmail("not an address", []string{"team@example.com"}, "s", "b", time.Now()); err == nil {
		t.Fatal("an invalid sender was accepted")
	}
}

func TestDeliveryBackoff(t *testing.T) {
	if got := deliveryBackoff(1); got != 30*time.Second {
		t.Errorf("attempt 1 = %v, want 30s", got)
	}
	if got := deliveryBackoff(3); got != 2*time.Minute {
		t.Errorf("attempt 3 = %v, want 2m", got)
	}
	if got := deliveryBackoff(20); got != time.Hour {
		t.Errorf("attempt 20 = %v, want the one hour cap", got)
	}
}

func TestNotificationKind(t *testing.T) {
	instant := db.AlertEvent{Delivery: alertrules.DeliveryInstant}
	for _, tc := range []struct {
		name string
		ev   db.AlertEvent
		res  db.RaiseResult
		want string
	}{
		{"opened", instant, db.RaiseResult{Opened: true}, db.DeliveryOpened},
		{"escalated", instant, db.RaiseResult{Escalated: true}, db.DeliveryEscalated},
		{"repeat is counted, not sent", instant, db.RaiseResult{}, ""},
		{"digest rule opening", db.AlertEvent{Delivery: alertrules.DeliveryDigest}, db.RaiseResult{Opened: true}, ""},
		{"record-only rule", db.AlertEvent{Delivery: alertrules.DeliveryNone}, db.RaiseResult{Opened: true}, ""},
		{"test ignores delivery", db.AlertEvent{Delivery: alertrules.DeliveryDigest, IsTest: true}, db.RaiseResult{Opened: true}, db.DeliveryTest},
	} {
		if got := notificationKind(tc.ev, tc.res); got != tc.want {
			t.Errorf("%s: kind = %q, want %q", tc.name, got, tc.want)
		}
	}
}
