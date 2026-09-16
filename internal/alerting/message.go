package alerting

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"muvon/internal/alertrules"
	"muvon/internal/db"
)

// Message is what one delivery says. It is rendered at send time from the
// alerts' current state, so a reminder reports the count as it is then.
type Message struct {
	Kind    string
	Alerts  []db.Alert
	Channel alertrules.Channel
	// PanelURL is the admin panel's base address; empty leaves links out.
	PanelURL string
	// Period labels a digest, such as its date.
	Period string
}

// digestLimit caps the alerts listed in one digest; the rest are counted.
const digestLimit = 50

func severityLabel(s string) string {
	switch s {
	case alertrules.SeverityCritical:
		return "KRİTİK"
	case alertrules.SeverityHigh:
		return "YÜKSEK"
	case alertrules.SeverityWarning:
		return "UYARI"
	case alertrules.SeverityInfo:
		return "BİLGİ"
	}
	return strings.ToUpper(s)
}

func kindLabel(kind string) string {
	switch kind {
	case db.DeliveryEscalated:
		return "Önem yükseldi"
	case db.DeliveryReminder:
		return "Hatırlatma: alarm hâlâ onaylanmadı"
	case db.DeliveryTest:
		return "TEST bildirimi"
	}
	return ""
}

func (m Message) location() *time.Location {
	if m.Channel.DigestTimezone != "" {
		if loc, err := time.LoadLocation(m.Channel.DigestTimezone); err == nil {
			return loc
		}
	}
	return time.UTC
}

func (m Message) formatTime(t time.Time) string {
	loc := m.location()
	return t.In(loc).Format("02.01.2006 15:04") + " " + loc.String()
}

func (m Message) alertURL(a db.Alert) string {
	if m.PanelURL == "" {
		return ""
	}
	return strings.TrimRight(m.PanelURL, "/") + "/alerts?id=" + a.ID
}

// alertLines renders the facts of one alert, without its heading.
func (m Message) alertLines(a db.Alert) []string {
	lines := []string{"Kural: " + a.RuleName}
	switch {
	case a.Project != "" && a.Component != "":
		lines = append(lines, "Proje: "+a.Project+" / "+a.Component)
	case a.Project != "":
		lines = append(lines, "Proje: "+a.Project)
	}
	if a.Host != "" {
		lines = append(lines, "Host: "+a.Host)
	}
	if a.SourceIP != "" {
		lines = append(lines, "IP: "+a.SourceIP)
	}
	if a.GroupKey != "" {
		lines = append(lines, "Grup: "+a.GroupKey)
	}
	lines = append(lines,
		fmt.Sprintf("Tekrar: %d", a.Occurrences),
		"İlk görülme: "+m.formatTime(a.FirstSeenAt),
		"Son görülme: "+m.formatTime(a.LastSeenAt),
	)
	return append(lines, latestFields(a)...)
}

// latestFields lists the fields the rule chose to include, from the most
// recent evidence line. Nothing else from the log line leaves the server.
func latestFields(a db.Alert) []string {
	var evidence []db.AlertEvidence
	if len(a.Evidence) == 0 || json.Unmarshal(a.Evidence, &evidence) != nil || len(evidence) == 0 {
		return nil
	}
	fields := evidence[len(evidence)-1].Fields
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+": "+fields[k])
	}
	return out
}

func (m Message) heading(a db.Alert) string {
	return "[" + severityLabel(a.Severity) + "] " + a.Title
}

// Subject is the email subject line.
func (m Message) Subject() string {
	if m.Kind == db.DeliveryDigest {
		return fmt.Sprintf("MUVON günlük alarm özeti: %s (%d alarm)", m.Period, len(m.Alerts))
	}
	if len(m.Alerts) == 0 {
		return "MUVON bildirimi"
	}
	a := m.Alerts[0]
	subject := m.heading(a)
	if a.Project != "" {
		subject += " (" + a.Project + ")"
	}
	if label := kindLabel(m.Kind); label != "" {
		subject = label + ": " + subject
	}
	return subject
}

// PlainText renders the message for email.
func (m Message) PlainText() string {
	var b strings.Builder
	if m.Kind == db.DeliveryDigest {
		fmt.Fprintf(&b, "%s tarihli özet, %s kanalı.\n\n", m.Period, m.Channel.Name)
		for i, a := range m.Alerts {
			if i == digestLimit {
				fmt.Fprintf(&b, "\nve %d alarm daha. Tamamı panelin Alarmlar sayfasında.\n", len(m.Alerts)-digestLimit)
				break
			}
			fmt.Fprintf(&b, "%s\n", m.heading(a))
			for _, l := range m.alertLines(a) {
				fmt.Fprintf(&b, "  %s\n", l)
			}
			if u := m.alertURL(a); u != "" {
				fmt.Fprintf(&b, "  Panelde aç: %s\n", u)
			}
			b.WriteString("\n")
		}
		return b.String()
	}
	for _, a := range m.Alerts {
		if label := kindLabel(m.Kind); label != "" {
			b.WriteString(label + "\n\n")
		}
		b.WriteString(m.heading(a) + "\n\n")
		for _, l := range m.alertLines(a) {
			b.WriteString(l + "\n")
		}
		if u := m.alertURL(a); u != "" {
			b.WriteString("\nPanelde aç: " + u + "\n")
		}
	}
	return b.String()
}

func slackIcon(severity string) string {
	switch severity {
	case alertrules.SeverityCritical:
		return ":rotating_light:"
	case alertrules.SeverityHigh:
		return ":red_circle:"
	case alertrules.SeverityWarning:
		return ":warning:"
	}
	return ":information_source:"
}

// SlackText renders the message as Slack mrkdwn.
func (m Message) SlackText() string {
	var b strings.Builder
	if m.Kind == db.DeliveryDigest {
		fmt.Fprintf(&b, ":clipboard: *MUVON günlük alarm özeti* %s, %d alarm\n", m.Period, len(m.Alerts))
		for i, a := range m.Alerts {
			if i == digestLimit {
				fmt.Fprintf(&b, "\nve %d alarm daha, tamamı panelde.", len(m.Alerts)-digestLimit)
				break
			}
			line := fmt.Sprintf("%s %s", slackIcon(a.Severity), slackEscape(m.heading(a)))
			if a.Project != "" {
				line += " (" + slackEscape(a.Project) + ")"
			}
			line += fmt.Sprintf(", tekrar %d", a.Occurrences)
			if u := m.alertURL(a); u != "" {
				line += " <" + u + "|aç>"
			}
			b.WriteString(line + "\n")
		}
		return b.String()
	}
	for _, a := range m.Alerts {
		if label := kindLabel(m.Kind); label != "" {
			b.WriteString("_" + label + "_\n")
		}
		fmt.Fprintf(&b, "%s *%s*\n", slackIcon(a.Severity), slackEscape(m.heading(a)))
		for _, l := range m.alertLines(a) {
			b.WriteString(slackEscape(l) + "\n")
		}
		if u := m.alertURL(a); u != "" {
			b.WriteString("<" + u + "|Panelde aç>\n")
		}
	}
	return b.String()
}

// slackEscape neutralises the characters Slack treats as markup, so a log
// field cannot inject a link or a mention.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
