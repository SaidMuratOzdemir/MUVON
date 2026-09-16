package alerting

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"muvon/internal/alertrules"
)

// SMTPConfig is the sending account every email channel uses. A channel only
// chooses recipients.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// EmailSender sends through the configured SMTP account.
type EmailSender struct {
	Config func() SMTPConfig
}

func (e *EmailSender) Send(ctx context.Context, ch alertrules.Channel, m Message) error {
	cfg := e.Config()
	if cfg.Host == "" || cfg.From == "" {
		return errors.New("email: the SMTP sending account is not configured")
	}
	if len(ch.EmailTo) == 0 {
		return errors.New("email: channel has no recipients")
	}
	msg, err := buildEmail(cfg.From, ch.EmailTo, m.Subject(), m.PlainText(), time.Now())
	if err != nil {
		return err
	}

	port := cfg.Port
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, port)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return sendSMTP(ctx, addr, cfg.Host, port == 465, auth, cfg.From, ch.EmailTo, msg)
}

// buildEmail assembles an RFC 5322 message. The subject is built from alert
// titles, which can come from log content, so line breaks are removed before
// it becomes a header and non-ASCII text is encoded rather than sent raw.
func buildEmail(from string, to []string, subject, body string, now time.Time) ([]byte, error) {
	if _, err := mail.ParseAddress(from); err != nil {
		return nil, fmt.Errorf("email: invalid sender address: %w", err)
	}
	for _, r := range to {
		if _, err := mail.ParseAddress(r); err != nil {
			return nil, fmt.Errorf("email: invalid recipient %q: %w", r, err)
		}
	}
	subject = strings.Join(strings.Fields(subject), " ")

	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("email: message id: %w", err)
	}
	domain := "muvon.local"
	if at := strings.LastIndexByte(from, '@'); at >= 0 {
		domain = strings.Trim(from[at+1:], "> ")
	}

	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + now.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + hex.EncodeToString(id) + "@" + domain + ">\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String()), nil
}

// smtpTimeout bounds the whole SMTP exchange (connect + protocol). Without it,
// net.Dial to a blackholed host blocks for the OS TCP connect timeout (minutes).
const smtpTimeout = 15 * time.Second

func sendSMTP(ctx context.Context, addr, host string, implicitTLS bool, auth smtp.Auth, from string, to []string, msg []byte) error {
	dialer := &net.Dialer{Timeout: smtpTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("email dial: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))
	if implicitTLS {
		tconn := tls.Client(conn, &tls.Config{ServerName: host})
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("email tls handshake: %w", err)
		}
		conn = tconn
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("email smtp client: %w", err)
	}
	defer client.Close()

	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return fmt.Errorf("email starttls: %w", err)
			}
		}
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("email mail: %w", err)
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("email rcpt: %w", err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("email write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email close data: %w", err)
	}
	return client.Quit()
}
