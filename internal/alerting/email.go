package alerting

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"muvon/internal/correlation"
)

// EmailNotifier sends alerts via SMTP.
type EmailNotifier struct {
	configFn ConfigFunc
}

func NewEmailNotifier(configFn ConfigFunc) *EmailNotifier {
	return &EmailNotifier{configFn: configFn}
}

func (e *EmailNotifier) Name() string { return "email" }

func (e *EmailNotifier) Send(ctx context.Context, alert correlation.Alert) error {
	cfg := e.configFn()
	if cfg.SMTPHost == "" || cfg.SMTPFrom == "" || cfg.SMTPTo == "" {
		return nil
	}

	subject := fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.Title)

	body := fmt.Sprintf("Rule: %s\nSeverity: %s\n", alert.Rule, alert.Severity)
	if alert.SourceIP != "" {
		body += fmt.Sprintf("Source IP: %s\n", alert.SourceIP)
	}
	if alert.Host != "" {
		body += fmt.Sprintf("Host: %s\n", alert.Host)
	}
	for k, v := range alert.Detail {
		body += fmt.Sprintf("%s: %v\n", k, v)
	}

	recipients := strings.Split(cfg.SMTPTo, ",")
	for i := range recipients {
		recipients[i] = strings.TrimSpace(recipients[i])
	}

	msg := "From: " + cfg.SMTPFrom + "\r\n" +
		"To: " + cfg.SMTPTo + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)

	var auth smtp.Auth
	if cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
	}

	// Direct TLS on 465, STARTTLS (when advertised) otherwise. Every step is
	// bounded by a dial timeout + connection deadline so an unreachable or slow
	// SMTP host can never stall the caller (the alerting dispatch goroutine).
	return sendSMTP(ctx, addr, cfg.SMTPHost, cfg.SMTPPort == 465, auth, cfg.SMTPFrom, recipients, []byte(msg))
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
