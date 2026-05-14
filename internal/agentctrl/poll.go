package agentctrl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PollClient is the agent-side long-poll driver. It loops forever:
// open a long-poll, dispatch the returned command (if any), report
// the result, repeat. Reconnect logic uses exponential backoff with
// jitter so a central outage doesn't pin the loop in tight-spin.
//
// The driver assumes a single agent identity (one X-Api-Key). Multi-
// tenant agents would instantiate one PollClient per identity.
type PollClient struct {
	centralURL string
	apiKey     string
	signingKey []byte
	registry   *Registry
	client     *http.Client
	// pollWait is the upper bound for each long-poll request. Server
	// caps at 50s; we ask for 25s by default so an idle agent costs
	// at most one HTTP round trip every ~25 seconds.
	pollWait time.Duration
}

// NewPollClient assembles a poll client. The HTTP client shares
// keep-alive connections so an empty-poll cycle costs essentially
// zero TLS handshakes.
func NewPollClient(centralURL, apiKey string, signingKey []byte, reg *Registry) *PollClient {
	transport := &http.Transport{
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 35 * time.Second, // > pollWait
	}
	return &PollClient{
		centralURL: strings.TrimRight(centralURL, "/"),
		apiKey:     apiKey,
		signingKey: signingKey,
		registry:   reg,
		client:     &http.Client{Transport: transport, Timeout: 35 * time.Second},
		pollWait:   25 * time.Second,
	}
}

// Run blocks until ctx is cancelled, polling for commands and
// dispatching them. Errors are logged + backed off; the loop never
// exits on a transient failure.
func (c *PollClient) Run(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		cmd, status, err := c.pollOnce(ctx)
		if err != nil {
			slog.Debug("command poll failed", "error", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = time.Second
		if status == http.StatusNoContent {
			// No command this cycle — repoll immediately. The server
			// already held the connection for the full wait window.
			continue
		}
		// Got a command. Verify signature + expiry, dispatch, report.
		if err := Verify(cmd, c.signingKey); err != nil {
			slog.Warn("agent command signature mismatch", "id", cmd.ID, "kind", cmd.Kind, "error", err)
			c.reportResult(ctx, Result{
				CommandID: cmd.ID, State: StateFailed,
				Error: "signature verification failed",
			})
			continue
		}
		if time.Now().After(cmd.ExpiresAt) {
			c.reportResult(ctx, Result{
				CommandID: cmd.ID, State: StateFailed,
				Error: "command already expired on receipt",
			})
			continue
		}
		result := c.registry.Dispatch(ctx, cmd)
		c.reportResult(ctx, result)
	}
}

// pollOnce executes a single long-poll. Returns the command (when
// status=200), HTTP status, and any transport error.
func (c *PollClient) pollOnce(ctx context.Context) (Command, int, error) {
	u := fmt.Sprintf("%s/api/v1/agent/commands?wait=%d", c.centralURL, int(c.pollWait.Seconds()))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Command{}, 0, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return Command{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return Command{}, resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return Command{}, resp.StatusCode, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Server returns the DB row shape (id, kind, payload, expires_at,
	// nonce, signature). Map it to Command.
	var dbRow struct {
		ID        string          `json:"id"`
		Kind      string          `json:"kind"`
		Payload   json.RawMessage `json:"payload"`
		ExpiresAt time.Time       `json:"expires_at"`
		Nonce     []byte          `json:"nonce"`
		Signature []byte          `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dbRow); err != nil {
		return Command{}, resp.StatusCode, fmt.Errorf("decode: %w", err)
	}
	return Command{
		ID:        dbRow.ID,
		Kind:      CommandKind(dbRow.Kind),
		Payload:   dbRow.Payload,
		ExpiresAt: dbRow.ExpiresAt,
		Nonce:     dbRow.Nonce,
		Signature: dbRow.Signature,
	}, resp.StatusCode, nil
}

// reportResult POSTs the terminal Result back. Failures here are
// logged but not retried — the server's sweeper will mark the row
// expired and the operator UI will surface it.
func (c *PollClient) reportResult(ctx context.Context, r Result) {
	body, err := json.Marshal(map[string]any{
		"state":  r.State,
		"output": r.Output,
		"error":  r.Error,
		"data":   r.Data,
	})
	if err != nil {
		slog.Warn("encode result failed", "id", r.CommandID, "error", err)
		return
	}
	u := fmt.Sprintf("%s/api/v1/agent/commands/%s/result", c.centralURL, url.PathEscape(r.CommandID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		slog.Warn("build result request failed", "id", r.CommandID, "error", err)
		return
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		slog.Warn("report result failed", "id", r.CommandID, "error", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusConflict {
		slog.Warn("report result rejected", "id", r.CommandID, "status", resp.StatusCode)
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}
