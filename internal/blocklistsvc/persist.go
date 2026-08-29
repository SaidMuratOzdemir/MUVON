package blocklistsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"muvon/internal/blocklist"
	"muvon/internal/db"
)

// DBPersister writes a block straight to PostgreSQL. Used by central, which
// owns the database.
type DBPersister struct {
	DB *db.DB
	// Host names the instance that decided the block, so the operator can tell
	// which edge saw the scanner before lifting it.
	Host string
}

func (p DBPersister) SaveBlock(ctx context.Context, b blocklist.Block) error {
	if p.DB == nil {
		return nil
	}
	return p.DB.UpsertIPBlock(ctx, b, p.Host, "auto")
}

// AgentPersister reports a locally decided block to central over the existing
// agent API. The agent has no database of its own, and central is what shares
// the decision with the rest of the fleet through the config snapshot.
//
// The local block is already in force by the time this runs, so a failure here
// costs reach, not protection.
type AgentPersister struct {
	CentralURL string
	APIKey     string
	AgentID    string
	Client     *http.Client
}

func (p AgentPersister) SaveBlock(ctx context.Context, b blocklist.Block) error {
	if p.CentralURL == "" || p.APIKey == "" {
		return nil
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	body, err := json.Marshal(map[string]any{
		"key":        b.Key,
		"rule":       b.Rule,
		"pattern":    b.Pattern,
		"score":      b.Score,
		"ban_count":  b.BanCount,
		"created_at": b.CreatedAt,
		"expires_at": b.ExpiresAt,
		"agent_id":   p.AgentID,
	})
	if err != nil {
		return err
	}

	url := strings.TrimSuffix(p.CentralURL, "/") + "/api/v1/agent/blocklist"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", p.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// A 404 means central predates this endpoint. That is an upgrade-order
	// situation, not a fault: say so once rather than treating it as an error
	// the operator has to chase.
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("central does not accept block reports yet (upgrade central first)")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("central returned %s", resp.Status)
	}
	return nil
}
