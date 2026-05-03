package logger

import (
	"encoding/json"
	"time"
)

// ContainerEntry is a single stdout/stderr record from a Docker container,
// already enriched with the dimension fields the shipper passed alongside
// the line. Worker writes it to container_logs.
//
// Independent of Entry: the http log path needs GeoIP + JWT enrichment
// hooks and per-row body shipping; container logs are a thinner pipe and
// duplicating the small struct keeps each path simple.
type ContainerEntry struct {
	// Dimension — propagated to every row in the batch.
	HostID        string
	ContainerID   string
	ContainerName string
	Image         string
	Project       string
	Component     string
	ReleaseID     string
	DeploymentID  string

	// Line — assigned by the shipper from the daemon stream.
	Timestamp time.Time
	Stream    string // "stdout" | "stderr"
	Line      string
	Truncated bool
	Seq       int64

	// Attrs — populated by the SIEM worker when Line parses as a JSON
	// object. Lets the UI filter on attrs.level=ERROR without changing
	// the wire shape.
	Attrs map[string]string

	// ReceivedAt is stamped by the SIEM on accept. Helps detect clock
	// skew when ts and received_at diverge by more than a window.
	ReceivedAt time.Time
}

// AttrsJSON marshals the parsed attrs map into JSONB for COPY. Returns nil
// when attrs is empty so the column stays NULL (and the partial GIN index
// stays sparse).
func (e *ContainerEntry) AttrsJSON() json.RawMessage {
	if len(e.Attrs) == 0 {
		return nil
	}
	b, _ := json.Marshal(e.Attrs)
	return b
}
