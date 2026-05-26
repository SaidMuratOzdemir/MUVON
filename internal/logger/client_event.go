package logger

import (
	"encoding/json"
	"time"
)

// ClientEvent is a single browser-side telemetry record, flattened so the
// worker can COPY it straight into client_events. The session/view envelope
// fields are copied onto every row in a batch — like ContainerEntry, a small
// duplicated struct keeps this thin pipe independent of the http log path.
//
// ClientIP / Host / UserAgent / ReceivedAt are stamped by the edge (the proxy
// handler), never trusted from the browser. Country/City are filled by the
// SIEM pipeline's GeoIP enricher — agents don't carry the GeoLite DB, so geo
// resolution happens centrally, exactly like the http log path.
type ClientEvent struct {
	// Envelope dimension — one logical batch, propagated to every row.
	App       string
	Release   string
	SDK       string
	SessionID string
	ViewID    string
	Route     string
	URLPath   string

	// Edge-stamped (proxy handler).
	Host       string // vhost the beacon hit
	HostID     string // "central" or agent UUID
	ClientIP   string
	UserAgent  string
	ReceivedAt time.Time

	// Per-event.
	EventName string
	ClientTS  time.Time // browser clock — untrusted, debug only
	TraceID   string
	SpanID    string
	Attrs     map[string]string

	// SIEM-enriched.
	Country string
	City    string
}

// AttrsJSON marshals attrs into JSONB for COPY; nil when empty so the column
// stays NULL and the partial GIN index stays sparse.
func (e *ClientEvent) AttrsJSON() json.RawMessage {
	if len(e.Attrs) == 0 {
		return nil
	}
	b, _ := json.Marshal(e.Attrs)
	return b
}

// ClientEventBatch is the proxy → log-sink boundary shape: one envelope plus
// the events it groups. The sink (grpcclient) maps it 1:1 to the protobuf
// ClientEventBatch; the SIEM flattens it back into per-row ClientEvent values.
type ClientEventBatch struct {
	App       string
	Release   string
	SDK       string
	SessionID string
	ViewID    string
	Route     string
	URLPath   string

	Host       string
	HostID     string
	ClientIP   string
	UserAgent  string
	ReceivedAt time.Time

	Events []ClientEventItem
}

// ClientEventItem is one event inside a ClientEventBatch.
type ClientEventItem struct {
	EventName string
	ClientTS  time.Time
	TraceID   string
	SpanID    string
	Attrs     map[string]string
}
