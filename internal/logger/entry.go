package logger

import (
	"encoding/json"
	"time"
)

type Entry struct {
	RequestID       string
	Timestamp       time.Time
	Host            string
	ClientIP        string
	Method          string
	Path            string
	QueryString     string
	RequestHeaders  map[string]string
	ResponseStatus  int
	ResponseHeaders map[string]string
	ResponseTimeMs  int
	RequestSize     int
	ResponseSize    int
	UserAgent       string
	Error           string
	RequestBody     []byte
	ResponseBody    []byte
	IsRequestTruncated  bool
	IsResponseTruncated bool
	WafBlocked      bool
	WafBlockReason  string
	WafScore        int
	WafAction       string

	// Identity enrichment (JWT)
	UserIdentity    *UserIdentity

	// GeoIP enrichment
	Country         string
	City            string
}

// UserIdentity represents extracted JWT identity information.
type UserIdentity struct {
	Claims   map[string]string `json:"claims,omitempty"`
	Verified bool              `json:"verified"`
	Source   string            `json:"source"` // "jwt_verify" or "jwt_decode"
}

func (u *UserIdentity) JSON() json.RawMessage {
	if u == nil {
		return nil
	}
	b, _ := json.Marshal(u)
	return b
}

func (e *Entry) RequestHeadersJSON() json.RawMessage {
	if len(e.RequestHeaders) == 0 {
		return nil
	}
	b, _ := json.Marshal(e.RequestHeaders)
	return b
}

func (e *Entry) ResponseHeadersJSON() json.RawMessage {
	if len(e.ResponseHeaders) == 0 {
		return nil
	}
	b, _ := json.Marshal(e.ResponseHeaders)
	return b
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nilIfZero(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}
