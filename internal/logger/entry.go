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

	// RawJWT is the unmodified bearer token captured from the request.
	// Set only when the host explicitly opts in (hosts.store_raw_jwt) —
	// otherwise the pipeline drops it after extracting claims so it never
	// reaches the DB. UI access goes through a reveal endpoint that
	// audit-logs every read.
	RawJWT          string

	// GeoIP enrichment
	Country         string
	City            string
}

// UserIdentity represents extracted JWT identity information.
//
// ExpExpired is set to true when the signature verified but the `exp` claim
// is in the past. In that case Verified is forced back to false — a
// cryptographically correct but stale token is still not trustworthy for
// authorization, and callers that key off Verified should treat it as a
// decode-only result. The boolean surfaces separately so the UI can show
// "the signature was valid, the token just expired" which is a different
// class of event from a forged token.
type UserIdentity struct {
	Claims     map[string]string `json:"claims,omitempty"`
	Verified   bool              `json:"verified"`
	Source     string            `json:"source"` // "jwt_verify", "jwt_decode", "jwt_expired"
	ExpExpired bool              `json:"exp_expired,omitempty"`
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
