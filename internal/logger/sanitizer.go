package logger

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// sanitizeText strips bytes PostgreSQL's UTF8 text/jsonb types reject: NUL
// (0x00, rejected by both text and jsonb string values) and invalid UTF-8
// sequences. Without this a single crafted field (e.g. a "%00" in a URL path,
// which net/http decodes to a literal NUL in r.URL.Path) makes the whole COPY
// batch fail, silently dropping every unrelated log entry batched with it.
func sanitizeText(s string) string {
	if s == "" {
		return s
	}
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

// sanitizeBytes is sanitizeText for a captured body destined for a TEXT column.
func sanitizeBytes(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	if bytes.IndexByte(b, 0) < 0 && utf8.Valid(b) {
		return b
	}
	s := strings.ReplaceAll(string(b), "\x00", "")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return []byte(s)
}

func sanitizeStringMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[sanitizeText(k)] = sanitizeText(v)
	}
	return out
}

// sanitizeEntryText scrubs every text/jsonb-bound field of an http_logs entry
// so one poisoned request can't drop an entire COPY batch.
func sanitizeEntryText(e *Entry) {
	e.Host = sanitizeText(e.Host)
	e.ClientIP = sanitizeText(e.ClientIP)
	e.Method = sanitizeText(e.Method)
	e.Path = sanitizeText(e.Path)
	e.QueryString = sanitizeText(e.QueryString)
	e.UserAgent = sanitizeText(e.UserAgent)
	e.Error = sanitizeText(e.Error)
	e.Country = sanitizeText(e.Country)
	e.City = sanitizeText(e.City)
	e.RawJWT = sanitizeText(e.RawJWT)
	e.TraceID = sanitizeText(e.TraceID)
	e.SpanID = sanitizeText(e.SpanID)
	e.RequestHeaders = sanitizeStringMap(e.RequestHeaders)
	e.ResponseHeaders = sanitizeStringMap(e.ResponseHeaders)
	e.RequestBody = sanitizeBytes(e.RequestBody)
	e.ResponseBody = sanitizeBytes(e.ResponseBody)
}

// sanitizeContainerEntry scrubs a container log row's text/jsonb fields — a
// container writing a NUL byte to stdout must not drop the whole COPY batch.
func sanitizeContainerEntry(e *ContainerEntry) {
	e.HostID = sanitizeText(e.HostID)
	e.ContainerID = sanitizeText(e.ContainerID)
	e.ContainerName = sanitizeText(e.ContainerName)
	e.Image = sanitizeText(e.Image)
	e.Project = sanitizeText(e.Project)
	e.Component = sanitizeText(e.Component)
	e.ReleaseID = sanitizeText(e.ReleaseID)
	e.DeploymentID = sanitizeText(e.DeploymentID)
	e.Stream = sanitizeText(e.Stream)
	e.Line = sanitizeText(e.Line)
	e.Attrs = sanitizeStringMap(e.Attrs)
}

// sanitizeClientEvent scrubs a RUM event's text/jsonb fields — a crafted beacon
// field must not drop the whole COPY batch.
func sanitizeClientEvent(e *ClientEvent) {
	e.App = sanitizeText(e.App)
	e.Release = sanitizeText(e.Release)
	e.SDK = sanitizeText(e.SDK)
	e.SessionID = sanitizeText(e.SessionID)
	e.ViewID = sanitizeText(e.ViewID)
	e.Route = sanitizeText(e.Route)
	e.URLPath = sanitizeText(e.URLPath)
	e.Host = sanitizeText(e.Host)
	e.HostID = sanitizeText(e.HostID)
	e.ClientIP = sanitizeText(e.ClientIP)
	e.UserAgent = sanitizeText(e.UserAgent)
	e.EventName = sanitizeText(e.EventName)
	e.TraceID = sanitizeText(e.TraceID)
	e.SpanID = sanitizeText(e.SpanID)
	e.Country = sanitizeText(e.Country)
	e.City = sanitizeText(e.City)
	e.Attrs = sanitizeStringMap(e.Attrs)
}

var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"proxy-authorization": true,
}

func SanitizeHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if sensitiveHeaders[strings.ToLower(k)] {
			out[k] = maskValue(v)
		} else {
			out[k] = v
		}
	}
	return out
}

func maskValue(v string) string {
	if len(v) <= 8 {
		return "***"
	}
	return v[:4] + "***" + v[len(v)-4:]
}
