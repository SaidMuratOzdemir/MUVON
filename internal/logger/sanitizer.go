package logger

import "strings"

var sensitiveHeaders = map[string]bool{
	"authorization":    true,
	"cookie":           true,
	"set-cookie":       true,
	"x-api-key":        true,
	"x-auth-token":     true,
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
