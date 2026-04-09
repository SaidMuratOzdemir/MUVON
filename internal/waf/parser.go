package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

// ParseBody extracts inspectable fields from the request body based on content type.
// Returns a map of field_name → value. Binary content types are skipped.
func ParseBody(body []byte, contentType string, maxBytes int) map[string]string {
	if len(body) == 0 {
		return nil
	}

	if maxBytes > 0 && len(body) > maxBytes {
		body = body[:maxBytes]
	}

	if isBinaryContentType(contentType) {
		return nil
	}

	mediaType, params, _ := mime.ParseMediaType(contentType)

	switch {
	case mediaType == "application/x-www-form-urlencoded":
		return parseFormURLEncoded(body)
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return parseJSON(body)
	case mediaType == "multipart/form-data":
		return parseMultipart(body, params["boundary"])
	case mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml"):
		return map[string]string{"body": toUTF8(body)}
	default:
		s := toUTF8(body)
		if s == "" {
			return nil
		}
		return map[string]string{"body": s}
	}
}

// parseFormURLEncoded parses application/x-www-form-urlencoded data.
func parseFormURLEncoded(body []byte) map[string]string {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return map[string]string{"body": string(body)}
	}
	result := make(map[string]string, len(values))
	for key, vals := range values {
		result[key] = strings.Join(vals, " ")
	}
	return result
}

// parseJSON recursively extracts all string values from a JSON document.
// Keys are dotted paths (e.g. "user.name", "items.0.title").
func parseJSON(body []byte) map[string]string {
	result := make(map[string]string)
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		// If JSON parsing fails, treat as raw string
		return map[string]string{"body": toUTF8(body)}
	}
	flattenJSON("", data, result)
	if len(result) == 0 {
		return map[string]string{"body": toUTF8(body)}
	}
	return result
}

func flattenJSON(prefix string, v any, result map[string]string) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenJSON(key, child, result)
		}
	case []any:
		for i, child := range val {
			key := fmt.Sprintf("%s.%d", prefix, i)
			if prefix == "" {
				key = fmt.Sprintf("%d", i)
			}
			flattenJSON(key, child, result)
		}
	case string:
		if val != "" {
			result[prefix] = val
		}
	case float64:
		result[prefix] = fmt.Sprintf("%g", val)
	case bool:
		result[prefix] = fmt.Sprintf("%t", val)
	}
}

// parseMultipart extracts text fields and filenames from multipart form data.
func parseMultipart(body []byte, boundary string) map[string]string {
	if boundary == "" {
		return map[string]string{"body": toUTF8(body)}
	}

	result := make(map[string]string)
	reader := multipart.NewReader(bytes.NewReader(body), boundary)

	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}

		name := part.FormName()
		filename := part.FileName()

		// Always inspect filenames (common injection vector)
		if filename != "" {
			result["filename:"+name] = filename
		}

		// Read text parts (skip file content to avoid huge binary blobs)
		if filename == "" {
			data, err := io.ReadAll(io.LimitReader(part, 64*1024))
			if err == nil && len(data) > 0 {
				if name == "" {
					name = "part"
				}
				result[name] = string(data)
			}
		}
		part.Close()
	}

	if len(result) == 0 {
		return map[string]string{"body": toUTF8(body)}
	}
	return result
}

// isBinaryContentType returns true for content types that should not be inspected.
var binaryPrefixes = []string{
	"image/", "video/", "audio/",
	"application/octet-stream",
	"application/zip", "application/gzip",
	"application/pdf",
	"application/x-tar",
	"application/x-rar",
	"application/x-7z-compressed",
}

func isBinaryContentType(ct string) bool {
	lower := strings.ToLower(ct)
	for _, prefix := range binaryPrefixes {
		if strings.HasPrefix(lower, prefix) || strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

// toUTF8 converts bytes to a UTF-8 string, ignoring invalid sequences.
func toUTF8(b []byte) string {
	// strings.ToValidUTF8 replaces invalid bytes
	return strings.ToValidUTF8(string(b), "")
}
