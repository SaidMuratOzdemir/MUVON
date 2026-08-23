package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

func NewTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true, // our own middleware handles gzip
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// ForceAttemptHTTP2 is deliberately left false: HTTP/2 has no
		// WebSocket Upgrade header (RFC 7540 8.1.2.2). A backend that wants
		// gRPC or HTTP/2 configures its backend_url for h2c instead.
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}
