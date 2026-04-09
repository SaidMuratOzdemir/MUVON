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
		DisableCompression:    true, // gzip bizde hallediliyor
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// ForceAttemptHTTP2 kasıtlı olarak false bırakıldı.
		// HTTP/2 WebSocket Upgrade başlığını desteklemez (RFC 7540 §8.1.2.2).
		// Backend gRPC/HTTP2 istiyorsa backend_url'yi h2c ile yapılandırmalı.
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}
