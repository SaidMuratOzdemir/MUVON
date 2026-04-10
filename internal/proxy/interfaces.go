package proxy

import (
	"context"

	"muvon/internal/logger"
	"muvon/internal/waf"
)

// Inspector abstracts WAF inspection — either in-process engine or remote gRPC client.
type Inspector interface {
	Inspect(ctx context.Context, req waf.InspectRequest) waf.InspectResult
}

// LogSink abstracts log delivery — either local pipeline or remote gRPC client.
type LogSink interface {
	Send(entry logger.Entry)
}

type InstanceTracker interface {
	AdjustDeployInstanceInFlight(ctx context.Context, instanceID string, delta int)
}
