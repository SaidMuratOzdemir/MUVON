package proxy

import (
	"context"

	"muvon/internal/logger"
)

// LogSink abstracts log delivery — either local pipeline or remote gRPC client.
type LogSink interface {
	Send(entry logger.Entry)
}

type InstanceTracker interface {
	AdjustDeployInstanceInFlight(ctx context.Context, instanceID string, delta int)
}
