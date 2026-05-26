package proxy

import (
	"context"

	"muvon/internal/logger"
)

// LogSink abstracts log delivery — either local pipeline or remote gRPC client.
type LogSink interface {
	Send(entry logger.Entry)
	// SendClientEvents ships a batch of edge-enriched browser telemetry
	// events. Fire-and-forget — the caller has already replied 204.
	SendClientEvents(batch logger.ClientEventBatch)
}

type InstanceTracker interface {
	AdjustDeployInstanceInFlight(ctx context.Context, instanceID string, delta int)
}
