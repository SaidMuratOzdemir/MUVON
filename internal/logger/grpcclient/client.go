package grpcclient

import (
	"context"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"muvon/internal/logger"
	pb "muvon/proto/logpb"
)

// RemoteLogSink sends log entries to diaLOG SIEM via gRPC.
// Also provides admin query methods for log search, stats, and streaming.
type RemoteLogSink struct {
	conn   *grpc.ClientConn
	client pb.LogServiceClient
}

// Dial connects to diaLOG's Unix socket (central server mode).
func Dial(socketPath string) (*RemoteLogSink, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &RemoteLogSink{
		conn:   conn,
		client: pb.NewLogServiceClient(conn),
	}, nil
}

// DialTCP connects to a diaLOG instance over TCP with API key auth.
// Used by agent binaries to send logs to the central server.
func DialTCP(addr, apiKey string) (*RemoteLogSink, error) {
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(apiKeyAuth{key: apiKey}),
	)
	if err != nil {
		return nil, err
	}
	return &RemoteLogSink{
		conn:   conn,
		client: pb.NewLogServiceClient(conn),
	}, nil
}

// apiKeyAuth implements credentials.PerRPCCredentials for agent log ingestion.
type apiKeyAuth struct{ key string }

func (a apiKeyAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"x-api-key": a.key}, nil
}

func (a apiKeyAuth) RequireTransportSecurity() bool { return false }

// Close closes the gRPC connection.
func (r *RemoteLogSink) Close() error {
	return r.conn.Close()
}

// Send sends a single log entry to diaLOG asynchronously (fire-and-forget).
func (r *RemoteLogSink) Send(entry logger.Entry) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := r.client.SendEntry(ctx, entryToProto(entry))
		if err != nil {
			slog.Debug("diaLOG send failed", "error", err)
		}
	}()
}

// Stats returns zero values since stats are on the remote side.
func (r *RemoteLogSink) Stats() (enqueued, dropped, queueLen uint64) {
	return 0, 0, 0
}

// Stop closes the connection.
func (r *RemoteLogSink) Stop() {
	r.conn.Close()
}

// ==================== Admin Query Methods ====================

// SearchLogs queries logs from diaLOG SIEM.
// 30s caps the wait for trigram scans that reach past TimescaleDB's
// compression horizon — older chunks fall back to columnar seq scan
// and a manual `from` covering archived data can run ~10s. Anything
// longer is almost certainly an admin asking for a window the engine
// can't service without narrowing the search window.
func (r *RemoteLogSink) SearchLogs(ctx context.Context, req *pb.SearchLogsRequest) (*pb.SearchLogsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return r.client.SearchLogs(ctx, req)
}

// GetLog retrieves a single log detail from diaLOG SIEM.
func (r *RemoteLogSink) GetLog(ctx context.Context, requestID string) (*pb.LogDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.GetLog(ctx, &pb.GetLogRequest{RequestId: requestID})
}

// GetLogStats retrieves log statistics from diaLOG SIEM.
func (r *RemoteLogSink) GetLogStats(ctx context.Context, host, from, to string) (*pb.LogStatsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return r.client.GetLogStats(ctx, &pb.GetLogStatsRequest{
		Host: host,
		From: from,
		To:   to,
	})
}

// StreamLogs opens a gRPC stream and fans entries into the returned channel.
// The caller should read from the channel until it's closed.
// Cancel the context to stop streaming.
func (r *RemoteLogSink) StreamLogs(ctx context.Context, host string) (<-chan *pb.LogEntry, error) {
	stream, err := r.client.StreamLogs(ctx, &pb.StreamLogsRequest{Host: host})
	if err != nil {
		return nil, err
	}
	ch := make(chan *pb.LogEntry, 64)
	go func() {
		defer close(ch)
		for {
			entry, err := stream.Recv()
			if err == io.EOF || ctx.Err() != nil {
				return
			}
			if err != nil {
				slog.Debug("diaLOG stream error", "error", err)
				return
			}
			select {
			case ch <- entry:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// UpsertNote adds/updates a note on a log entry.
func (r *RemoteLogSink) UpsertNote(ctx context.Context, requestID, note string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.client.UpsertNote(ctx, &pb.UpsertNoteRequest{
		RequestId: requestID,
		Note:      note,
	})
	return err
}

// ToggleStar toggles the star status of a log entry.
func (r *RemoteLogSink) ToggleStar(ctx context.Context, requestID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.client.ToggleStar(ctx, &pb.ToggleStarRequest{
		RequestId: requestID,
	})
	return err
}

// ==================== Converters ====================

func entryToProto(e logger.Entry) *pb.LogEntry {
	p := &pb.LogEntry{
		RequestId:           e.RequestID,
		Timestamp:           e.Timestamp.Format(time.RFC3339Nano),
		Host:                e.Host,
		ClientIp:            e.ClientIP,
		Method:              e.Method,
		Path:                e.Path,
		QueryString:         e.QueryString,
		ResponseStatus:      int32(e.ResponseStatus),
		ResponseTimeMs:      int32(e.ResponseTimeMs),
		RequestSize:         int32(e.RequestSize),
		ResponseSize:        int32(e.ResponseSize),
		UserAgent:           e.UserAgent,
		Error:               e.Error,
		RequestBody:         e.RequestBody,
		ResponseBody:        e.ResponseBody,
		IsRequestTruncated:  e.IsRequestTruncated,
		IsResponseTruncated: e.IsResponseTruncated,
		WafBlocked:          e.WafBlocked,
		WafBlockReason:      e.WafBlockReason,
		WafScore:            int32(e.WafScore),
		WafAction:           e.WafAction,
		RequestHeaders:      e.RequestHeaders,
		ResponseHeaders:     e.ResponseHeaders,
		Country:             e.Country,
		City:                e.City,
	}
	if e.UserIdentity != nil {
		p.UserIdentity = &pb.UserIdentity{
			Claims:   e.UserIdentity.Claims,
			Verified: e.UserIdentity.Verified,
			Source:   e.UserIdentity.Source,
		}
	}
	return p
}
