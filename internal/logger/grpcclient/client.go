package grpcclient

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"muvon/internal/logger"
	pb "muvon/proto/logpb"
)

// RemoteLogSink sends log entries to diaLOG SIEM via gRPC.
// Also provides admin query methods for log search, stats, and streaming.
//
// The shipper keeps an in-memory retry queue so a transient central
// outage doesn't lose every log written during the gap. The queue is
// bounded — overflow drops the oldest entries (counted in `dropped`) so
// the proxy never blocks on log writes. For long outages prefer the
// agent dockerwatch spool path, which is disk-backed.
type RemoteLogSink struct {
	conn   *grpc.ClientConn
	client pb.LogServiceClient
	retry  chan logger.Entry
	stop   chan struct{}
	// Atomic counters for Stats().
	enqueued uint64
	dropped  uint64
}

// retryQueueSize bounds the in-memory backlog. 4096 ~ 30s of moderate
// traffic before backpressure kicks in. Each Entry is small (≤ a few
// hundred bytes once strings are short), so total memory is bounded.
const retryQueueSize = 4096

// retryAttempts caps how many times the worker re-sends one entry
// before giving up. 3 attempts at 3s timeout each ≈ 10s — generous
// enough to ride a deploy bounce, short enough that the queue drains.
const retryAttempts = 3
const retryBackoff = 2 * time.Second

// newSink constructs a sink with retry plumbing wired up. The retry
// worker starts immediately; it terminates when Stop() closes `stop`.
func newSink(conn *grpc.ClientConn) *RemoteLogSink {
	r := &RemoteLogSink{
		conn:   conn,
		client: pb.NewLogServiceClient(conn),
		retry:  make(chan logger.Entry, retryQueueSize),
		stop:   make(chan struct{}),
	}
	go r.retryLoop()
	return r
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
	return newSink(conn), nil
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
	return newSink(conn), nil
}

// apiKeyAuth implements credentials.PerRPCCredentials for agent log ingestion.
type apiKeyAuth struct{ key string }

func (a apiKeyAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"x-api-key": a.key}, nil
}

func (a apiKeyAuth) RequireTransportSecurity() bool { return false }

// Close closes the gRPC connection.
func (r *RemoteLogSink) Close() error {
	r.Stop()
	return r.conn.Close()
}

// Send tries one synchronous attempt first; if central is unreachable
// the entry lands on the bounded retry queue so a brief outage doesn't
// lose every log written during it. Queue full = drop oldest (counted)
// rather than block the proxy — request latency must not depend on the
// log channel being healthy.
func (r *RemoteLogSink) Send(entry logger.Entry) {
	atomic.AddUint64(&r.enqueued, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	_, err := r.client.SendEntry(ctx, entryToProto(entry))
	cancel()
	if err == nil {
		return
	}
	select {
	case r.retry <- entry:
	default:
		// Queue full — pop one to make room (oldest-out), count the loss.
		select {
		case <-r.retry:
			atomic.AddUint64(&r.dropped, 1)
		default:
		}
		select {
		case r.retry <- entry:
		default:
			atomic.AddUint64(&r.dropped, 1)
		}
	}
}

// retryLoop drains the retry queue with backoff. Stops when Stop()
// closes the signal channel.
func (r *RemoteLogSink) retryLoop() {
	for {
		select {
		case <-r.stop:
			return
		case entry := <-r.retry:
			r.shipWithRetry(entry)
		}
	}
}

func (r *RemoteLogSink) shipWithRetry(entry logger.Entry) {
	pbEntry := entryToProto(entry)
	for attempt := 1; attempt <= retryAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := r.client.SendEntry(ctx, pbEntry)
		cancel()
		if err == nil {
			return
		}
		if attempt == retryAttempts {
			atomic.AddUint64(&r.dropped, 1)
			slog.Debug("diaLOG retry exhausted, log dropped", "error", err)
			return
		}
		select {
		case <-r.stop:
			return
		case <-time.After(retryBackoff):
		}
	}
}

// Stats reports counters useful for health endpoints. queueLen tracks
// the live size of the retry buffer so an admin can spot a stuck sink.
func (r *RemoteLogSink) Stats() (enqueued, dropped, queueLen uint64) {
	return atomic.LoadUint64(&r.enqueued), atomic.LoadUint64(&r.dropped), uint64(len(r.retry))
}

// Stop closes the connection and the retry loop. Safe to call twice
// (the second close-of-stop is guarded behind a select default in the
// loop, so we use sync.Once-style discipline at the caller instead).
func (r *RemoteLogSink) Stop() {
	select {
	case <-r.stop:
		// already stopped
	default:
		close(r.stop)
	}
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

// GetLogRawJWT pulls the raw bearer token captured on a log row. Returns
// empty token when the host opted out or the token was not captured.
func (r *RemoteLogSink) GetLogRawJWT(ctx context.Context, requestID string) (*pb.GetLogRawJWTResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.GetLogRawJWT(ctx, &pb.GetLogRawJWTRequest{RequestId: requestID})
}

// EnrichmentStatus reports whether GeoIP / JWT identity enrichment are
// loaded on the diaLOG side. Used by the admin /api/system/health handler
// to render an actionable banner when an enrichment feature is configured
// but not actually working.
func (r *RemoteLogSink) EnrichmentStatus(ctx context.Context) (*pb.EnrichmentStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return r.client.GetEnrichmentStatus(ctx, &pb.EnrichmentStatusRequest{})
}

// ==================== Container Log Methods ====================

// SendContainerLogBatch ships a batch of container log records to
// dialog-siem. Synchronous — caller's context governs timeout. Caller
// (the deployer's logship or the agent's dockerwatch) handles retry +
// spool when this errors.
func (r *RemoteLogSink) SendContainerLogBatch(ctx context.Context, batch *pb.ContainerLogBatch) error {
	_, err := r.client.SendContainerLogBatch(ctx, batch)
	return err
}

// SearchContainerLogs runs a paginated container-log search. 30s timeout
// matches the http log search ceiling — older chunks fall back to seq
// scan once compressed.
func (r *RemoteLogSink) SearchContainerLogs(ctx context.Context, req *pb.SearchContainerLogsRequest) (*pb.SearchContainerLogsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return r.client.SearchContainerLogs(ctx, req)
}

// ListContainersFromDialog lists dimension-table rows. Distinct method
// name so callers can tell it apart from the deployerclient method that
// returns live Docker state.
func (r *RemoteLogSink) ListContainersFromDialog(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return r.client.ListContainers(ctx, req)
}

// GetContainerLogContext fetches ±N lines around an anchor row.
func (r *RemoteLogSink) GetContainerLogContext(ctx context.Context, anchorID string, n int) (*pb.SearchContainerLogsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return r.client.GetContainerLogContext(ctx, &pb.GetContainerLogContextRequest{Id: anchorID, N: int32(n)})
}

// GetIngestStatus reports container-log shipper health (spool size, lag,
// last-batch time). The admin UI banner reads this.
func (r *RemoteLogSink) GetIngestStatus(ctx context.Context) (*pb.IngestStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return r.client.GetIngestStatus(ctx, &pb.IngestStatusRequest{})
}

// GetContainerLastLogAt fetches the latest ingested timestamp for the
// container, used by logship to compute `since` on reconnect. Returns
// zero time when the SIEM has no rows yet (cold container).
func (r *RemoteLogSink) GetContainerLastLogAt(ctx context.Context, containerID string) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := r.client.GetContainerLastLogAt(ctx, &pb.GetContainerLastLogAtRequest{ContainerId: containerID})
	if err != nil || resp == nil || resp.LastLogAt == "" {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, resp.LastLogAt)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
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
