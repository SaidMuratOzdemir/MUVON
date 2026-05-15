package grpcclient

import (
	"context"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"muvon/internal/deployer/grpcserver"
	pb "muvon/proto/deployerpb"
)

// RemoteDeployer talks to muvon-deployer's gRPC service over the local
// Unix socket. The admin gateway dials this on startup; nil means the
// deployer service is unreachable and admin handlers should 503 with a
// clear message (same fail-open shape as diaLOG).
type RemoteDeployer struct {
	conn   *grpc.ClientConn
	client pb.DeployerServiceClient
}

// Dial connects to the deployer Unix socket. Errors here are surface to
// the binary so it can decide whether to keep retrying or flag the
// admin UI as degraded.
func Dial(socketPath string) (*RemoteDeployer, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &RemoteDeployer{
		conn:   conn,
		client: pb.NewDeployerServiceClient(conn),
	}, nil
}

// DialTCP connects to an agent's deployer over the private network and
// attaches the shared bearer token on every call. Used by the central
// admin handler to stream live container logs from agent hosts.
func DialTCP(addr, token string) (*RemoteDeployer, error) {
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(&staticToken{token: token}),
	)
	if err != nil {
		return nil, err
	}
	return &RemoteDeployer{
		conn:   conn,
		client: pb.NewDeployerServiceClient(conn),
	}, nil
}

// staticToken attaches the shared deployer-token metadata on every
// outgoing RPC. RequireTransportSecurity returns false because the
// connection is expected to ride a private network (Hetzner cloud
// network or equivalent); upgrading to TLS is the operator's call.
type staticToken struct{ token string }

func (s *staticToken) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{grpcserver.AuthMetadataKey: s.token}, nil
}
func (s *staticToken) RequireTransportSecurity() bool { return false }

func (r *RemoteDeployer) Close() error { return r.conn.Close() }

// WithAuth attaches the deployer bearer token to an existing outgoing
// context. Used when the caller already has a context they want to
// thread through (e.g. SSE handler's r.Context()).
func WithAuth(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, grpcserver.AuthMetadataKey, token)
}

// ListContainers returns a snapshot of currently-known containers from
// the deployer's perspective (live Docker state).
func (r *RemoteDeployer) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.ListContainers(ctx, req)
}

// GetContainer returns Inspect results for a single container.
func (r *RemoteDeployer) GetContainer(ctx context.Context, containerID string) (*pb.ContainerDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.client.GetContainer(ctx, &pb.GetContainerRequest{ContainerId: containerID})
}

// StreamContainerLogs opens the live tail. The returned channel closes
// when the upstream stream ends (container exit, EOF, or ctx canceled).
// Errors during reads are logged at debug — the consumer signals end via
// channel close.
func (r *RemoteDeployer) StreamContainerLogs(ctx context.Context, req *pb.StreamContainerLogsRequest) (<-chan *pb.ContainerLogChunk, error) {
	stream, err := r.client.StreamContainerLogs(ctx, req)
	if err != nil {
		return nil, err
	}
	ch := make(chan *pb.ContainerLogChunk, 256)
	go func() {
		defer close(ch)
		for {
			chunk, err := stream.Recv()
			if err == io.EOF || ctx.Err() != nil {
				return
			}
			if err != nil {
				slog.Debug("deployer log stream error", "error", err)
				return
			}
			select {
			case ch <- chunk:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// Health is a cheap probe — admin uses it to gate the live-tail UI.
func (r *RemoteDeployer) Health(ctx context.Context) (*pb.HealthResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return r.client.Health(ctx, &pb.HealthRequest{})
}

// SelfImageDigest returns the image digest of the currently-running
// muvon container so the admin UI can compare it against the registry.
// Convenience wrapper around the gRPC; returns "" + error on failure
// so callers can degrade gracefully (handler shows "unknown" badge).
func (r *RemoteDeployer) SelfImageDigest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := r.client.SelfImageDigest(ctx, &pb.SelfImageDigestRequest{})
	if err != nil {
		return "", err
	}
	if d, ok := resp.GetDigests()["muvon"]; ok {
		return d, nil
	}
	return "", nil
}

// SystemUpgrade opens the streaming upgrade RPC. The admin SSE handler
// pumps every event straight to the operator's browser.
func (r *RemoteDeployer) SystemUpgrade(ctx context.Context, req *pb.SystemUpgradeRequest) (pb.DeployerService_SystemUpgradeClient, error) {
	return r.client.SystemUpgrade(ctx, req)
}
