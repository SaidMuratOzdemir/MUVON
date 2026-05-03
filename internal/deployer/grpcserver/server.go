package grpcserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"muvon/internal/deployer"
	pb "muvon/proto/deployerpb"
)

// Service is what muvon-deployer's main provides to expose Docker
// introspection through a gRPC surface. The DockerClient lives in the
// deployer service; we accept it as a field rather than re-dialling.
type Server struct {
	pb.UnimplementedDeployerServiceServer

	docker *deployer.DockerClient

	// Limits — populated from env in cmd/muvon-deployer.
	maxViewersPerContainer int32
	maxViewersGlobal       int32
	maxLine                int

	// Live-tail state. perContainer keeps a count per container_id;
	// global is the sum, used for the global cap. Both protected by mu.
	mu           sync.Mutex
	perContainer map[string]int32
	global       int32

	// Health counters reported via the Health RPC.
	lastTickUnix atomic.Int64

	// Shipper-supplied state. Set via SetShipperReporter from logship.
	shipperReportFn func() (active int32)
}

// New wires a Server with the given Docker client and limits. Pass zero
// for a limit field to use defaults: per-container=4, global=64,
// max-line=16384.
func New(docker *deployer.DockerClient, maxPerContainer, maxGlobal int, maxLine int) *Server {
	if maxPerContainer <= 0 {
		maxPerContainer = 4
	}
	if maxGlobal <= 0 {
		maxGlobal = 64
	}
	if maxLine <= 0 {
		maxLine = 16 * 1024
	}
	return &Server{
		docker:                 docker,
		maxViewersPerContainer: int32(maxPerContainer),
		maxViewersGlobal:       int32(maxGlobal),
		maxLine:                maxLine,
		perContainer:           make(map[string]int32),
	}
}

// SetShipperReporter lets logship report the number of containers it is
// actively tailing for persistent ingest. Surfaced through Health.
func (s *Server) SetShipperReporter(fn func() int32) {
	s.shipperReportFn = fn
}

// MarkTick is called from the deployer's main loop on each tick so the
// Health RPC can report tick freshness — a "deployer is up but stuck"
// scenario is otherwise invisible.
func (s *Server) MarkTick() {
	s.lastTickUnix.Store(time.Now().Unix())
}

// --- ListContainers ---

func (s *Server) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	containers, err := s.docker.ContainerListAll(ctx, req.ManagedOnly)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "docker list: %v", err)
	}
	resp := &pb.ListContainersResponse{Containers: make([]*pb.ContainerDetail, 0, len(containers))}
	for _, c := range containers {
		// Apply project/component/state filters in-process — Docker's
		// filter param doesn't support our label values syntax for
		// arbitrary key/value pairs.
		if req.Project != "" && c.Labels["muvon.project"] != req.Project {
			continue
		}
		if req.Component != "" && c.Labels["muvon.component"] != req.Component {
			continue
		}
		if req.State == "running" && c.State != "running" {
			continue
		}
		if req.State == "exited" && c.State != "exited" && c.State != "dead" {
			continue
		}
		detail := summaryToProto(c)
		resp.Containers = append(resp.Containers, detail)
	}
	return resp, nil
}

// --- GetContainer ---

func (s *Server) GetContainer(ctx context.Context, req *pb.GetContainerRequest) (*pb.ContainerDetail, error) {
	if req.ContainerId == "" {
		return nil, status.Error(codes.InvalidArgument, "container_id is required")
	}
	insp, err := s.docker.ContainerInspect(ctx, req.ContainerId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "inspect %s: %v", req.ContainerId, err)
	}
	return inspectToProto(insp), nil
}

// --- StreamContainerLogs ---

func (s *Server) StreamContainerLogs(req *pb.StreamContainerLogsRequest, stream pb.DeployerService_StreamContainerLogsServer) error {
	if req.ContainerId == "" {
		return status.Error(codes.InvalidArgument, "container_id is required")
	}

	// Reserve a viewer slot under both caps. On rejection the user
	// sees a structured RESOURCE_EXHAUSTED — UI bubbles a toast.
	if !s.acquire(req.ContainerId) {
		return status.Error(codes.ResourceExhausted, "too many concurrent log viewers for this container")
	}
	defer s.release(req.ContainerId)

	// Resolve options. Tail<0 means "all"; tail==0 means "only new"; the
	// Docker API uses the string form, with "all" as the magic value.
	tail := req.Tail
	tailStr := ""
	switch {
	case tail < 0:
		tailStr = "all"
	case tail == 0:
		tailStr = "0"
	default:
		tailStr = fmt.Sprintf("%d", tail)
	}

	stdout := true
	stderr := true
	if len(req.Streams) > 0 {
		stdout = false
		stderr = false
		for _, s := range req.Streams {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "stdout":
				stdout = true
			case "stderr":
				stderr = true
			}
		}
	}

	since := time.Time{}
	if req.Since != "" {
		// Best effort — invalid timestamps fall through unset (Docker
		// returns from the beginning, capped by tail).
		if t, err := time.Parse(time.RFC3339Nano, req.Since); err == nil {
			since = t
		} else if t, err := time.Parse(time.RFC3339, req.Since); err == nil {
			since = t
		}
	}

	body, err := s.docker.ContainerLogs(stream.Context(), req.ContainerId, deployer.ContainerLogsOptions{
		Stdout:     stdout,
		Stderr:     stderr,
		Follow:     req.Follow,
		Timestamps: true,
		Since:      since,
		Tail:       tailStr,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "docker logs: %v", err)
	}
	defer body.Close()

	dem := deployer.NewLogDemuxer(body, deployer.DemuxOptions{
		MaxLine:       s.maxLine,
		Buffer:        1024,
		HasTimestamps: true,
	})

	prevDropped := int64(0)
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case chunk, ok := <-dem.Out():
			if !ok {
				// Body EOF or read error — emit a synthetic "container
				// exited" marker if we can confirm exit, then return.
				if d := dem.DroppedCount(); d > prevDropped {
					_ = stream.Send(syntheticDropChunk(d - prevDropped))
				}
				_ = stream.Send(syntheticEndChunk(req.ContainerId))
				return nil
			}
			// Emit a synthetic dropped-N marker before the chunk that
			// "won" the next slot, so the consumer sees the gap in
			// chronological order.
			if d := dem.DroppedCount(); d > prevDropped {
				if err := stream.Send(syntheticDropChunk(d - prevDropped)); err != nil {
					return err
				}
				prevDropped = d
			}
			out := &pb.ContainerLogChunk{
				Stream:    chunk.Stream,
				Line:      chunk.Line,
				Truncated: chunk.Truncated,
				Seq:       chunk.Seq,
			}
			if !chunk.Timestamp.IsZero() {
				out.Timestamp = chunk.Timestamp.UTC().Format(time.RFC3339Nano)
			}
			if err := stream.Send(out); err != nil {
				return err
			}
		}
	}
}

// --- Health ---

func (s *Server) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	resp := &pb.HealthResponse{Ok: true}
	if v := s.lastTickUnix.Load(); v > 0 {
		resp.LastTickAgeSeconds = time.Now().Unix() - v
	}
	s.mu.Lock()
	resp.ActiveTailStreams = s.global
	s.mu.Unlock()
	if s.shipperReportFn != nil {
		resp.ShipperActiveContainers = s.shipperReportFn()
	}
	return resp, nil
}

// --- limits ---

func (s *Server) acquire(containerID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.global >= s.maxViewersGlobal {
		return false
	}
	if s.perContainer[containerID] >= s.maxViewersPerContainer {
		return false
	}
	s.perContainer[containerID]++
	s.global++
	return true
}

func (s *Server) release(containerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perContainer[containerID] > 0 {
		s.perContainer[containerID]--
		if s.perContainer[containerID] == 0 {
			delete(s.perContainer, containerID)
		}
	}
	if s.global > 0 {
		s.global--
	}
}

// --- helpers ---

func summaryToProto(c deployer.ContainerSummary) *pb.ContainerDetail {
	name := ""
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}
	d := &pb.ContainerDetail{
		ContainerId:   c.ID,
		ContainerName: name,
		Image:         c.Image,
		State:         c.State,
		Status:        c.Status,
		Labels:        c.Labels,
	}
	if c.Created > 0 {
		d.StartedAt = time.Unix(c.Created, 0).UTC().Format(time.RFC3339)
	}
	if v := c.Labels["muvon.project"]; v != "" {
		d.Project = v
	}
	if v := c.Labels["muvon.component"]; v != "" {
		d.Component = v
	}
	if v := c.Labels["muvon.release_id"]; v != "" {
		d.ReleaseId = v
	}
	return d
}

func inspectToProto(i deployer.ContainerInspectResult) *pb.ContainerDetail {
	d := &pb.ContainerDetail{
		ContainerId:   i.ID,
		ContainerName: i.Name,
		Image:         i.ImageRef,
		ImageDigest:   i.Image,
		State:         i.State,
		Status:        i.Status,
		Labels:        i.Labels,
		ExitCode:      int32(i.ExitCode),
	}
	if !i.StartedAt.IsZero() {
		d.StartedAt = i.StartedAt.UTC().Format(time.RFC3339)
	}
	if !i.FinishedAt.IsZero() {
		d.FinishedAt = i.FinishedAt.UTC().Format(time.RFC3339)
	}
	if v := i.Labels["muvon.project"]; v != "" {
		d.Project = v
	}
	if v := i.Labels["muvon.component"]; v != "" {
		d.Component = v
	}
	if v := i.Labels["muvon.release_id"]; v != "" {
		d.ReleaseId = v
	}
	return d
}

func syntheticDropChunk(n int64) *pb.ContainerLogChunk {
	return &pb.ContainerLogChunk{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Stream:    "stderr",
		Line:      fmt.Sprintf("[muvon] dropped %d log lines (slow consumer)", n),
		Synthetic: true,
	}
}

func syntheticEndChunk(containerID string) *pb.ContainerLogChunk {
	return &pb.ContainerLogChunk{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Stream:    "stderr",
		Line:      fmt.Sprintf("[muvon] log stream ended for container %s", shortID(containerID)),
		Synthetic: true,
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// PrintListenAddr is a convenience used by the binary's startup log so we
// can normalise the unix:// prefix consistently.
func PrintListenAddr(socketPath string) string {
	u := &url.URL{Scheme: "unix", Path: socketPath}
	return u.String()
}

// LogStartup is intended to be called by the binary right before
// Serve() so the slog output matches the dialog/muwaf shape.
func LogStartup(socketPath string) {
	slog.Info("muvon-deployer gRPC listening", "socket", socketPath)
}
