package grpcserver

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pb "muvon/proto/logpb"
)

// AgentIdentity is the authenticated caller on the TCP listener. The unix
// socket carries none: it is reachable only from central's own containers.
type AgentIdentity struct {
	ID     string
	HostID string
}

type agentIdentityKey struct{}

// ContextWithAgent records the agent an API key belongs to, so handlers can
// decide what that agent is allowed to claim.
func ContextWithAgent(ctx context.Context, a AgentIdentity) context.Context {
	return context.WithValue(ctx, agentIdentityKey{}, a)
}

// AgentFromContext returns the authenticated agent, or false for a local
// caller.
func AgentFromContext(ctx context.Context) (AgentIdentity, bool) {
	a, ok := ctx.Value(agentIdentityKey{}).(AgentIdentity)
	return a, ok
}

// ComponentOwnership reports which host runs a managed component.
type ComponentOwnership interface {
	// Owner returns the agent id running project/component, "" for central,
	// and false when no such component exists.
	Owner(ctx context.Context, project, component string) (string, bool)
}

// SetComponentOwnership registers the ownership source. Without one, container
// batches keep the attribution the shipper sent.
func (s *Server) SetComponentOwnership(o ComponentOwnership) {
	s.ownership = o
}

// attributeContainerMeta decides what a batch may claim about itself.
//
// Project and component come from container labels, and labels are whatever
// the shipper sends: an agent key proves the caller is some agent, not that the
// container belongs to it. Event rules and the panel group lines by project, so
// a claim is kept only when the component exists and runs on the host that
// sent it. A claim that fails is dropped rather than refused, because the line
// itself is still worth storing. host_id is taken from the agent record for the
// same reason, since it decides which agent the panel dials for a live tail.
func (s *Server) attributeContainerMeta(ctx context.Context, meta *pb.ContainerMeta) *pb.ContainerMeta {
	out := proto.Clone(meta).(*pb.ContainerMeta)
	caller, fromAgent := AgentFromContext(ctx)

	if fromAgent {
		switch {
		case caller.HostID != "":
			out.HostId = caller.HostID
		case out.HostId == "" || out.HostId == "central":
			out.HostId = "agent:" + caller.ID
		}
	}

	if out.Project == "" || s.ownership == nil {
		return out
	}
	owner, exists := s.ownership.Owner(ctx, out.Project, out.Component)
	want := ""
	if fromAgent {
		want = caller.ID
	}
	if exists && owner == want {
		return out
	}

	s.warnUnattributed(out.ContainerId, out.Project, out.Component, want, owner, exists)
	out.Project = ""
	out.Component = ""
	out.ReleaseId = ""
	return out
}

// warnUnattributed logs a refused claim once per container per hour; a
// running container repeats the same claim on every batch.
func (s *Server) warnUnattributed(containerID, project, component, caller, owner string, exists bool) {
	now := time.Now()
	if v, ok := s.attributionWarned.Load(containerID); ok && now.Sub(v.(time.Time)) < time.Hour {
		return
	}
	s.attributionWarned.Store(containerID, now)
	slog.Warn("container log project claim dropped: the component does not run on the sending host",
		"container_id", containerID,
		"project", project,
		"component", component,
		"caller_agent", caller,
		"owner_agent", owner,
		"component_exists", exists)
}

// OwnerCache answers ComponentOwnership from a periodically refreshed map.
// A miss refreshes early, bounded, so a component created a moment ago is
// recognised on its first batch without a query per batch.
type OwnerCache struct {
	load func(ctx context.Context) (map[string]string, error)

	mu          sync.RWMutex
	owners      map[string]string
	loadedAt    time.Time
	lastAttempt time.Time
}

const (
	ownerCacheMaxAge      = 30 * time.Second
	ownerCacheMissRefresh = 5 * time.Second
)

// NewOwnerCache wraps a loader such as db.ComponentOwners.
func NewOwnerCache(load func(ctx context.Context) (map[string]string, error)) *OwnerCache {
	return &OwnerCache{load: load}
}

func (c *OwnerCache) Owner(ctx context.Context, project, component string) (string, bool) {
	key := project + "/" + component
	now := time.Now()

	c.mu.RLock()
	owner, ok := c.owners[key]
	stale := now.Sub(c.loadedAt) > ownerCacheMaxAge
	canRetry := now.Sub(c.lastAttempt) > ownerCacheMissRefresh
	c.mu.RUnlock()

	if (stale || !ok) && canRetry {
		c.refresh(ctx, now)
		c.mu.RLock()
		owner, ok = c.owners[key]
		c.mu.RUnlock()
	}
	return owner, ok
}

func (c *OwnerCache) refresh(ctx context.Context, now time.Time) {
	c.mu.Lock()
	if now.Sub(c.lastAttempt) <= ownerCacheMissRefresh {
		c.mu.Unlock()
		return
	}
	c.lastAttempt = now
	c.mu.Unlock()

	owners, err := c.load(ctx)
	if err != nil {
		// Keep the previous map: a database hiccup must not strip the
		// attribution of every line until it passes.
		slog.Warn("component owner refresh failed", "error", err)
		return
	}
	c.mu.Lock()
	c.owners = owners
	c.loadedAt = now
	c.mu.Unlock()
}
