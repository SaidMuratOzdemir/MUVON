package grpcserver

import (
	"context"
	"testing"

	pb "muvon/proto/logpb"
)

type staticOwners map[string]string

func (o staticOwners) Owner(_ context.Context, project, component string) (string, bool) {
	owner, ok := o[project+"/"+component]
	return owner, ok
}

func TestAttributeContainerMeta(t *testing.T) {
	owners := staticOwners{
		"shop/api":    "agent-a",
		"billing/web": "",
	}
	agentA := ContextWithAgent(context.Background(), AgentIdentity{ID: "agent-a", HostID: "host-a"})
	agentB := ContextWithAgent(context.Background(), AgentIdentity{ID: "agent-b", HostID: "host-b"})
	central := context.Background()

	for _, tc := range []struct {
		name        string
		ctx         context.Context
		project     string
		component   string
		wantProject string
	}{
		{"agent claims its own component", agentA, "shop", "api", "shop"},
		{"agent claims another agent's component", agentB, "shop", "api", ""},
		{"agent claims a central component", agentA, "billing", "web", ""},
		{"central claims an agent component", central, "shop", "api", ""},
		{"central claims its own component", central, "billing", "web", "billing"},
		{"claim of a component that does not exist", agentA, "ghost", "api", ""},
		{"unmanaged container claims nothing", agentA, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ownership: owners}
			in := &pb.ContainerMeta{
				ContainerId: "c1", Project: tc.project, Component: tc.component,
				ReleaseId: "r1", HostId: "central",
			}
			got := s.attributeContainerMeta(tc.ctx, in)
			if got.Project != tc.wantProject {
				t.Fatalf("project = %q, want %q", got.Project, tc.wantProject)
			}
			if tc.wantProject == "" && tc.project != "" && (got.Component != "" || got.ReleaseId != "") {
				t.Fatalf("a dropped claim kept component %q release %q", got.Component, got.ReleaseId)
			}
			if in.Project != tc.project {
				t.Fatal("the request meta was modified in place")
			}
		})
	}
}

// host_id decides which agent the panel dials for a live tail, so an agent
// cannot pick it.
func TestAttributeContainerMetaHostID(t *testing.T) {
	s := &Server{}

	withHost := ContextWithAgent(context.Background(), AgentIdentity{ID: "agent-a", HostID: "host-a"})
	if got := s.attributeContainerMeta(withHost, &pb.ContainerMeta{ContainerId: "c1", HostId: "host-b"}); got.HostId != "host-a" {
		t.Errorf("host_id = %q, want the agent record's host-a", got.HostId)
	}

	noHost := ContextWithAgent(context.Background(), AgentIdentity{ID: "agent-a"})
	if got := s.attributeContainerMeta(noHost, &pb.ContainerMeta{ContainerId: "c1", HostId: "central"}); got.HostId != "agent:agent-a" {
		t.Errorf("host_id = %q, want an agent cannot claim central", got.HostId)
	}

	if got := s.attributeContainerMeta(context.Background(), &pb.ContainerMeta{ContainerId: "c1", HostId: "central"}); got.HostId != "central" {
		t.Errorf("host_id = %q, want central for the local socket", got.HostId)
	}
}

func TestOwnerCacheRefreshesOnMiss(t *testing.T) {
	calls := 0
	owners := map[string]string{}
	c := NewOwnerCache(func(context.Context) (map[string]string, error) {
		calls++
		copyOf := make(map[string]string, len(owners))
		for k, v := range owners {
			copyOf[k] = v
		}
		return copyOf, nil
	})

	if _, ok := c.Owner(context.Background(), "shop", "api"); ok {
		t.Fatal("unknown component reported as existing")
	}
	owners["shop/api"] = "agent-a"
	// Within the miss interval the cache does not hit the database again.
	if _, ok := c.Owner(context.Background(), "shop", "api"); ok {
		t.Fatal("cache refreshed inside the miss interval")
	}
	if calls != 1 {
		t.Fatalf("loads = %d, want 1", calls)
	}
}
