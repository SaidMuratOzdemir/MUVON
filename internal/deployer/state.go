package deployer

import (
	"context"
	"time"

	"muvon/internal/db"
)

// State abstracts every piece of persistent state the deployer touches.
// The central deployer (muvon-deployer) supplies a DB-backed implementation;
// the embedded edge deployer in cmd/agent supplies an HTTP-backed one
// that calls the central admin server.
//
// All methods take a context so the caller can cancel long-running ops on
// shutdown. Returns mirror the underlying db package types verbatim — the
// HTTP implementation simply serialises/deserialises the same shapes.
type State interface {
	// Claim is the only mutator that hands a deployment out. Returns
	// ok=false (no error) when no deployment matches the caller's
	// owner — the loop sleeps and tries again next tick.
	Claim(ctx context.Context) (deployment db.Deployment, ok bool, err error)

	// LoadPlan returns the deployment, its release, the parent project,
	// and every component+release_component pair that needs a candidate
	// container. Called once per claimed deployment.
	LoadPlan(ctx context.Context, deploymentID string) (db.DeploymentPlan, error)

	// AddEvent appends a single deployment_events row. Detail is JSON-
	// serialised by the implementation, never inspected here.
	AddEvent(ctx context.Context, deploymentID, eventType, message string, detail any) error

	// Fail flips a deployment to 'failed' with an error message and
	// records a "failed" event in the same transaction.
	Fail(ctx context.Context, deploymentID, message string) error

	// CreateInstance records a freshly-started candidate container.
	// State starts as 'warming'; the caller will Promote it once
	// health checks pass.
	CreateInstance(ctx context.Context, componentID int, releaseUUID, containerID, containerName, backendURL string) (db.DeployInstance, error)

	// MarkInstanceUnhealthy records why a candidate never reached
	// healthy. Distinct from Fail — the deployment as a whole is failed
	// separately by the caller.
	MarkInstanceUnhealthy(ctx context.Context, instanceID, message string) error

	// Promote atomically (1) drains every existing 'active' instance for
	// the affected components, (2) marks candidates 'active', and (3)
	// flips the deployment to 'succeeded'. Returns an error if no
	// candidates survived health checks.
	Promote(ctx context.Context, deploymentID string, candidateIDs []string) error

	// ResetStaleRunning recovers from a deployer crash: deployments stuck
	// in 'running' longer than `olderThan` go back to 'pending' so the
	// next tick retries them. Returns rows reset.
	ResetStaleRunning(ctx context.Context, olderThan time.Duration) (int, error)

	// CleanupStaleWarming marks 'warming' instances 'unhealthy' when the
	// deployment they belong to has finished (succeeded or failed) —
	// usually because the deployer crashed mid-promote.
	CleanupStaleWarming(ctx context.Context) (int, error)

	// ListDrainable returns instances ready to stop: either no in-flight
	// requests remain, or the configured drain timeout has elapsed.
	ListDrainable(ctx context.Context) ([]db.DeployInstance, error)

	// MarkInstanceStopped is the final state transition after Docker
	// confirms the container has been removed.
	MarkInstanceStopped(ctx context.Context, instanceID string) error

	// ListLiveManagedContainerIDs returns the union of every container
	// the system still wants alive. Containers Docker shows that aren't
	// in this set are orphans from a crashed deployment.
	ListLiveManagedContainerIDs(ctx context.Context) (map[string]struct{}, error)

	// ListPrunableImageRefs returns image refs for a component that are
	// safe to drop from the local Docker daemon — outside the last keepN
	// succeeded releases and not bound to any live instance. Called
	// best-effort after each successful promote; errors are logged but
	// don't fail the deployment.
	ListPrunableImageRefs(ctx context.Context, componentID, keepN int) ([]string, error)
}

// dbState wraps *db.DB so it satisfies State for the central deployer.
// The agent_id filter is bound at construction; central deployer passes
// "" (NULL filter), the embedded agent deployer would pass its own id.
type dbState struct {
	db      *db.DB
	agentID string
}

// NewDBState wires *db.DB to the State interface. Pass agentID="" for
// the central deployer; an embedded edge deployer would pass its agent id
// to claim only its own deployments.
func NewDBState(database *db.DB, agentID string) State {
	return &dbState{db: database, agentID: agentID}
}

func (s *dbState) Claim(ctx context.Context) (db.Deployment, bool, error) {
	return s.db.ClaimNextDeployment(ctx, s.agentID)
}

func (s *dbState) LoadPlan(ctx context.Context, deploymentID string) (db.DeploymentPlan, error) {
	return s.db.LoadDeploymentPlan(ctx, deploymentID)
}

func (s *dbState) AddEvent(ctx context.Context, deploymentID, eventType, message string, detail any) error {
	return s.db.AddDeploymentEvent(ctx, deploymentID, eventType, message, detail)
}

func (s *dbState) Fail(ctx context.Context, deploymentID, message string) error {
	return s.db.FailDeployment(ctx, deploymentID, message)
}

func (s *dbState) CreateInstance(ctx context.Context, componentID int, releaseUUID, containerID, containerName, backendURL string) (db.DeployInstance, error) {
	return s.db.CreateDeployInstance(ctx, componentID, releaseUUID, containerID, containerName, backendURL)
}

func (s *dbState) MarkInstanceUnhealthy(ctx context.Context, instanceID, message string) error {
	return s.db.MarkDeployInstanceUnhealthy(ctx, instanceID, message)
}

func (s *dbState) Promote(ctx context.Context, deploymentID string, candidateIDs []string) error {
	return s.db.PromoteDeployInstances(ctx, deploymentID, candidateIDs)
}

func (s *dbState) ResetStaleRunning(ctx context.Context, olderThan time.Duration) (int, error) {
	return s.db.ResetStaleRunningDeployments(ctx, olderThan)
}

func (s *dbState) CleanupStaleWarming(ctx context.Context) (int, error) {
	return s.db.CleanupStaleWarmingInstances(ctx)
}

func (s *dbState) ListDrainable(ctx context.Context) ([]db.DeployInstance, error) {
	return s.db.ListDrainableDeployInstances(ctx)
}

func (s *dbState) MarkInstanceStopped(ctx context.Context, instanceID string) error {
	return s.db.MarkDeployInstanceStopped(ctx, instanceID)
}

func (s *dbState) ListLiveManagedContainerIDs(ctx context.Context) (map[string]struct{}, error) {
	return s.db.ListLiveManagedContainerIDsForAgent(ctx, s.agentID)
}

func (s *dbState) ListPrunableImageRefs(ctx context.Context, componentID, keepN int) ([]string, error) {
	return s.db.ListPrunableImageRefsForAgent(ctx, s.agentID, componentID, keepN)
}
