package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentcenter/pb"
	"github.com/lyflow/ly-flow-platform/server/agentidentity"
	"github.com/lyflow/ly-flow-platform/server/ingestionauth"
	"github.com/lyflow/ly-flow-platform/server/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

type failingAgentCenterAudit struct{ outcome string }

func (a failingAgentCenterAudit) Record(_ context.Context, event ingestionauth.Event) error {
	if event.Outcome == a.outcome {
		return errors.New("audit persistence failed")
	}
	return nil
}

func TestGenerateAgentKeyFailsClosedWhenEntropyUnavailable(t *testing.T) {
	// When
	_, err := generateAgentKey(failingReader{})

	// Then
	if err == nil {
		t.Fatal("credential generation succeeded without entropy")
	}
	credential, err := generateAgentKey(bytes.NewReader(make([]byte, 32)))
	if err != nil || len(credential) != len("key-")+64 {
		t.Fatalf("credential generation = %q error = %v", credential, err)
	}
}

type fakeAgentDB struct {
	agent            *models.Agent
	heartbeatUpdates int
}

func (db *fakeAgentDB) CreateAgent(_ context.Context, agent *models.Agent) error {
	db.agent = agent
	return nil
}
func (db *fakeAgentDB) UpdateAgentHeartbeat(context.Context, string) error {
	db.heartbeatUpdates++
	return nil
}
func (db *fakeAgentDB) GetAgentByUUID(context.Context, string) (*models.Agent, error) {
	if db.agent == nil {
		return nil, errors.New("agent not found")
	}
	return db.agent, nil
}

func TestGRPCEnrollmentTokenAndCredentialAuthentication(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := agentidentity.NewManager(agentidentity.NewMemoryStore(), func() time.Time { return now })
	token, err := manager.IssueEnrollmentToken("agent-grpc", time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	database := &fakeAgentDB{}
	server := &AgentServer{db: database, identity: manager, agents: map[string]*AgentSession{}}
	enrollContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs(enrollmentTokenMetadata, token))

	// When
	response, err := server.Enroll(enrollContext, &pb.EnrollRequest{Hostname: "grpc-host", Ip: "192.0.2.20"})

	// Then
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if response.AgentId != "agent-grpc" || response.AgentKey == "" {
		t.Fatalf("enrollment response = id %q key %q", response.AgentId, response.AgentKey)
	}
	if database.agent == nil {
		t.Fatal("Agent enrollment was not persisted")
	}
	if database.agent.AgentKey != "" {
		t.Fatalf("persisted plaintext Agent credential = %q", database.agent.AgentKey)
	}
	authContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationMetadata, "Bearer "+response.AgentKey, agentIDMetadata, response.AgentId))
	if _, err := server.Heartbeat(authContext, &pb.HeartbeatRequest{AgentId: response.AgentId}); err != nil {
		t.Fatalf("authenticated heartbeat: %v", err)
	}
	restarted := &AgentServer{db: database, identity: manager, agents: map[string]*AgentSession{}}
	if _, err := restarted.Heartbeat(authContext, &pb.HeartbeatRequest{AgentId: response.AgentId}); err != nil {
		t.Fatalf("heartbeat after AgentCenter restart: %v", err)
	}
	if _, err := server.Enroll(enrollContext, &pb.EnrollRequest{Hostname: "replay"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("replayed enrollment status = %s, error = %v", status.Code(err), err)
	}
	badContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationMetadata, "Bearer wrong", agentIDMetadata, response.AgentId))
	if _, err := server.Heartbeat(badContext, &pb.HeartbeatRequest{AgentId: response.AgentId}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong credential status = %s, error = %v", status.Code(err), err)
	}
}

func TestReportTaskResultRejectsUnknownAgent(t *testing.T) {
	server := &AgentServer{identity: agentidentity.NewManager(agentidentity.NewMemoryStore(), time.Now), agents: map[string]*AgentSession{}}
	_, err := server.ReportTaskResult(context.Background(), &pb.TaskResultRequest{AgentId: "missing", TaskId: "task-1"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for unknown agent, got %v", err)
	}
}

func TestReportTaskResultAcceptsKnownAgent(t *testing.T) {
	store := agentidentity.NewMemoryStore()
	manager := agentidentity.NewManager(store, time.Now)
	id, err := agentidentity.NewAgentID("agent-1")
	if err != nil {
		t.Fatalf("agent id: %v", err)
	}
	record, err := agentidentity.NewLegacyRecord(id, "credential", agentidentity.EnabledTransports{GRPC: true})
	if err != nil {
		t.Fatalf("legacy record: %v", err)
	}
	if err := manager.Store(record); err != nil {
		t.Fatalf("store record: %v", err)
	}
	server := &AgentServer{identity: manager, agents: map[string]*AgentSession{"agent-1": {ID: "agent-1"}}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationMetadata, "Bearer credential", agentIDMetadata, "agent-1"))
	resp, err := server.ReportTaskResult(ctx, &pb.TaskResultRequest{AgentId: "agent-1", TaskId: "task-1", Success: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.Ack {
		t.Fatalf("expected ack response, got %#v", resp)
	}
}

func TestGRPCPrincipalRejectsPayloadAgentMismatchAndMissingMetadata(t *testing.T) {
	// Given
	store := agentidentity.NewMemoryStore()
	manager := agentidentity.NewManager(store, time.Now)
	id, err := agentidentity.NewAgentID("agent-1")
	if err != nil {
		t.Fatalf("agent id: %v", err)
	}
	record, err := agentidentity.NewLegacyRecord(id, "credential", agentidentity.EnabledTransports{GRPC: true})
	if err != nil {
		t.Fatalf("legacy record: %v", err)
	}
	if err := manager.Store(record); err != nil {
		t.Fatalf("store record: %v", err)
	}
	server := newAgentServerForTest(manager, map[string]*AgentSession{"agent-1": {ID: "agent-1"}})
	mismatchContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationMetadata, "Bearer credential", agentIDMetadata, "agent-1"))

	// When
	_, mismatchErr := server.ReportTaskResult(mismatchContext, &pb.TaskResultRequest{AgentId: "agent-2", TaskId: "task-1"})
	_, missingErr := server.ReportTaskResult(context.Background(), &pb.TaskResultRequest{AgentId: "agent-1", TaskId: "task-1"})

	// Then
	if status.Code(mismatchErr) != codes.PermissionDenied {
		t.Fatalf("mismatch status = %s error = %v", status.Code(mismatchErr), mismatchErr)
	}
	if status.Code(missingErr) != codes.Unauthenticated {
		t.Fatalf("missing metadata status = %s error = %v", status.Code(missingErr), missingErr)
	}
}

func TestGRPCAuditFailurePropagatesAndPreventsHeartbeatMutation(t *testing.T) {
	// Given
	manager := grpcTestIdentity(t)
	lastSeen := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	database := &fakeAgentDB{agent: &models.Agent{UUID: "agent-1", LastHeartbeat: lastSeen}}
	authenticator := ingestionauth.New(manager, failingAgentCenterAudit{outcome: ingestionauth.OutcomeAccepted}, time.Now, 10, time.Minute)
	server := &AgentServer{db: database, identity: manager, authn: authenticator, agents: map[string]*AgentSession{}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationMetadata, "Bearer credential", agentIDMetadata, "agent-1"))

	// When
	_, err := server.Heartbeat(ctx, &pb.HeartbeatRequest{AgentId: "agent-1"})

	// Then
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %s error = %v", status.Code(err), err)
	}
	if database.heartbeatUpdates != 0 || len(server.agents) != 0 {
		t.Fatalf("heartbeat mutated before audit: updates=%d cached_sessions=%d", database.heartbeatUpdates, len(server.agents))
	}
}

func TestGRPCMismatchAuditFailureReturnsUnavailable(t *testing.T) {
	// Given
	manager := grpcTestIdentity(t)
	authenticator := ingestionauth.New(manager, failingAgentCenterAudit{outcome: ingestionauth.OutcomeIdentityMismatch}, time.Now, 10, time.Minute)
	server := &AgentServer{identity: manager, authn: authenticator, agents: map[string]*AgentSession{"agent-1": {ID: "agent-1"}}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationMetadata, "Bearer credential", agentIDMetadata, "agent-1"))

	// When
	_, err := server.ReportTaskResult(ctx, &pb.TaskResultRequest{AgentId: "agent-2", TaskId: "task-1"})

	// Then
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %s error = %v", status.Code(err), err)
	}
}

func grpcTestIdentity(t *testing.T) *agentidentity.Manager {
	t.Helper()
	manager := agentidentity.NewManager(agentidentity.NewMemoryStore(), time.Now)
	id, err := agentidentity.NewAgentID("agent-1")
	if err != nil {
		t.Fatalf("Agent ID: %v", err)
	}
	record, err := agentidentity.NewLegacyRecord(id, "credential", agentidentity.EnabledTransports{GRPC: true})
	if err != nil {
		t.Fatalf("Agent record: %v", err)
	}
	if err := manager.Store(record); err != nil {
		t.Fatalf("store Agent: %v", err)
	}
	return manager
}
