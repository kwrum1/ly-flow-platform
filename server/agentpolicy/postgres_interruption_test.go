package agentpolicy

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresPolicyStore_interrupted_assignment_does_not_create_false_ack(t *testing.T) {
	// Given
	dsn := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("LYFLOW_TEST_POSTGRES_DSN is required for interruption QA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS rasp_policy_audit,rasp_policy_assignments,rasp_policy_versions CASCADE`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	store := NewPostgresStore(pool)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	policy := PersistedPolicy{
		Envelope: SignedPolicy{Policy: Policy{ID: "fixture", Version: 1, Owner: "owner", Mode: ModeMonitor, ExpiresAt: now.Add(time.Hour), FailBehavior: FailMonitor, AuditLink: "audit://fixture"}},
		State:    StateActive, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.Create(ctx, policy, AuditEvent{Version: 1, Type: "created", AuditLink: "audit://fixture", OccurredAt: now}); err != nil {
		t.Fatalf("create policy fixture: %v", err)
	}
	interrupted, interrupt := context.WithCancel(ctx)
	interrupt()

	// When
	err = store.Assign(interrupted, Assignment{AgentID: "agent-interrupted", Envelope: policy.Envelope, AssignedAt: now}, AuditEvent{Version: 1, Type: "assigned", AuditLink: "audit://fixture", OccurredAt: now})

	// Then
	if err == nil {
		t.Fatal("interrupted assignment unexpectedly succeeded")
	}
	acks, countErr := store.ACKCount(ctx, 1)
	if countErr != nil {
		t.Fatalf("count acknowledgements: %v", countErr)
	}
	if acks != 0 {
		t.Fatalf("ack count = %d, want 0", acks)
	}
}
