package agentpolicy

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

func TestPostgresPolicyStore_persists_promoted_policy_ack_and_rollback(t *testing.T) {
	// Given
	dsn := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("LYFLOW_TEST_POSTGRES_DSN is required for real persistence QA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS rasp_policy_audit, rasp_policy_assignments, rasp_policy_versions CASCADE`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	store := NewPostgresStore(pool)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	base := t.TempDir()
	layout := trustroot.Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.Bootstrap(rand.Reader); err != nil {
		t.Fatalf("bootstrap roots: %v", err)
	}
	signer, err := layout.LoadSigner(trustroot.PolicySigner)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	manager := NewManager(ManagerConfig{Store: store, Signer: signer, Verifier: layout, Now: func() time.Time { return now }})
	if _, err := manager.EnsureDefault(ctx, "platform-owner", "audit://default"); err != nil {
		t.Fatalf("ensure default: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("repeat schema migration over live policy: %v", err)
	}
	policy := DefaultPolicy(now, "security-owner", "audit://version/2")
	policy.ID, policy.Version = "rasp-primary", 2
	policy.Selectors.AgentIDs = []string{"agent-real"}
	policy.Rollback = RollbackPolicy{TargetVersion: 1, Deadline: now.Add(48 * time.Hour)}

	// When
	signed, err := manager.Create(ctx, policy)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := manager.StartCanary(ctx, policy.Version); err != nil {
		t.Fatalf("start canary: %v", err)
	}
	assignment, err := manager.Assign(ctx, assignmentTarget("agent-real", shared.LanguagePython), policy.Version)
	if err != nil {
		t.Fatalf("assign policy: %v", err)
	}
	if err := manager.Acknowledge(ctx, Acknowledgement{AgentID: assignment.AgentID, Version: policy.Version, Signature: signed.Signature}); err != nil {
		t.Fatalf("ack policy: %v", err)
	}
	if err := manager.CompleteCanary(ctx, policy.Version, successfulCanary()); err != nil {
		t.Fatalf("complete canary: %v", err)
	}
	if err := manager.Promote(ctx, policy.Version); err != nil {
		t.Fatalf("promote policy: %v", err)
	}
	restarted := NewManager(ManagerConfig{Store: NewPostgresStore(pool), Signer: signer, Verifier: layout, Now: func() time.Time { return now }})
	if err := restarted.Rollback(ctx, policy.Version); err != nil {
		t.Fatalf("rollback after manager restart: %v", err)
	}

	// Then
	active, err := store.Active(ctx)
	if err != nil {
		t.Fatalf("load active: %v", err)
	}
	if active.Envelope.Policy.Version != 1 {
		t.Fatalf("active version = %d, want 1", active.Envelope.Policy.Version)
	}
}
