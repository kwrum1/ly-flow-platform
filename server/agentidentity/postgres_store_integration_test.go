package agentidentity

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresEnrollmentRollsBackTokenWhenIdentityEventPersistenceFails(t *testing.T) {
	// Given
	dsn := os.Getenv("LYFLOW_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("LYFLOW_POSTGRES_TEST_DSN is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	store := NewPostgresStore(pool)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION fail_agent_identity_event() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'injected event persistence failure'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER fail_agent_identity_event BEFORE INSERT ON agent_identity_events
		FOR EACH ROW EXECUTE FUNCTION fail_agent_identity_event()`)
	if err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS fail_agent_identity_event ON agent_identity_events`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS fail_agent_identity_event()`)
	})
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := NewPersistentManager(store, store, func() time.Time { return now })
	token, err := manager.IssueEnrollmentToken("agent-postgres-atomic", time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// When
	_, firstErr := manager.EnrollContext(ctx, token, "legacy", EnabledTransports{HTTP: true})
	if _, err := pool.Exec(ctx, `DROP TRIGGER fail_agent_identity_event ON agent_identity_events`); err != nil {
		t.Fatalf("remove failure trigger: %v", err)
	}
	_, retryErr := manager.EnrollContext(ctx, token, "legacy", EnabledTransports{HTTP: true})

	// Then
	if firstErr == nil {
		t.Fatal("enrollment succeeded despite identity event failure")
	}
	if retryErr != nil {
		t.Fatalf("retry after transaction rollback: %v", retryErr)
	}
}
