package incidentlifecycle

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestStore(t *testing.T) (*PostgresStore, *pgxpool.Pool, context.Context, time.Time) {
	t.Helper()
	dsn := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("LYFLOW_TEST_POSTGRES_DSN is required for incident lifecycle integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS incident_lifecycle_cutover_audit, incident_lifecycle_legacy_snapshots, incident_lifecycle_audit, incident_evidence_lineage, incident_suppressions, incidents, incident_lifecycle_schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset incident lifecycle tables: %v", err)
	}
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	store := NewPostgresStore(pool, func() time.Time { return now })
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return store, pool, ctx, now
}

func activeSnapshot(t *testing.T, now time.Time) ActiveSnapshot {
	t.Helper()
	snapshot, err := NewActiveSnapshot("v2-active", []Candidate{{
		IncidentID: "inc-hyp-1", SourceChainID: "hyp-1", CorrelationKey: "asset-1", Title: "asset-1 attack chain",
		Severity: "high", FirstSeen: now.Add(-time.Hour), LastSeen: now,
		Evidence: []Evidence{
			{EventUID: "event-1", Stage: "initial_access", ObservedAt: now.Add(-time.Hour), SourceNodeUID: "node-event-1"},
			{EventUID: "event-2", Stage: "execution", ObservedAt: now, SourceNodeUID: "node-event-2"},
		},
	}})
	if err != nil {
		t.Fatalf("create active snapshot: %v", err)
	}
	return snapshot
}

func analystActor() Actor { return Actor{ID: "user:7", Role: RoleAnalyst} }
