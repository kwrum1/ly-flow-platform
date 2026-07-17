package advisoryresponse

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

type fakeSimulationAdapter struct {
	mu       sync.Mutex
	active   map[string]bool
	apply    int
	rollback int
}

func newFakeSimulationAdapter() *fakeSimulationAdapter {
	return &fakeSimulationAdapter{active: make(map[string]bool)}
}

func (adapter *fakeSimulationAdapter) Simulate(_ context.Context, candidate Candidate) (Verification, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.active[candidate.ID()] = true
	adapter.apply++
	delete(adapter.active, candidate.ID())
	adapter.rollback++
	return Verification{Adapter: "in-memory-fake", Applied: true, RolledBack: true}, nil
}

func (adapter *fakeSimulationAdapter) assertInertRollback(t *testing.T) {
	t.Helper()
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if len(adapter.active) != 0 || adapter.apply != 1 || adapter.rollback != 1 {
		t.Fatalf("fake adapter active=%v apply=%d rollback=%d", adapter.active, adapter.apply, adapter.rollback)
	}
}

func newAdvisoryTestStore(t *testing.T, incidentLastSeen time.Time, agentHealthy bool) (*PostgresStore, *pgxpool.Pool, context.Context, time.Time) {
	t.Helper()
	dsn := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("LYFLOW_TEST_POSTGRES_DSN is required for advisory response integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS response_advisory_audit, response_advisories, incident_lifecycle_cutover_audit, incident_lifecycle_legacy_snapshots, incident_lifecycle_audit, incident_evidence_lineage, incident_suppressions, incidents, incident_lifecycle_schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset advisory tables: %v", err)
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	incidents := incidentlifecycle.NewPostgresStore(pool, func() time.Time { return now })
	if err := incidents.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure incident schema: %v", err)
	}
	snapshot, err := incidentlifecycle.NewActiveSnapshot(incidentlifecycle.ActiveAlgorithm, []incidentlifecycle.Candidate{{
		IncidentID: "inc-1", SourceChainID: "chain-1", Severity: "high",
		FirstSeen: incidentLastSeen.Add(-time.Hour), LastSeen: incidentLastSeen,
	}})
	if err != nil {
		t.Fatalf("create active incident: %v", err)
	}
	if _, err := incidents.SyncActive(ctx, snapshot); err != nil {
		t.Fatalf("seed active incident: %v", err)
	}
	status := "offline"
	if agentHealthy {
		status = "online"
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS agents (uuid TEXT PRIMARY KEY, status TEXT, last_heartbeat TIMESTAMPTZ)`); err != nil {
		t.Fatalf("create Agent health table: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE agents ADD COLUMN IF NOT EXISTS status TEXT, ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMPTZ`); err != nil {
		t.Fatalf("ensure Agent health columns: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agents(uuid,status,last_heartbeat) VALUES ('agent-1',$1,$2) ON CONFLICT (uuid) DO UPDATE SET status=EXCLUDED.status,last_heartbeat=EXCLUDED.last_heartbeat`, status, now); err != nil {
		t.Fatalf("seed Agent health: %v", err)
	}
	store := NewPostgresStore(pool, func() time.Time { return now }, Limits{IncidentMaxAge: 30 * time.Minute, AgentMaxAge: 5 * time.Minute})
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure advisory schema: %v", err)
	}
	return store, pool, ctx, now
}

func testCandidate(t *testing.T) Candidate {
	t.Helper()
	id := CandidateID("inc-1", ActionIncreaseMonitoring, "agent-1")
	candidate, err := NewCandidate(CandidateInput{
		ID: id, IncidentID: "inc-1", AgentID: "agent-1",
		Algorithm: ActiveAlgorithm, Action: ActionIncreaseMonitoring,
		Target: "agent-1", Reason: "elevated chain score",
	})
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	return candidate
}
