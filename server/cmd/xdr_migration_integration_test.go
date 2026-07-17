package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestXDRGraphRuntime_restart_is_idempotent_and_version_separated(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	events := []contracts.CanonicalSecurityEvent{
		canonicalXDRTestEvent(t, "graph-1", now),
		canonicalXDRTestEvent(t, "graph-2", now.Add(time.Minute)),
	}
	first, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(time.Now, now.Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("create first runtime: %v", err)
	}

	// When
	active, err := first.RunActive(ctx, events, 20)
	if err != nil {
		t.Fatalf("run active: %v", err)
	}
	shadow, err := first.RunShadow(ctx, events)
	if err != nil {
		t.Fatalf("run shadow: %v", err)
	}
	checkpointUpdatedAt := readXDRCheckpointUpdatedAt(t, ctx, pool, "v2-active")
	restarted, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(time.Now, now.Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("restart runtime: %v", err)
	}
	activeAfterRestart, err := restarted.RunActive(ctx, events, 20)
	if err != nil {
		t.Fatalf("rerun active: %v", err)
	}

	// Then
	if active.checksum == "" || active.checksum != shadow.checksum || active.checksum != activeAfterRestart.checksum {
		t.Fatalf("checksums active=%q shadow=%q restart=%q", active.checksum, shadow.checksum, activeAfterRestart.checksum)
	}
	assertXDRPersistenceCounts(t, ctx, pool, "v2-active", len(events), 1)
	assertXDRPersistenceCounts(t, ctx, pool, "v3-shadow", len(events), 1)
	if got := readXDRCheckpointUpdatedAt(t, ctx, pool, "v2-active"); !got.Equal(checkpointUpdatedAt) {
		t.Fatalf("idempotent restart rewrote checkpoint: before=%s after=%s", checkpointUpdatedAt, got)
	}
	health := restarted.Health().Algorithms["v2-active"]
	if health.Checkpoint == "" || health.GraphChecksum != active.checksum {
		t.Fatalf("restored active health=%+v", health)
	}
}

func TestXDRGraphRuntime_failed_persistence_degrades_without_promotion(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(time.Now, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	pool.Close()

	// When
	result, err := runtime.RunActive(ctx, []contracts.CanonicalSecurityEvent{canonicalXDRTestEvent(t, "failed", now)}, 20)

	// Then
	if err == nil || len(result.chains) != 0 {
		t.Fatalf("failed persistence promoted chains=%d err=%v", len(result.chains), err)
	}
	health := runtime.Health()
	if health.Status != xdrHealthDegraded || health.LastPersistenceError == "" {
		t.Fatalf("runtime health=%+v", health)
	}
}

func TestXDRGraphRuntime_unknown_schema_quarantine_preserves_graph(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	valid := canonicalXDRTestEvent(t, "valid", now)
	if _, err := runtime.RunActive(ctx, []contracts.CanonicalSecurityEvent{valid}, 20); err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	before := countXDRRows(t, ctx, pool, "xdr_graph_nodes_versioned", "v2-active")
	future := valid
	future.SchemaVersion = "lyflow.security_event.v99"

	// When
	err = runtime.IngestRaw(ctx, xdrV2ActiveIdentity(), [][]byte{marshalXDRFixture(t, future)})

	// Then
	var quarantine *contracts.QuarantineError
	if !errors.As(err, &quarantine) {
		t.Fatalf("future schema error=%v", err)
	}
	after := countXDRRows(t, ctx, pool, "xdr_graph_nodes_versioned", "v2-active")
	if before != after {
		t.Fatalf("quarantine corrupted graph rows before=%d after=%d", before, after)
	}
	if countXDRRows(t, ctx, pool, "xdr_input_quarantine", "v2-active") != 1 {
		t.Fatal("quarantine record missing")
	}
}

func TestXDRGraphRuntime_interrupted_persistence_preserves_checkpoint_and_dirty_version(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(time.Now, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	if _, err := runtime.RunActive(ctx, []contracts.CanonicalSecurityEvent{canonicalXDRTestEvent(t, "committed", now)}, 20); err != nil {
		t.Fatalf("seed committed graph: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO xdr_algorithm_checkpoints
		(tenant_id, algorithm_version, input_checksum, graph_checksum, event_count, updated_at)
		VALUES ('dirty-tenant','v3-shadow','dirty-input','dirty-graph',9,NOW())`); err != nil {
		t.Fatalf("seed dirty checkpoint: %v", err)
	}
	var before string
	if err := pool.QueryRow(ctx, `SELECT graph_checksum FROM xdr_algorithm_checkpoints WHERE tenant_id='default' AND algorithm_version='v2-active'`).Scan(&before); err != nil {
		t.Fatalf("read checkpoint before interruption: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	// When
	_, err = runtime.RunActive(cancelled, []contracts.CanonicalSecurityEvent{canonicalXDRTestEvent(t, "interrupted", now)}, 20)

	// Then
	if err == nil {
		t.Fatal("cancelled persistence unexpectedly succeeded")
	}
	var after, dirty string
	if err := pool.QueryRow(ctx, `SELECT graph_checksum FROM xdr_algorithm_checkpoints WHERE tenant_id='default' AND algorithm_version='v2-active'`).Scan(&after); err != nil {
		t.Fatalf("read checkpoint after interruption: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT graph_checksum FROM xdr_algorithm_checkpoints WHERE tenant_id='dirty-tenant' AND algorithm_version='v3-shadow'`).Scan(&dirty); err != nil {
		t.Fatalf("read dirty checkpoint: %v", err)
	}
	if before != after || dirty != "dirty-graph" {
		t.Fatalf("interruption changed checkpoint before=%q after=%q dirty=%q", before, after, dirty)
	}
}

func xdrMigrationTestPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("LYFLOW_TEST_POSTGRES_DSN is required for XDR migration integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS xdr_scoring_input_details_versioned, xdr_input_quarantine, xdr_algorithm_checkpoints, xdr_chain_hypotheses_versioned, xdr_graph_edges_versioned, xdr_graph_nodes_versioned`); err != nil {
		t.Fatalf("reset XDR tables: %v", err)
	}
	return pool, ctx
}

func assertXDRPersistenceCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, algorithm string, events, checkpoints int) {
	t.Helper()
	if got := countXDRRows(t, ctx, pool, "xdr_graph_nodes_versioned", algorithm); got != events {
		t.Fatalf("%s node rows=%d, want %d", algorithm, got, events)
	}
	if got := countXDRRows(t, ctx, pool, "xdr_algorithm_checkpoints", algorithm); got != checkpoints {
		t.Fatalf("%s checkpoints=%d, want %d", algorithm, got, checkpoints)
	}
}

func countXDRRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, algorithm string) int {
	t.Helper()
	var count int
	query := "SELECT COUNT(*) FROM " + table + " WHERE algorithm_version=$1"
	if err := pool.QueryRow(ctx, query, algorithm).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

func readXDRCheckpointUpdatedAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, algorithm string) time.Time {
	t.Helper()
	var updatedAt time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM xdr_algorithm_checkpoints WHERE tenant_id='default' AND algorithm_version=$1`, algorithm).Scan(&updatedAt); err != nil {
		t.Fatalf("read %s checkpoint timestamp: %v", algorithm, err)
	}
	return updatedAt
}
