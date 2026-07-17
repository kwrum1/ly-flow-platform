package analytics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventStorageMigration_read_switch_blocks_when_reconciliation_is_stale_or_clickhouse_is_down(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	if err := manager.Write(ctx, testStorageEvent("gate", 1)); err != nil {
		t.Fatalf("seed legacy event: %v", err)
	}
	if err := manager.Advance(ctx, PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	if _, err := manager.Backfill(ctx, 100); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if err := manager.Advance(ctx, PhaseReconcile); err != nil {
		t.Fatalf("advance reconcile: %v", err)
	}
	if _, err := manager.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// When
	if err := manager.Write(ctx, testStorageEvent("gate", 2)); err != nil {
		t.Fatalf("write after reconcile: %v", err)
	}
	staleErr := manager.Advance(ctx, PhaseReadSwitch)
	if _, err := manager.Reconcile(ctx); err != nil {
		t.Fatalf("refresh reconciliation: %v", err)
	}
	unavailable, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: "http://127.0.0.1:1", Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("create unavailable client: %v", err)
	}
	outageErr := manager.WithClickHouse(unavailable).Advance(ctx, PhaseReadSwitch)

	// Then
	if !errors.Is(staleErr, ErrConsistencyMismatch) || !errors.Is(outageErr, ErrStorageBackpressure) {
		t.Fatalf("stale=%v outage=%v", staleErr, outageErr)
	}
	status, err := manager.Status(ctx)
	if err != nil || status.Phase != PhaseReconcile || !status.Degraded {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestEventStorageMigration_outbox_completion_preserves_concurrent_higher_version(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	if err := manager.Advance(ctx, PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	if err := manager.writePostgres(ctx, testStorageEvent("cas", 1), true); err != nil {
		t.Fatalf("queue version one: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	client, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatalf("create controlled client: %v", err)
	}
	delivery := make(chan error, 1)
	go func() { delivery <- manager.WithClickHouse(client).flushPending(ctx, 1) }()
	<-started

	// When
	if err := manager.writePostgres(ctx, testStorageEvent("cas", 2), true); err != nil {
		t.Fatalf("refresh to version two: %v", err)
	}
	close(release)
	if err := <-delivery; err != nil {
		t.Fatalf("complete version one delivery: %v", err)
	}
	pending, err := manager.pendingEvents(ctx, 10)

	// Then
	if err != nil || len(pending) != 1 || pending[0].Version != 2 {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	if err := manager.flushPending(ctx, 10); err != nil {
		t.Fatalf("deliver preserved version two: %v", err)
	}
}

func TestEventStorageMigration_migrate_transitions_unversioned_merge_tree_once(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	if err := resetStorageMigrationTestSchema(ctx, manager); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	oldDDL := `CREATE TABLE lyflow_security_events (
event_uid String, timestamp DateTime64(3, 'UTC'), source_module String, event_type String, severity String,
agent_id String, host_id String, chain_id String, entity_id String, raw_reference String, message String, payload_json String
) ENGINE = MergeTree ORDER BY event_uid`
	for _, query := range []string{
		`CREATE TABLE lyflow_event_storage_migrations (version UInt64, applied_at DateTime64(3, 'UTC')) ENGINE = ReplacingMergeTree(applied_at) ORDER BY version`,
		`INSERT INTO lyflow_event_storage_migrations VALUES (1, now64(3)), (2, now64(3))`,
		oldDDL,
		`INSERT INTO lyflow_security_events VALUES ('old', now64(3), 'security', 'alert', 'high', 'agent', 'host', '', '', '', 'old', '{}')`,
	} {
		if _, err := manager.clickhouse.execute(ctx, query); err != nil {
			t.Fatalf("seed old schema: %v", err)
		}
	}

	// When
	firstErr := manager.Migrate(ctx)
	secondErr := manager.Migrate(ctx)
	engine, engineErr := manager.clickhouse.execute(ctx, `SELECT engine FROM system.tables WHERE database=currentDatabase() AND name='lyflow_security_events' FORMAT TabSeparated`)
	ledger, ledgerErr := manager.clickhouse.execute(ctx, `SELECT version, count() FROM lyflow_event_storage_migrations GROUP BY version ORDER BY version FORMAT TabSeparated`)
	events, queryErr := manager.clickhouse.QueryFinal(ctx, 10)

	// Then
	if firstErr != nil || secondErr != nil || engineErr != nil || ledgerErr != nil || queryErr != nil {
		t.Fatalf("migrate=%v/%v engine=%v ledger=%v query=%v", firstErr, secondErr, engineErr, ledgerErr, queryErr)
	}
	if strings.TrimSpace(string(engine)) != "ReplacingMergeTree" || strings.TrimSpace(string(ledger)) != "1\t1\n2\t1\n3\t1" {
		t.Fatalf("engine=%q ledger=%q", engine, ledger)
	}
	if len(events) != 1 || events[0].ID != "old" || events[0].Version != 1 {
		t.Fatalf("transitioned events=%+v", events)
	}
}

func TestEventStorageMigration_read_switch_requires_zero_pending_and_non_degraded_control(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	if _, err := manager.postgres.Exec(ctx, `UPDATE lyflow_event_storage_control SET phase=$1, last_reconcile_match=TRUE, degraded=TRUE WHERE singleton=TRUE`, PhaseReconcile); err != nil {
		t.Fatalf("seed degraded reconcile: %v", err)
	}

	// When
	err := manager.Advance(context.Background(), PhaseReadSwitch)

	// Then
	if !errors.Is(err, ErrStorageBackpressure) {
		t.Fatalf("error=%v, want storage backpressure", err)
	}
}
