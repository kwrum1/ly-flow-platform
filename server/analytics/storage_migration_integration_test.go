package analytics

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEventStorageMigration_real_stores_backfill_reconcile_switch_and_rollback(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	for _, event := range []EventRecord{testStorageEvent("event-a", 1), testStorageEvent("event-b", 1)} {
		if err := manager.Write(ctx, event); err != nil {
			t.Fatalf("seed legacy event: %v", err)
		}
	}
	if err := manager.Advance(ctx, PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	if err := manager.Write(ctx, testStorageEvent("event-c", 1)); err != nil {
		t.Fatalf("dual write: %v", err)
	}
	if err := manager.Write(ctx, testStorageEvent("event-c", 1)); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}

	// When
	if _, err := manager.Backfill(ctx, 100); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if err := manager.Advance(ctx, PhaseReconcile); err != nil {
		t.Fatalf("advance reconcile: %v", err)
	}
	report, err := manager.Reconcile(ctx)
	if err != nil {
		t.Fatalf("reconcile=%+v err=%v", report, err)
	}
	dualResult, err := manager.Search(ctx, 100)
	if err != nil {
		t.Fatalf("dual read: %v", err)
	}
	if err := manager.Advance(ctx, PhaseReadSwitch); err != nil {
		t.Fatalf("advance read-switch: %v", err)
	}
	canonicalResult, err := manager.Search(ctx, 100)
	if err != nil {
		t.Fatalf("canonical search: %v", err)
	}
	if err := manager.Rollback(ctx); err != nil {
		t.Fatalf("nondestructive rollback: %v", err)
	}
	rolledBack, err := manager.Search(ctx, 100)
	if err != nil {
		t.Fatalf("rolled-back dual read: %v", err)
	}

	// Then
	if !report.Match || report.PostgresCount != 3 || report.ClickHouseCount != 3 || report.PostgresChecksum != report.ClickHouseChecksum {
		t.Fatalf("reconciliation report=%+v", report)
	}
	if dualResult.Authority != ReadReconciled || canonicalResult.Authority != ReadClickHouse || rolledBack.Authority != ReadReconciled {
		t.Fatalf("authorities dual=%s canonical=%s rollback=%s", dualResult.Authority, canonicalResult.Authority, rolledBack.Authority)
	}
	if len(canonicalResult.Events) != 3 || canonicalResult.Checksum != report.PostgresChecksum {
		t.Fatalf("canonical result=%+v report=%+v", canonicalResult, report)
	}
	status, err := manager.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.CheckpointUID == "" || status.BackupCheckpointUID == "" || status.Owner != "todo10-test" || status.RetentionClaimsEnabled {
		t.Fatalf("control metadata=%+v", status)
	}
}

func TestEventStorageMigration_clickhouse_outage_is_explicit_and_retryable(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	if err := manager.Advance(ctx, PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	unavailable, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: "http://127.0.0.1:1", Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("create unavailable client: %v", err)
	}
	degraded := manager.WithClickHouse(unavailable)

	// When
	writeErr := degraded.Write(ctx, testStorageEvent("outage", 1))
	status, statusErr := degraded.Status(ctx)

	// Then
	if statusErr != nil {
		t.Fatalf("status: %v", statusErr)
	}
	if !errors.Is(writeErr, ErrStorageBackpressure) || !status.Degraded || status.PendingWrites != 1 || status.Metrics.BackpressureEvents == 0 {
		t.Fatalf("writeErr=%v status=%+v", writeErr, status)
	}
	if _, err := manager.Backfill(ctx, 100); err != nil {
		t.Fatalf("retry pending write after recovery: %v", err)
	}
	recovered, err := manager.Status(ctx)
	if err != nil || recovered.PendingWrites != 0 || recovered.Degraded {
		t.Fatalf("recovered status=%+v err=%v", recovered, err)
	}
}

func TestEventStorageMigration_retirement_window_keeps_rollback_and_disables_expiry(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	if err := manager.Write(ctx, testStorageEvent("retained", 1)); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	for _, phase := range []StoragePhase{PhaseDualWrite, PhaseReconcile} {
		if phase == PhaseReconcile {
			if _, err := manager.Backfill(ctx, 100); err != nil {
				t.Fatalf("backfill: %v", err)
			}
		}
		if err := manager.Advance(ctx, phase); err != nil {
			t.Fatalf("advance %s: %v", phase, err)
		}
	}
	if _, err := manager.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, phase := range []StoragePhase{PhaseReadSwitch, PhaseObserve, PhaseRetireLegacy} {
		if err := manager.Advance(ctx, phase); err != nil {
			t.Fatalf("advance %s: %v", phase, err)
		}
	}

	// When
	expireErr := manager.ExpireLegacy(ctx, time.Now().UTC())
	rollbackErr := manager.Rollback(ctx)
	result, searchErr := manager.Search(ctx, 10)

	// Then
	if !errors.Is(expireErr, ErrRetentionUnmeasured) || rollbackErr != nil || searchErr != nil {
		t.Fatalf("expire=%v rollback=%v search=%v", expireErr, rollbackErr, searchErr)
	}
	if result.Authority != ReadReconciled || len(result.Events) != 1 {
		t.Fatalf("rollback result=%+v", result)
	}
}

func realStorageMigration(t *testing.T) (*StorageMigration, context.Context) {
	t.Helper()
	clickHouseEndpoint := os.Getenv("LYFLOW_TEST_CLICKHOUSE_HTTP")
	postgresDSN := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if clickHouseEndpoint == "" || postgresDSN == "" {
		t.Skip("LYFLOW_TEST_CLICKHOUSE_HTTP and LYFLOW_TEST_POSTGRES_DSN are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, postgresDSN)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	client, err := NewHTTPClickHouse(HTTPClickHouseConfig{
		Endpoint: clickHouseEndpoint,
		Username: os.Getenv("LYFLOW_TEST_CLICKHOUSE_USER"),
		Password: os.Getenv("LYFLOW_TEST_CLICKHOUSE_PASSWORD"),
	})
	if err != nil {
		t.Fatalf("create ClickHouse client: %v", err)
	}
	manager, err := NewStorageMigration(StorageMigrationConfig{
		Postgres: pool, ClickHouse: client, Owner: "todo10-test", RollbackWindow: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("create migration manager: %v", err)
	}
	if err := resetStorageMigrationTestSchema(ctx, manager); err != nil {
		t.Fatalf("reset isolated schema: %v", err)
	}
	if err := manager.Migrate(ctx); err != nil {
		t.Fatalf("apply versioned migrations: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_ = resetStorageMigrationTestSchema(cleanupCtx, manager)
	})
	return manager, ctx
}

func resetStorageMigrationTestSchema(ctx context.Context, manager *StorageMigration) error {
	for _, query := range []string{
		"DROP TABLE IF EXISTS lyflow_security_events_versioned_transition",
		"DROP TABLE IF EXISTS lyflow_security_events_pre_versioned",
		"DROP TABLE IF EXISTS lyflow_security_events",
		"DROP TABLE IF EXISTS lyflow_event_storage_migrations",
	} {
		if _, err := manager.clickhouse.execute(ctx, query); err != nil {
			return err
		}
	}
	_, err := manager.postgres.Exec(ctx, `DROP TABLE IF EXISTS lyflow_event_storage_outbox;
DROP TABLE IF EXISTS lyflow_event_storage_control;
DROP TABLE IF EXISTS lyflow_event_storage_events;
DROP TABLE IF EXISTS lyflow_event_storage_migrations`)
	return err
}
