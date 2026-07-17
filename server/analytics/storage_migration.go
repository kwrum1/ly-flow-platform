package analytics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type StorageMigrationConfig struct {
	Postgres       *pgxpool.Pool
	ClickHouse     *HTTPClickHouse
	Owner          string
	RollbackWindow time.Duration
	Clock          func() time.Time
}

type StorageMigration struct {
	postgres       *pgxpool.Pool
	clickhouse     *HTTPClickHouse
	owner          string
	rollbackWindow time.Duration
	clock          func() time.Time
	retention      RetentionPolicy
}

func NewStorageMigration(config StorageMigrationConfig) (*StorageMigration, error) {
	if config.Postgres == nil || config.ClickHouse == nil || config.Owner == "" {
		return nil, fmt.Errorf("Postgres, ClickHouse, and migration owner are required")
	}
	if config.RollbackWindow <= 0 {
		return nil, fmt.Errorf("rollback window must be positive")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &StorageMigration{
		postgres: config.Postgres, clickhouse: config.ClickHouse, owner: config.Owner,
		rollbackWindow: config.RollbackWindow, clock: clock, retention: DefaultRetentionPolicy(),
	}, nil
}

func (migration *StorageMigration) WithClickHouse(client *HTTPClickHouse) *StorageMigration {
	copy := *migration
	copy.clickhouse = client
	return &copy
}

func (migration *StorageMigration) Write(ctx context.Context, event EventRecord) error {
	if event.ID == "" || event.Version == 0 || event.Timestamp.IsZero() {
		return fmt.Errorf("event UID, version, and timestamp are required")
	}
	status, err := migration.loadControl(ctx, false)
	if err != nil {
		return err
	}
	policy, err := PolicyForPhase(status.Phase)
	if err != nil {
		return err
	}
	dualWrite := policy.Write == WritePostgresAndClickHouse
	if err := migration.writePostgres(ctx, event, dualWrite); err != nil {
		return err
	}
	if !dualWrite {
		return nil
	}
	if err := migration.flushPending(ctx, 100); err != nil {
		return err
	}
	return nil
}

func (migration *StorageMigration) flushPending(ctx context.Context, limit int) error {
	events, err := migration.pendingEvents(ctx, limit)
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := migration.clickhouse.Insert(ctx, event); err != nil {
			recordErr := migration.recordBackpressure(ctx, err)
			return errors.Join(ErrStorageBackpressure, fmt.Errorf("flush event %s: %w", event.ID, err), recordErr)
		}
		if _, err := migration.postgres.Exec(ctx, `DELETE FROM lyflow_event_storage_outbox
		WHERE event_uid=$1 AND version=$2`, event.ID, event.Version); err != nil {
			return fmt.Errorf("complete ClickHouse event %s: %w", event.ID, err)
		}
	}
	if _, err := migration.postgres.Exec(ctx, `UPDATE lyflow_event_storage_control SET degraded=FALSE, last_error='' WHERE singleton=TRUE`); err != nil {
		return fmt.Errorf("clear ClickHouse degraded state: %w", err)
	}
	return nil
}

func (migration *StorageMigration) recordBackpressure(ctx context.Context, cause error) error {
	recordContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_, err := migration.postgres.Exec(recordContext, `UPDATE lyflow_event_storage_control SET degraded=TRUE, last_error=$1,
backpressure_events=backpressure_events+1 WHERE singleton=TRUE`, cause.Error())
	if err != nil {
		return fmt.Errorf("persist ClickHouse backpressure: %w", err)
	}
	return nil
}

func (migration *StorageMigration) Backfill(ctx context.Context, batchSize int) (string, error) {
	if batchSize <= 0 || batchSize > 1000 {
		return "", fmt.Errorf("backfill batch size must be between 1 and 1000")
	}
	if err := migration.flushPending(ctx, batchSize); err != nil {
		return "", err
	}
	status, err := migration.loadControl(ctx, false)
	if err != nil {
		return "", err
	}
	events, err := migration.postgresEvents(ctx, status.CheckpointUID, batchSize)
	if err != nil {
		return "", err
	}
	checkpoint := status.CheckpointUID
	for _, event := range events {
		if err := migration.clickhouse.Insert(ctx, event); err != nil {
			recordErr := migration.recordBackpressure(ctx, err)
			return checkpoint, errors.Join(ErrStorageBackpressure, fmt.Errorf("backfill event %s: %w", event.ID, err), recordErr)
		}
		checkpoint = event.ID
	}
	if _, err := migration.postgres.Exec(ctx, `UPDATE lyflow_event_storage_control SET checkpoint_uid=$1,
degraded=FALSE, last_error='' WHERE singleton=TRUE`, checkpoint); err != nil {
		return status.CheckpointUID, fmt.Errorf("persist backfill checkpoint: %w", err)
	}
	return checkpoint, nil
}

func (migration *StorageMigration) Reconcile(ctx context.Context) (ReconciliationReport, error) {
	if err := migration.flushPending(ctx, 1000); err != nil {
		return ReconciliationReport{}, err
	}
	start, err := migration.loadControl(ctx, false)
	if err != nil {
		return ReconciliationReport{}, err
	}
	postgresEvents, err := migration.postgresEvents(ctx, "", 0)
	if err != nil {
		return ReconciliationReport{}, err
	}
	clickHouseEvents, err := migration.clickhouse.QueryFinal(ctx, len(postgresEvents)+1000)
	if err != nil {
		recordErr := migration.recordBackpressure(ctx, err)
		return ReconciliationReport{}, errors.Join(err, recordErr)
	}
	report := reconciliationReport(postgresEvents, clickHouseEvents)
	transaction, err := migration.postgres.Begin(ctx)
	if err != nil {
		return ReconciliationReport{}, fmt.Errorf("begin reconciliation record: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var writeRevision uint64
	var checkpoint string
	var pending int64
	if err := transaction.QueryRow(ctx, `SELECT write_revision, checkpoint_uid,
	(SELECT COUNT(*) FROM lyflow_event_storage_outbox) FROM lyflow_event_storage_control
	WHERE singleton=TRUE FOR UPDATE`).Scan(&writeRevision, &checkpoint, &pending); err != nil {
		return ReconciliationReport{}, fmt.Errorf("lock reconciliation watermark: %w", err)
	}
	current := start.WriteRevision == writeRevision && start.CheckpointUID == checkpoint && pending == 0
	match := report.Match && current
	message := mismatchMessage(report)
	if report.Match && !current {
		message = "writes or checkpoint changed during reconciliation"
	}
	if _, err := transaction.Exec(ctx, `UPDATE lyflow_event_storage_control SET
	last_reconcile_match=$1, reconcile_write_revision=$2, reconcile_checkpoint_uid=$3,
	reconciliations=reconciliations+1, consistency_failures=consistency_failures+$4,
	degraded=$4::BIGINT>0, last_error=$5 WHERE singleton=TRUE`, match, writeRevision, checkpoint,
		boolCount(!match), message); err != nil {
		return ReconciliationReport{}, fmt.Errorf("persist reconciliation report: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return ReconciliationReport{}, fmt.Errorf("commit reconciliation report: %w", err)
	}
	if !match {
		return report, ErrConsistencyMismatch
	}
	return report, nil
}
