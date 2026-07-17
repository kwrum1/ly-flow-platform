package analytics

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func (migration *StorageMigration) Search(ctx context.Context, limit int) (SearchResult, error) {
	if limit <= 0 || limit > 1000 {
		return SearchResult{}, fmt.Errorf("search limit must be between 1 and 1000")
	}
	status, err := migration.loadControl(ctx, false)
	if err != nil {
		return SearchResult{}, err
	}
	policy, err := PolicyForPhase(status.Phase)
	if err != nil {
		return SearchResult{}, err
	}
	switch policy.Read {
	case ReadPostgres:
		events, err := migration.postgresEvents(ctx, "", 0)
		if err != nil {
			return SearchResult{}, err
		}
		events = newestEvents(events, limit)
		return SearchResult{Events: events, Authority: ReadPostgres, Checksum: checksumEvents(events)}, nil
	case ReadReconciled:
		report, err := migration.Reconcile(ctx)
		if err != nil {
			return SearchResult{}, err
		}
		events, err := migration.postgresEvents(ctx, "", 0)
		if err != nil {
			return SearchResult{}, err
		}
		events = newestEvents(events, limit)
		return SearchResult{Events: events, Authority: ReadReconciled, Checksum: report.PostgresChecksum}, nil
	case ReadClickHouse:
		events, err := migration.clickhouse.QueryFinal(ctx, limit)
		if err != nil {
			recordErr := migration.recordBackpressure(ctx, err)
			return SearchResult{}, errors.Join(ErrStorageBackpressure, err, recordErr)
		}
		return SearchResult{Events: events, Authority: ReadClickHouse, Checksum: checksumEvents(events)}, nil
	default:
		return SearchResult{}, fmt.Errorf("read authority %q: %w", policy.Read, ErrInvalidStoragePhase)
	}
}

func newestEvents(events []EventRecord, limit int) []EventRecord {
	copy := append([]EventRecord(nil), events...)
	sortEventsNewest(copy)
	if len(copy) > limit {
		copy = copy[:limit]
	}
	return copy
}

func sortEventsNewest(events []EventRecord) {
	for left := 1; left < len(events); left++ {
		for right := left; right > 0 && events[right].Timestamp.After(events[right-1].Timestamp); right-- {
			events[right], events[right-1] = events[right-1], events[right]
		}
	}
}

func (migration *StorageMigration) Advance(ctx context.Context, next StoragePhase) error {
	transaction, err := migration.postgres.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin phase advance: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	row := transaction.QueryRow(ctx, `SELECT phase, revision, owner, checkpoint_uid, last_reconcile_match,
	degraded, write_revision, reconcile_write_revision, reconcile_checkpoint_uid,
	(SELECT COUNT(*) FROM lyflow_event_storage_outbox)
FROM lyflow_event_storage_control WHERE singleton=TRUE FOR UPDATE`)
	var phase StoragePhase
	var revision uint64
	var owner, checkpoint string
	var reconciliationMatch bool
	var degraded bool
	var writeRevision, reconcileWriteRevision uint64
	var reconcileCheckpoint string
	var pending int64
	if err := row.Scan(&phase, &revision, &owner, &checkpoint, &reconciliationMatch, &degraded,
		&writeRevision, &reconcileWriteRevision, &reconcileCheckpoint, &pending); err != nil {
		return fmt.Errorf("lock migration control: %w", err)
	}
	if owner != migration.owner {
		return fmt.Errorf("migration owner %q does not match %q", migration.owner, owner)
	}
	if expectedStoragePhase(phase) != next {
		return fmt.Errorf("%s to %s: %w", phase, next, ErrInvalidTransition)
	}
	if next == PhaseReadSwitch {
		if degraded {
			return errors.Join(ErrStorageBackpressure, fmt.Errorf("read switch requires non-degraded storage health"))
		}
		if !reconciliationMatch || pending != 0 || reconcileWriteRevision != writeRevision || reconcileCheckpoint != checkpoint {
			return fmt.Errorf("read switch requires current reconciliation and zero pending writes: %w", ErrConsistencyMismatch)
		}
		if _, healthErr := migration.clickhouse.QueryFinal(ctx, 1); healthErr != nil {
			if _, err := transaction.Exec(ctx, `UPDATE lyflow_event_storage_control SET degraded=TRUE, last_error=$1 WHERE singleton=TRUE`, healthErr.Error()); err != nil {
				return errors.Join(healthErr, fmt.Errorf("persist read-switch health failure: %w", err))
			}
			if err := transaction.Commit(ctx); err != nil {
				return errors.Join(healthErr, fmt.Errorf("commit read-switch health failure: %w", err))
			}
			return errors.Join(ErrStorageBackpressure, healthErr)
		}
	}
	rollbackUntil := any(nil)
	backupCheckpoint := ""
	legacyRetired := false
	if next == PhaseReadSwitch {
		rollbackUntil = migration.clock().UTC().Add(migration.rollbackWindow)
		backupCheckpoint = checkpoint
	}
	if next == PhaseRetireLegacy {
		legacyRetired = true
	}
	_, err = transaction.Exec(ctx, `UPDATE lyflow_event_storage_control SET phase=$1, revision=$2,
backup_checkpoint_uid=CASE WHEN $3='' THEN backup_checkpoint_uid ELSE $3 END,
rollback_until=COALESCE($4, rollback_until), legacy_retired=legacy_retired OR $5 WHERE singleton=TRUE`,
		next, revision+1, backupCheckpoint, rollbackUntil, legacyRetired)
	if err != nil {
		return fmt.Errorf("persist phase %s: %w", next, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit phase %s: %w", next, err)
	}
	return nil
}

func expectedStoragePhase(phase StoragePhase) StoragePhase {
	switch phase {
	case PhaseLegacy:
		return PhaseDualWrite
	case PhaseDualWrite:
		return PhaseReconcile
	case PhaseReconcile:
		return PhaseReadSwitch
	case PhaseReadSwitch:
		return PhaseObserve
	case PhaseObserve:
		return PhaseRetireLegacy
	case PhaseRetireLegacy:
		return ""
	default:
		return ""
	}
}

func (migration *StorageMigration) Rollback(ctx context.Context) error {
	status, err := migration.loadControl(ctx, false)
	if err != nil {
		return err
	}
	if status.Owner != migration.owner {
		return fmt.Errorf("migration owner %q does not match %q", migration.owner, status.Owner)
	}
	previous, err := rollbackStoragePhase(status.Phase)
	if err != nil {
		return err
	}
	if status.Phase == PhaseRetireLegacy && (status.RollbackUntil.IsZero() || migration.clock().UTC().After(status.RollbackUntil)) {
		return fmt.Errorf("rollback window ended at %s: %w", status.RollbackUntil, ErrInvalidTransition)
	}
	_, err = migration.postgres.Exec(ctx, `UPDATE lyflow_event_storage_control SET phase=$1, revision=revision+1,
checkpoint_uid=CASE WHEN backup_checkpoint_uid='' THEN checkpoint_uid ELSE backup_checkpoint_uid END,
legacy_retired=FALSE, degraded=FALSE, last_error='' WHERE singleton=TRUE AND owner=$2`, previous, migration.owner)
	if err != nil {
		return fmt.Errorf("rollback to %s: %w", previous, err)
	}
	return nil
}

func rollbackStoragePhase(phase StoragePhase) (StoragePhase, error) {
	switch phase {
	case PhaseDualWrite:
		return PhaseLegacy, nil
	case PhaseReconcile:
		return PhaseDualWrite, nil
	case PhaseReadSwitch, PhaseObserve, PhaseRetireLegacy:
		return PhaseReconcile, nil
	case PhaseLegacy:
		return "", fmt.Errorf("from %s: %w", phase, ErrInvalidTransition)
	default:
		return "", fmt.Errorf("from %s: %w", phase, ErrInvalidStoragePhase)
	}
}

func (migration *StorageMigration) Status(ctx context.Context) (MigrationStatus, error) {
	status, err := migration.loadControl(ctx, false)
	if err != nil {
		return MigrationStatus{}, err
	}
	if err := migration.postgres.QueryRow(ctx, `SELECT COUNT(*) FROM lyflow_event_storage_outbox`).Scan(&status.PendingWrites); err != nil {
		return MigrationStatus{}, fmt.Errorf("count pending ClickHouse writes: %w", err)
	}
	return status, nil
}

func (migration *StorageMigration) ExpireLegacy(ctx context.Context, before time.Time) error {
	if err := migration.retention.AuthorizeExpiry(before); err != nil {
		return err
	}
	_, err := migration.postgres.Exec(ctx, `DELETE FROM lyflow_event_storage_events WHERE event_timestamp < $1`, before.UTC())
	if err != nil {
		return fmt.Errorf("expire legacy events: %w", err)
	}
	return nil
}

func (migration *StorageMigration) Delete(ctx context.Context, eventUID string) error {
	if eventUID == "" {
		return fmt.Errorf("event UID is required")
	}
	for _, character := range eventUID {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != ':' && character != '.' && character != '_' && character != '-' {
			return fmt.Errorf("event UID contains unsupported character %q", character)
		}
	}
	query := fmt.Sprintf("ALTER TABLE lyflow_security_events DELETE WHERE event_uid='%s' SETTINGS mutations_sync=2", eventUID)
	if _, err := migration.clickhouse.execute(ctx, query); err != nil {
		return fmt.Errorf("delete ClickHouse event %s: %w", eventUID, err)
	}
	if _, err := migration.postgres.Exec(ctx, `DELETE FROM lyflow_event_storage_events WHERE event_uid=$1`, eventUID); err != nil {
		return fmt.Errorf("delete Postgres event %s: %w", eventUID, err)
	}
	if _, err := migration.postgres.Exec(ctx, `UPDATE lyflow_event_storage_control SET
	write_revision=write_revision+1, last_reconcile_match=FALSE WHERE singleton=TRUE`); err != nil {
		return fmt.Errorf("record event deletion %s: %w", eventUID, err)
	}
	return nil
}
