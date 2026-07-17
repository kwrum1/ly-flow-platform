package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const postgresEventColumns = `event_uid, version, event_timestamp, source_module, event_type, severity,
agent_id, host_id, chain_id, entity_id, raw_reference, message, payload_json`

func (migration *StorageMigration) writePostgres(ctx context.Context, event EventRecord, dualWrite bool) error {
	transaction, err := migration.postgres.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Postgres event write: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	command, err := transaction.Exec(ctx, `INSERT INTO lyflow_event_storage_events (`+postgresEventColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (event_uid) DO UPDATE SET version=EXCLUDED.version, event_timestamp=EXCLUDED.event_timestamp,
source_module=EXCLUDED.source_module, event_type=EXCLUDED.event_type, severity=EXCLUDED.severity,
agent_id=EXCLUDED.agent_id, host_id=EXCLUDED.host_id, chain_id=EXCLUDED.chain_id,
entity_id=EXCLUDED.entity_id, raw_reference=EXCLUDED.raw_reference, message=EXCLUDED.message,
payload_json=EXCLUDED.payload_json WHERE EXCLUDED.version > lyflow_event_storage_events.version`,
		event.ID, event.Version, event.Timestamp.UTC(), event.SourceModule, event.EventType, event.Severity,
		event.AgentID, event.HostID, event.ChainID, event.EntityID, event.RawReference, event.Message, event.PayloadJSON)
	if err != nil {
		return fmt.Errorf("upsert Postgres event %s: %w", event.ID, err)
	}
	changed := command.RowsAffected() > 0
	if dualWrite && changed {
		if _, err := transaction.Exec(ctx, `INSERT INTO lyflow_event_storage_outbox(event_uid, version) VALUES ($1, $2)
	ON CONFLICT (event_uid) DO UPDATE SET version=EXCLUDED.version, queued_at=NOW()
	WHERE EXCLUDED.version > lyflow_event_storage_outbox.version`, event.ID, event.Version); err != nil {
			return fmt.Errorf("queue ClickHouse event %s: %w", event.ID, err)
		}
	}
	if _, err := transaction.Exec(ctx, `UPDATE lyflow_event_storage_control SET write_attempts=write_attempts+1,
	write_revision=write_revision+$1 WHERE singleton=TRUE`, boolCount(changed)); err != nil {
		return fmt.Errorf("record event write metric: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit Postgres event %s: %w", event.ID, err)
	}
	return nil
}

func (migration *StorageMigration) postgresEvents(ctx context.Context, afterUID string, limit int) ([]EventRecord, error) {
	query := `SELECT ` + postgresEventColumns + ` FROM lyflow_event_storage_events`
	arguments := make([]any, 0, 2)
	if afterUID != "" {
		query += ` WHERE event_uid > $1`
		arguments = append(arguments, afterUID)
	}
	query += ` ORDER BY event_uid`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := migration.postgres.Query(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("query Postgres events: %w", err)
	}
	defer rows.Close()
	events := make([]EventRecord, 0)
	for rows.Next() {
		event, err := scanPostgresEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Postgres events: %w", err)
	}
	return events, nil
}

type eventScanner interface {
	Scan(dest ...any) error
}

func scanPostgresEvent(scanner eventScanner) (EventRecord, error) {
	var event EventRecord
	if err := scanner.Scan(
		&event.ID, &event.Version, &event.Timestamp, &event.SourceModule, &event.EventType, &event.Severity,
		&event.AgentID, &event.HostID, &event.ChainID, &event.EntityID, &event.RawReference, &event.Message, &event.PayloadJSON,
	); err != nil {
		return EventRecord{}, fmt.Errorf("scan Postgres event: %w", err)
	}
	return event, nil
}

func (migration *StorageMigration) pendingEvents(ctx context.Context, limit int) ([]EventRecord, error) {
	rows, err := migration.postgres.Query(ctx, `SELECT e.`+postgresEventColumnsWithPrefix("e.")+`
FROM lyflow_event_storage_outbox o JOIN lyflow_event_storage_events e ON e.event_uid=o.event_uid
WHERE e.version=o.version ORDER BY o.queued_at, o.event_uid LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending ClickHouse events: %w", err)
	}
	defer rows.Close()
	events := make([]EventRecord, 0, limit)
	for rows.Next() {
		event, err := scanPostgresEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending ClickHouse events: %w", err)
	}
	return events, nil
}

func postgresEventColumnsWithPrefix(prefix string) string {
	return "event_uid, " + prefix + "version, " + prefix + "event_timestamp, " + prefix + "source_module, " +
		prefix + "event_type, " + prefix + "severity, " + prefix + "agent_id, " + prefix + "host_id, " +
		prefix + "chain_id, " + prefix + "entity_id, " + prefix + "raw_reference, " + prefix + "message, " + prefix + "payload_json"
}

func (migration *StorageMigration) loadControl(ctx context.Context, lock bool) (MigrationStatus, error) {
	query := `SELECT phase, revision, owner, checkpoint_uid, backup_checkpoint_uid, rollback_until,
	legacy_retired, retention_claims_enabled, degraded, last_error, write_attempts, backpressure_events,
	reconciliations, consistency_failures, write_revision, reconcile_write_revision,
	reconcile_checkpoint_uid, last_reconcile_match FROM lyflow_event_storage_control WHERE singleton=TRUE`
	if lock {
		query += ` FOR UPDATE`
	}
	row := migration.postgres.QueryRow(ctx, query)
	var status MigrationStatus
	var rollbackUntil *time.Time
	if err := row.Scan(&status.Phase, &status.Revision, &status.Owner, &status.CheckpointUID,
		&status.BackupCheckpointUID, &rollbackUntil, &status.LegacyRetired, &status.RetentionClaimsEnabled,
		&status.Degraded, &status.LastError, &status.Metrics.WriteAttempts, &status.Metrics.BackpressureEvents,
		&status.Metrics.Reconciliations, &status.Metrics.ConsistencyFailures, &status.WriteRevision,
		&status.ReconcileWriteRevision, &status.ReconcileCheckpointUID, &status.LastReconcileMatch); err != nil {
		if err == pgx.ErrNoRows {
			return MigrationStatus{}, fmt.Errorf("migration control is not initialized: %w", err)
		}
		return MigrationStatus{}, fmt.Errorf("load migration control: %w", err)
	}
	if rollbackUntil != nil {
		status.RollbackUntil = rollbackUntil.UTC()
	}
	return status, nil
}
