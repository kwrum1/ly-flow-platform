package incidentlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const LegacyCutoverName = "todo19-legacy-incident-status"

type cutoverStage string

const (
	cutoverAfterAudit  cutoverStage = "after_audit"
	cutoverAfterMarker cutoverStage = "after_marker"
)

func (store *PostgresStore) LegacyCutover(ctx context.Context) (SnapshotReport, bool, error) {
	var encoded []byte
	err := store.pool.QueryRow(ctx, `SELECT report FROM incident_lifecycle_cutover_audit WHERE name=$1`, LegacyCutoverName).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return SnapshotReport{}, false, nil
	}
	if err != nil {
		return SnapshotReport{}, false, fmt.Errorf("read legacy incident cutover: %w", err)
	}
	report, err := decodeSnapshotReport(encoded)
	if err != nil {
		return SnapshotReport{}, false, err
	}
	return report, true, nil
}

func (store *PostgresStore) ImportLegacyCutover(ctx context.Context) (SnapshotReport, error) {
	if err := authorize(Actor{ID: "system:legacy-snapshot", Role: RoleSystem}, ActionSnapshot); err != nil {
		return SnapshotReport{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return SnapshotReport{}, fmt.Errorf("begin legacy incident cutover: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, LegacyCutoverName); err != nil {
		return SnapshotReport{}, fmt.Errorf("lock legacy incident cutover: %w", err)
	}
	var persisted []byte
	err = tx.QueryRow(ctx, `SELECT report FROM incident_lifecycle_cutover_audit WHERE name=$1`, LegacyCutoverName).Scan(&persisted)
	if err == nil {
		return decodeSnapshotReport(persisted)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return SnapshotReport{}, fmt.Errorf("read atomic legacy incident cutover: %w", err)
	}
	var payload []byte
	if err := tx.QueryRow(ctx, `SELECT payload FROM incident_lifecycle_legacy_snapshots WHERE name=$1 FOR UPDATE`, LegacyCutoverName).Scan(&payload); errors.Is(err, pgx.ErrNoRows) {
		return SnapshotReport{}, ErrLegacySnapshotRequired
	} else if err != nil {
		return SnapshotReport{}, fmt.Errorf("read durable legacy incident snapshot: %w", err)
	}
	var snapshot durableLegacySnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return SnapshotReport{}, fmt.Errorf("decode durable legacy incident snapshot: %w", err)
	}
	checksum, err := legacySnapshotChecksum(snapshot)
	if err != nil {
		return SnapshotReport{}, err
	}
	if snapshot.Checksum == "" || snapshot.Checksum != checksum {
		return SnapshotReport{}, fmt.Errorf("legacy incident snapshot checksum: %w", ErrLegacySnapshotInvalid)
	}
	report, err := store.importLegacySnapshotTx(ctx, tx, snapshot)
	if err != nil {
		return report, err
	}
	if err := store.interruptCutover(cutoverAfterAudit); err != nil {
		return report, err
	}
	report.CutoverMarked = true
	encoded, err := json.Marshal(report)
	if err != nil {
		return SnapshotReport{}, fmt.Errorf("encode legacy incident cutover: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO incident_lifecycle_cutover_audit
		(name,source,captured,imported,unrecoverable,report,completed_at)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)`, LegacyCutoverName, report.Source, report.Captured, report.Imported,
		report.Unrecoverable.Total(), encoded, store.now().UTC()); err != nil {
		return SnapshotReport{}, fmt.Errorf("persist legacy incident cutover audit: %w", err)
	}
	if err := store.interruptCutover(cutoverAfterMarker); err != nil {
		return report, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SnapshotReport{}, fmt.Errorf("commit legacy incident cutover: %w", err)
	}
	return report, nil
}

func (store *PostgresStore) interruptCutover(stage cutoverStage) error {
	if store.cutoverInterrupt == nil {
		return nil
	}
	if err := store.cutoverInterrupt(stage); err != nil {
		return fmt.Errorf("legacy incident cutover interrupted at %s: %w", stage, err)
	}
	return nil
}

func decodeSnapshotReport(encoded []byte) (SnapshotReport, error) {
	var report SnapshotReport
	if err := json.Unmarshal(encoded, &report); err != nil {
		return SnapshotReport{}, fmt.Errorf("decode legacy incident cutover audit: %w", err)
	}
	return report, nil
}
