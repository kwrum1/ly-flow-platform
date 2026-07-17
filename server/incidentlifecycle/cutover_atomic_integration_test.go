package incidentlifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresStore_checkpoint_persists_checksum_timestamp_and_loss_counts_without_cutover(t *testing.T) {
	// Given
	store, pool, ctx, _ := newTestStore(t)
	statuses := []LegacyStatus{{IncidentID: "inc-hyp-1", Status: StatusProcessing}}

	// When
	report, err := store.CheckpointLegacySnapshot(ctx, statuses, "live legacy writer")

	// Then
	if err != nil {
		t.Fatalf("checkpoint legacy snapshot: %v", err)
	}
	if report.SnapshotChecksum == "" || report.SnapshotCapturedAt.IsZero() {
		t.Fatalf("checkpoint metadata=%+v", report)
	}
	if !reflect.DeepEqual(report.ImportableFields, []string{"status"}) {
		t.Fatalf("importable fields=%v", report.ImportableFields)
	}
	if report.Captured != 1 || report.Unrecoverable.Assignee != 1 || report.Unrecoverable.Suppression != 1 || report.Unrecoverable.TransitionHistory != 1 || report.CutoverMarked {
		t.Fatalf("checkpoint loss report=%+v", report)
	}
	var snapshots, cutovers int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_legacy_snapshots`).Scan(&snapshots); err != nil {
		t.Fatalf("count durable snapshots: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_cutover_audit`).Scan(&cutovers); err != nil {
		t.Fatalf("count cutovers: %v", err)
	}
	if snapshots != 1 || cutovers != 0 {
		t.Fatalf("checkpoint rows snapshots=%d cutovers=%d", snapshots, cutovers)
	}
}

func TestPostgresStore_cutover_interruption_rolls_back_import_audit_and_marker_then_retry_preserves_original_counts(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}
	if _, err := store.CheckpointLegacySnapshot(ctx, []LegacyStatus{{IncidentID: "inc-hyp-1", Status: StatusProcessing}}, "live legacy writer"); err != nil {
		t.Fatalf("checkpoint legacy snapshot: %v", err)
	}
	store.cutoverInterrupt = func(stage cutoverStage) error {
		if stage == cutoverAfterAudit {
			return errors.New("injected transaction interruption")
		}
		return nil
	}

	// When
	_, interruptedErr := store.ImportLegacyCutover(ctx)

	// Then
	if interruptedErr == nil {
		t.Fatal("interrupted cutover unexpectedly succeeded")
	}
	database := legacyCutoverTestDatabase{pool: pool, ctx: ctx}
	database.assertState(t, legacyCutoverExpectedState{status: StatusOpen, version: 1})

	store.cutoverInterrupt = nil
	first, err := store.ImportLegacyCutover(ctx)
	if err != nil {
		t.Fatalf("retry cutover: %v", err)
	}
	second, err := store.ImportLegacyCutover(ctx)
	if err != nil {
		t.Fatalf("idempotent cutover retry: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("retry changed original report first=%+v second=%+v", first, second)
	}
	if first.Imported != 1 || first.AlreadyPersisted != 0 || !first.CutoverMarked {
		t.Fatalf("original cutover counts=%+v", first)
	}
	database.assertState(t, legacyCutoverExpectedState{status: StatusProcessing, version: 2, audits: 1, cutovers: 1})
}

func TestPostgresStore_cutover_interruption_after_marker_rolls_back_entire_transaction(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}
	if _, err := store.CheckpointLegacySnapshot(ctx, []LegacyStatus{{IncidentID: "inc-hyp-1", Status: StatusProcessing}}, "live legacy writer"); err != nil {
		t.Fatalf("checkpoint legacy snapshot: %v", err)
	}
	store.cutoverInterrupt = func(stage cutoverStage) error {
		if stage == cutoverAfterMarker {
			return errors.New("injected interruption after marker")
		}
		return nil
	}

	// When
	_, err := store.ImportLegacyCutover(ctx)

	// Then
	if err == nil {
		t.Fatal("post-marker interruption unexpectedly committed")
	}
	database := legacyCutoverTestDatabase{pool: pool, ctx: ctx}
	database.assertState(t, legacyCutoverExpectedState{status: StatusOpen, version: 1})
}

func TestPostgresStore_cutover_rejects_tampered_unrecoverable_counts_without_marker(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}
	if _, err := store.CheckpointLegacySnapshot(ctx, []LegacyStatus{{IncidentID: "inc-hyp-1", Status: StatusProcessing}}, "live legacy writer"); err != nil {
		t.Fatalf("checkpoint legacy snapshot: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE incident_lifecycle_legacy_snapshots SET payload=jsonb_set(payload,'{unrecoverable,transition_history}','99')`); err != nil {
		t.Fatalf("tamper legacy snapshot counts: %v", err)
	}

	// When
	_, err := store.ImportLegacyCutover(ctx)

	// Then
	if !errors.Is(err, ErrLegacySnapshotInvalid) {
		t.Fatalf("tampered snapshot error=%v", err)
	}
	database := legacyCutoverTestDatabase{pool: pool, ctx: ctx}
	database.assertState(t, legacyCutoverExpectedState{status: StatusOpen, version: 1})
}

type legacyCutoverTestDatabase struct {
	pool *pgxpool.Pool
	ctx  context.Context
}

type legacyCutoverExpectedState struct {
	status   Status
	version  int64
	audits   int
	cutovers int
}

func (database legacyCutoverTestDatabase) assertState(t *testing.T, expected legacyCutoverExpectedState) {
	t.Helper()
	var gotStatus Status
	var gotVersion int64
	if err := database.pool.QueryRow(database.ctx, `SELECT status,version FROM incidents WHERE id='inc-hyp-1'`).Scan(&gotStatus, &gotVersion); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	var gotAudits, gotCutovers int
	if err := database.pool.QueryRow(database.ctx, `SELECT COUNT(*) FROM incident_lifecycle_audit WHERE action=$1`, ActionSnapshot).Scan(&gotAudits); err != nil {
		t.Fatalf("count snapshot audits: %v", err)
	}
	if err := database.pool.QueryRow(database.ctx, `SELECT COUNT(*) FROM incident_lifecycle_cutover_audit`).Scan(&gotCutovers); err != nil {
		t.Fatalf("count cutovers: %v", err)
	}
	if gotStatus != expected.status || gotVersion != expected.version || gotAudits != expected.audits || gotCutovers != expected.cutovers {
		t.Fatalf("database state status=%s version=%d audits=%d cutovers=%d", gotStatus, gotVersion, gotAudits, gotCutovers)
	}
}
