package incidentlifecycle

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPostgresStore_restart_preserves_lifecycle_suppression_dedup_and_lineage(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	snapshot := activeSnapshot(t, now)
	if _, err := store.SyncActive(ctx, snapshot); err != nil {
		t.Fatalf("sync active incident: %v", err)
	}
	incident, err := store.Get(ctx, "inc-hyp-1")
	if err != nil {
		t.Fatalf("get created incident: %v", err)
	}
	commands := []Command{
		{IncidentID: incident.ID, IdempotencyKey: "assign-1", Actor: analystActor(), Action: ActionAssign, Assignee: "analyst-7", ExpectedVersion: incident.Version},
		{IncidentID: incident.ID, IdempotencyKey: "triage-1", Actor: analystActor(), Action: ActionTransition, To: StatusTriaged, ExpectedVersion: incident.Version + 1},
		{IncidentID: incident.ID, IdempotencyKey: "process-1", Actor: analystActor(), Action: ActionTransition, To: StatusProcessing, ExpectedVersion: incident.Version + 2},
		{IncidentID: incident.ID, IdempotencyKey: "suppress-1", Actor: analystActor(), Action: ActionSuppress, SuppressUntil: now.Add(time.Hour), Reason: "maintenance", ExpectedVersion: incident.Version + 3},
		{IncidentID: incident.ID, IdempotencyKey: "resolve-1", Actor: analystActor(), Action: ActionTransition, To: StatusResolved, ExpectedVersion: incident.Version + 4},
	}
	for _, command := range commands {
		if _, err := store.Apply(ctx, command); err != nil {
			t.Fatalf("apply %s: %v", command.IdempotencyKey, err)
		}
	}

	// When
	restarted := NewPostgresStore(pool, func() time.Time { return now.Add(30 * time.Minute) })
	got, err := restarted.Get(ctx, incident.ID)

	// Then
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	if got.Status != StatusResolved || got.Assignee != "analyst-7" || !got.Suppressed || got.ResolvedAt == nil {
		t.Fatalf("restarted incident=%+v", got)
	}
	if len(got.Evidence) != 2 || got.DedupKey != DedupKey("default", snapshot.Candidates()[0]) {
		t.Fatalf("lineage or dedup lost: %+v", got)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_audit WHERE incident_id=$1 AND outcome='applied'`, incident.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount != 6 {
		t.Fatalf("applied audit count=%d, want 6", auditCount)
	}
}

func TestPostgresStore_concurrent_idempotency_records_one_transition(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}
	command := Command{IncidentID: "inc-hyp-1", IdempotencyKey: "same-request", Actor: analystActor(), Action: ActionTransition, To: StatusTriaged, ExpectedVersion: 1}
	const workers = 12
	start := make(chan struct{})
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			<-start
			_, err := store.Apply(ctx, command)
			errorsByWorker <- err
		}()
	}

	// When
	close(start)
	wait.Wait()
	close(errorsByWorker)

	// Then
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("idempotent apply: %v", err)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_audit WHERE incident_id='inc-hyp-1' AND idempotency_key='same-request'`).Scan(&count); err != nil {
		t.Fatalf("count idempotent audit: %v", err)
	}
	if count != 1 {
		t.Fatalf("idempotent audit rows=%d, want 1", count)
	}
}

func TestPostgresStore_same_idempotency_key_with_different_payload_returns_conflict(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}
	first := Command{IncidentID: "inc-hyp-1", IdempotencyKey: "payload-bound", Actor: analystActor(), Action: ActionTransition, To: StatusTriaged, Reason: "first review", ExpectedVersion: 1}
	if _, err := store.Apply(ctx, first); err != nil {
		t.Fatalf("apply first payload: %v", err)
	}
	changed := first
	changed.Reason = "different review"

	// When
	_, err := store.Apply(ctx, changed)

	// Then
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("different payload error=%v, want conflict", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_audit WHERE idempotency_key='payload-bound'`).Scan(&count); err != nil {
		t.Fatalf("count payload-bound audit: %v", err)
	}
	if count != 1 {
		t.Fatalf("payload-bound audit rows=%d, want 1", count)
	}
}

func TestPostgresStore_concurrent_conflict_preserves_winner_and_rejected_audit(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}
	commands := []Command{
		{IncidentID: "inc-hyp-1", IdempotencyKey: "winner-a", Actor: analystActor(), Action: ActionAssign, Assignee: "alice", ExpectedVersion: 1},
		{IncidentID: "inc-hyp-1", IdempotencyKey: "winner-b", Actor: analystActor(), Action: ActionAssign, Assignee: "bob", ExpectedVersion: 1},
	}
	start := make(chan struct{})
	results := make(chan error, len(commands))
	for _, command := range commands {
		go func(command Command) {
			<-start
			_, err := store.Apply(ctx, command)
			results <- err
		}(command)
	}

	// When
	close(start)
	firstErr, secondErr := <-results, <-results

	// Then
	conflicts := 0
	for _, err := range []error{firstErr, secondErr} {
		if errors.Is(err, ErrConflict) {
			conflicts++
		} else if err != nil {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if conflicts != 1 {
		t.Fatalf("conflicts=%d, errors=%v/%v", conflicts, firstErr, secondErr)
	}
	var applied, rejected int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FILTER (WHERE outcome='applied'), COUNT(*) FILTER (WHERE outcome='rejected') FROM incident_lifecycle_audit WHERE idempotency_key IN ('winner-a','winner-b')`).Scan(&applied, &rejected); err != nil {
		t.Fatalf("count conflict audits: %v", err)
	}
	if applied != 1 || rejected != 1 {
		t.Fatalf("conflict audit applied=%d rejected=%d", applied, rejected)
	}
}

func TestPostgresStore_suppression_expires_without_erasing_history(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}
	_, err := store.Apply(ctx, Command{IncidentID: "inc-hyp-1", IdempotencyKey: "suppress-expiry", Actor: analystActor(), Action: ActionSuppress, SuppressUntil: now.Add(time.Minute), Reason: "maintenance", ExpectedVersion: 1})
	if err != nil {
		t.Fatalf("suppress incident: %v", err)
	}

	// When
	expiredStore := NewPostgresStore(pool, func() time.Time { return now.Add(2 * time.Minute) })
	incident, err := expiredStore.Get(ctx, "inc-hyp-1")

	// Then
	if err != nil {
		t.Fatalf("get expired suppression: %v", err)
	}
	if incident.Suppressed {
		t.Fatal("expired suppression remains active")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_suppressions WHERE incident_id='inc-hyp-1'`).Scan(&count); err != nil {
		t.Fatalf("count suppression history: %v", err)
	}
	if count != 1 {
		t.Fatalf("suppression history rows=%d", count)
	}
}

func TestPostgresStore_RBAC_denial_is_audited_without_mutation(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}

	// When
	_, err := store.Apply(ctx, Command{IncidentID: "inc-hyp-1", IdempotencyKey: "viewer-denied", Actor: Actor{ID: "user:9", Role: RoleViewer}, Action: ActionTransition, To: StatusTriaged, ExpectedVersion: 1})

	// Then
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer error=%v", err)
	}
	incident, getErr := store.Get(ctx, "inc-hyp-1")
	if getErr != nil {
		t.Fatalf("get incident: %v", getErr)
	}
	if incident.Status != StatusOpen || incident.Version != 1 {
		t.Fatalf("viewer mutated incident=%+v", incident)
	}
	var outcome string
	if err := pool.QueryRow(ctx, `SELECT outcome FROM incident_lifecycle_audit WHERE idempotency_key='viewer-denied'`).Scan(&outcome); err != nil {
		t.Fatalf("read denial audit: %v", err)
	}
	if outcome != "rejected" {
		t.Fatalf("denial outcome=%q", outcome)
	}
}

func TestPostgresStore_illegal_transition_is_audited_without_lost_history(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}

	// When
	_, err := store.Apply(ctx, Command{IncidentID: "inc-hyp-1", IdempotencyKey: "illegal-resolve", Actor: analystActor(), Action: ActionTransition, To: StatusResolved, ExpectedVersion: 1})

	// Then
	if !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("illegal transition error=%v", err)
	}
	incident, getErr := store.Get(ctx, "inc-hyp-1")
	if getErr != nil {
		t.Fatalf("get incident: %v", getErr)
	}
	if incident.Status != StatusOpen || incident.Version != 1 || len(incident.Evidence) != 2 {
		t.Fatalf("illegal transition changed history=%+v", incident)
	}
	var outcome, fromStatus, toStatus string
	if err := pool.QueryRow(ctx, `SELECT outcome,from_status,to_status FROM incident_lifecycle_audit WHERE idempotency_key='illegal-resolve'`).Scan(&outcome, &fromStatus, &toStatus); err != nil {
		t.Fatalf("read illegal transition audit: %v", err)
	}
	if outcome != "rejected" || fromStatus != "open" || toStatus != "resolved" {
		t.Fatalf("illegal transition audit=%s %s->%s", outcome, fromStatus, toStatus)
	}
}

func TestPostgresStore_legacy_snapshot_reports_unrecoverable_history(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}

	if _, err := store.CheckpointLegacySnapshot(ctx, []LegacyStatus{{IncidentID: "inc-hyp-1", Status: StatusProcessing}, {IncidentID: "missing", Status: StatusTriaged}}, "legacy integration fixture"); err != nil {
		t.Fatalf("checkpoint legacy snapshot: %v", err)
	}

	// When
	report, err := store.ImportLegacyCutover(ctx)

	// Then
	if err != nil {
		t.Fatalf("import legacy snapshot: %v", err)
	}
	if report.Imported != 1 || len(report.Unmatched) != 1 || report.Unmatched[0] != "missing" || len(report.UnrecoverableHistory) != 2 {
		t.Fatalf("legacy snapshot report=%+v", report)
	}
	if report.Recovered.Status != 1 || report.Recovered.Evidence != 2 {
		t.Fatalf("legacy snapshot recovered fields=%+v", report.Recovered)
	}
	if report.Unrecoverable.Status != 1 || report.Unrecoverable.Assignee != 2 || report.Unrecoverable.Suppression != 2 || report.Unrecoverable.Evidence != 1 || report.Unrecoverable.TransitionHistory != 2 {
		t.Fatalf("legacy snapshot unrecoverable fields=%+v details=%v", report.Unrecoverable, report.UnrecoverableDetails)
	}
	var migrationName string
	if err := pool.QueryRow(ctx, `SELECT name FROM incident_lifecycle_schema_migrations WHERE version=19`).Scan(&migrationName); err != nil {
		t.Fatalf("read migration 19: %v", err)
	}
	if migrationName != "persist_incident_lifecycle" {
		t.Fatalf("migration name=%q", migrationName)
	}
}
