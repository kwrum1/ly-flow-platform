package incidentlifecycle

import (
	"reflect"
	"sync"
	"testing"
)

func TestPostgresStore_legacy_cutover_is_concurrently_idempotent(t *testing.T) {
	// Given
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("sync incident: %v", err)
	}
	if _, err := store.CheckpointLegacySnapshot(ctx, []LegacyStatus{{IncidentID: "inc-hyp-1", Status: StatusProcessing}}, "concurrent fixture"); err != nil {
		t.Fatalf("checkpoint legacy snapshot: %v", err)
	}
	results := make([]SnapshotReport, 2)
	errors := make([]error, len(results))
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(len(results))
	for index := range results {
		go func() {
			defer wait.Done()
			<-start
			results[index], errors[index] = store.ImportLegacyCutover(ctx)
		}()
	}

	// When
	close(start)
	wait.Wait()

	// Then
	for index, err := range errors {
		if err != nil {
			t.Fatalf("complete concurrent cutover %d: %v", index, err)
		}
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Fatalf("concurrent cutover reports differ: first=%+v second=%+v", results[0], results[1])
	}
	if results[0].Imported != 1 || results[0].AlreadyPersisted != 0 {
		t.Fatalf("concurrent cutover changed original counts: %+v", results[0])
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_cutover_audit WHERE name=$1`, LegacyCutoverName).Scan(&count); err != nil {
		t.Fatalf("count cutover audit: %v", err)
	}
	if count != 1 {
		t.Fatalf("cutover audit rows=%d, want 1", count)
	}
}
