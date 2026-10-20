package incidentlifecycle

import (
	"testing"
	"time"
)

func TestPostgresStore_rekeys_same_incident_id_without_primary_key_collision(t *testing.T) {
	store, pool, ctx, now := newTestStore(t)
	if _, err := store.SyncActive(ctx, activeSnapshot(t, now)); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	second, err := NewActiveSnapshot("v2-active", []Candidate{{
		IncidentID: "inc-hyp-1", SourceChainID: "hyp-2", CorrelationKey: "asset-1",
		Title: "asset-1 attack chain", Severity: "high",
		FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(time.Minute),
		Evidence: []Evidence{
			{EventUID: "event-1", Stage: "initial_access", ObservedAt: now.Add(-time.Hour), SourceNodeUID: "node-event-1"},
			{EventUID: "event-2", Stage: "execution", ObservedAt: now, SourceNodeUID: "node-event-2"},
		},
	}})
	if err != nil {
		t.Fatalf("build rekeyed snapshot: %v", err)
	}
	if _, err := store.SyncActive(ctx, second); err != nil {
		t.Fatalf("rekey same incident id: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE id='inc-hyp-1'`).Scan(&count); err != nil {
		t.Fatalf("count incidents: %v", err)
	}
	if count != 1 {
		t.Fatalf("incident count=%d, want 1", count)
	}
	incident, err := store.Get(ctx, "inc-hyp-1")
	if err != nil {
		t.Fatalf("get rekeyed incident: %v", err)
	}
	want := DedupKey("default", second.Candidates()[0])
	if incident.DedupKey != want {
		t.Fatalf("dedup key=%s, want %s", incident.DedupKey, want)
	}
}
