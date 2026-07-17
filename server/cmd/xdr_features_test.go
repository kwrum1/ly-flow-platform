package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestXDRShadowFeatureResult_is_versioned_and_has_no_writer_interfaces(t *testing.T) {
	// Given
	shadowType := reflect.TypeOf(shadowXDRResult{})

	// When / Then
	for name, writerInput := range map[string]reflect.Type{
		"incident":    reflect.TypeOf((*xdrIncidentInput)(nil)).Elem(),
		"suppression": reflect.TypeOf((*xdrSuppressionInput)(nil)).Elem(),
		"response":    reflect.TypeOf((*xdrResponseCandidateInput)(nil)).Elem(),
	} {
		if shadowType.Implements(writerInput) {
			t.Fatalf("v3 feature result implements forbidden %s writer", name)
		}
	}
	if models.FeatureVersionV1 == models.EvalVersionV2 {
		t.Fatalf("feature version aliases active evaluation version %q", models.EvalVersionV2)
	}
}

func TestXDRGraphRuntime_side_by_side_features_do_not_change_active_incidents(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	events := []contracts.CanonicalSecurityEvent{
		canonicalXDRTestEvent(t, "feature-1", now),
		canonicalXDRTestEvent(t, "feature-2", now.Add(time.Minute)),
	}
	active, err := runtime.RunActive(ctx, events, 20)
	if err != nil {
		t.Fatalf("run active: %v", err)
	}
	before := incidentsFromActiveXDR(active)
	for _, chain := range active.chains {
		if _, exists := chain.jsonRow()["scoring_input"]; exists {
			t.Fatal("v2-active output contains v3 scoring input")
		}
	}

	// When
	shadow, err := runtime.RunShadow(ctx, events)
	if err != nil {
		t.Fatalf("run shadow: %v", err)
	}
	after := incidentsFromActiveXDR(active)

	// Then
	if len(before) != len(after) {
		t.Fatalf("shadow changed active incidents: before=%d after=%d", len(before), len(after))
	}
	if shadow.scoringInput == nil || shadow.scoringInput.AlgorithmVersion != "v3-shadow" {
		t.Fatalf("shadow scoring input=%+v", shadow.scoringInput)
	}
	if len(shadow.chains) > 0 && shadow.chains[0].ScoringInput == nil {
		t.Fatal("shadow output omitted explainable scoring input")
	}
}

func TestXDRGraphRuntime_duplicate_single_source_stale_shadow_has_no_promotion_surface(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	stale := canonicalXDRTestEvent(t, "stale-source", now.Add(-96*time.Hour))
	stale.Provenance.Source = contracts.SourceWazuh
	stale.Timestamps.IngestedAt = now
	duplicate := stale
	duplicate.EventUID = "stale-source-duplicate"
	duplicate.CorrelationID = duplicate.EventUID

	// When
	shadow, err := runtime.RunShadow(ctx, []contracts.CanonicalSecurityEvent{stale, duplicate})
	if err != nil {
		t.Fatalf("run shadow: %v", err)
	}

	// Then
	if shadow.scoringInput == nil || shadow.scoringInput.Duplicates.DuplicateRecordCount != 1 || !shadow.scoringInput.Provenance.SingleSource {
		t.Fatalf("shadow quality features=%+v", shadow.scoringInput)
	}
	if shadow.scoringInput.Staleness.MaxObservationAgeSeconds < int64((95*time.Hour)/time.Second) {
		t.Fatalf("stale input age=%d", shadow.scoringInput.Staleness.MaxObservationAgeSeconds)
	}
	for _, chain := range shadow.chains {
		if len(chain.ResponseCandidates) != 0 {
			t.Fatalf("shadow promoted response candidates=%v", chain.ResponseCandidates)
		}
	}
	if reflect.TypeOf(shadow).Implements(reflect.TypeOf((*xdrIncidentInput)(nil)).Elem()) {
		t.Fatal("shadow duplicate/stale output became incident-writable")
	}
}

func TestXDRFeaturePersistence_restart_checksum_is_deterministic_and_records_are_immutable(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := []contracts.CanonicalSecurityEvent{
		canonicalXDRTestEvent(t, "persist-feature-1", now),
		canonicalXDRTestEvent(t, "persist-feature-2", now.Add(time.Minute)),
	}
	runtime, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(time.Now, now.Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	first, err := runtime.RunShadow(ctx, events)
	if err != nil {
		t.Fatalf("first shadow replay: %v", err)
	}
	restarted, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(time.Now, now.Add(24*time.Hour)))
	if err != nil {
		t.Fatalf("restart runtime: %v", err)
	}

	// When
	second, err := restarted.RunShadow(ctx, []contracts.CanonicalSecurityEvent{events[1], events[0]})
	if err != nil {
		t.Fatalf("second shadow replay: %v", err)
	}
	_, mutationErr := pool.Exec(ctx, `UPDATE xdr_scoring_input_details_versioned SET feature_version='tampered' WHERE detail_uid=$1`, first.scoringInput.DetailUID)

	// Then
	if first.scoringInput.DetailChecksum != second.scoringInput.DetailChecksum {
		t.Fatalf("restart checksum changed: %s != %s", first.scoringInput.DetailChecksum, second.scoringInput.DetailChecksum)
	}
	if mutationErr == nil {
		t.Fatal("immutable scoring detail accepted update")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM xdr_scoring_input_details_versioned WHERE algorithm_version='v3-shadow' AND detail_uid=$1`, first.scoringInput.DetailUID).Scan(&count); err != nil {
		t.Fatalf("count scoring details: %v", err)
	}
	if count != 1 {
		t.Fatalf("persisted detail count=%d", count)
	}
	third := canonicalXDRTestEvent(t, "persist-feature-3", now.Add(2*time.Minute))
	if _, err := restarted.RunShadow(ctx, append(events, third)); err != nil {
		t.Fatalf("append shadow detail version: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM xdr_scoring_input_details_versioned WHERE algorithm_version='v3-shadow'`).Scan(&count); err != nil {
		t.Fatalf("count versioned scoring details: %v", err)
	}
	if count != 2 {
		t.Fatalf("append-only detail count=%d", count)
	}
	if first.checksum != second.checksum {
		t.Fatalf("graph checksum changed: %s != %s", first.checksum, second.checksum)
	}
}
