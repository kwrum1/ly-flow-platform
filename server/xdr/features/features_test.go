package features

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestCompute_normalizes_entity_aliases_and_is_order_independent(t *testing.T) {
	// Given
	events, graph := featureFixture()
	reversedEvents := []contracts.CanonicalSecurityEvent{events[2], events[1], events[0]}
	reversedGraph := []*models.CanonicalEventV2{graph[2], graph[1], graph[0]}

	// When
	first, err := Compute(Input{Events: events, GraphEvents: graph, InputChecksum: "fixture-input"})
	if err != nil {
		t.Fatalf("compute features: %v", err)
	}
	second, err := Compute(Input{Events: reversedEvents, GraphEvents: reversedGraph, InputChecksum: "fixture-input"})
	if err != nil {
		t.Fatalf("compute reversed features: %v", err)
	}

	// Then
	if first.DetailChecksum != second.DetailChecksum {
		t.Fatalf("order changed checksum: %s != %s", first.DetailChecksum, second.DetailChecksum)
	}
	if first.Entities.EntityCount != 1 || first.Entities.AliasCount != 4 {
		t.Fatalf("entity features=%+v", first.Entities)
	}
	wantAliases := []string{"agent:agent-1", "asset:web-01", "host:host-1", "ip:10.0.0.8"}
	if got := first.Entities.Entities[0].Aliases; !equalStrings(got, wantAliases) {
		t.Fatalf("aliases=%v, want %v", got, wantAliases)
	}
}

func TestCompute_captures_transition_and_exact_time_boundaries(t *testing.T) {
	// Given
	events, graph := featureFixture()

	// When
	detail, err := Compute(Input{Events: events, GraphEvents: graph, InputChecksum: "fixture-input"})
	if err != nil {
		t.Fatalf("compute features: %v", err)
	}

	// Then
	if detail.Time.SpanSeconds != 3600 || detail.Time.MaxObservationAgeSeconds != 7200 || detail.Time.MaxIngestLagSeconds != 7200 {
		t.Fatalf("time features=%+v", detail.Time)
	}
	if detail.Transitions.Allowed != 2 || detail.Transitions.Total != 2 {
		t.Fatalf("transition features=%+v", detail.Transitions)
	}
	if detail.Transitions.Sequence[0].Class != models.TransitionAllowed {
		t.Fatalf("first transition=%+v", detail.Transitions.Sequence[0])
	}
}

func TestCompute_features_are_monotonic_for_independent_evidence(t *testing.T) {
	// Given
	events, graph := featureFixture()

	// When
	base, err := Compute(Input{Events: events[:2], GraphEvents: graph[:2], InputChecksum: "base"})
	if err != nil {
		t.Fatalf("compute base features: %v", err)
	}
	expanded, err := Compute(Input{Events: events, GraphEvents: graph, InputChecksum: "expanded"})
	if err != nil {
		t.Fatalf("compute expanded features: %v", err)
	}

	// Then
	if expanded.Diversity.SourceCount < base.Diversity.SourceCount || expanded.Diversity.StageCount < base.Diversity.StageCount || expanded.Transitions.Allowed < base.Transitions.Allowed {
		t.Fatalf("independent evidence reduced features: base=%+v expanded=%+v", base, expanded)
	}
	if expanded.Criticality.MaxSeverityRank < base.Criticality.MaxSeverityRank || expanded.Continuity.EdgeCount < base.Continuity.EdgeCount {
		t.Fatalf("expanded criticality/continuity regressed: base=%+v expanded=%+v", base, expanded)
	}
}

func TestCompute_matches_explainable_versioned_golden(t *testing.T) {
	// Given
	events, graph := featureFixture()

	// When
	detail, err := Compute(Input{Events: events, GraphEvents: graph, InputChecksum: "fixture-input"})
	if err != nil {
		t.Fatalf("compute features: %v", err)
	}
	encoded, err := json.MarshalIndent(detail, "", "  ")
	if err != nil {
		t.Fatalf("encode detail: %v", err)
	}
	want, err := os.ReadFile("testdata/shadow-features.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	// Then
	if string(encoded)+"\n" != string(want) {
		t.Fatalf("feature golden mismatch\n--- got ---\n%s\n--- want ---\n%s", encoded, want)
	}
	if detail.AlgorithmVersion != models.AlgorithmV3Shadow.String() || detail.FeatureVersion != models.FeatureVersionV1 {
		t.Fatalf("feature version identity=%+v", detail)
	}
	for _, name := range []string{"entity.alias_count", "provenance.source_count", "time.max_observation_age_seconds", "transition.allowed", "diversity.stage_count", "duplicate.record_count", "staleness.max_observation_age_seconds", "continuity.average_edge_strength", "criticality.max_severity_rank"} {
		if !hasExplanation(detail.Explanations, name) {
			t.Fatalf("missing explanation field %q", name)
		}
	}
}

func featureFixture() ([]contracts.CanonicalSecurityEvent, []*models.CanonicalEventV2) {
	base := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	events := []contracts.CanonicalSecurityEvent{
		featureEvent("event-1", contracts.SourceAgentTraffic, "adapter-a", "digest-1", contracts.SeverityMedium, base, base.Add(2*time.Hour)),
		featureEvent("event-2", contracts.SourceWazuh, "adapter-b", "digest-2", contracts.SeverityHigh, base.Add(30*time.Minute), base.Add(2*time.Hour)),
		featureEvent("event-3", contracts.SourceAgentRASP, "adapter-c", "digest-3", contracts.SeverityCritical, base.Add(time.Hour), base.Add(2*time.Hour)),
	}
	graph := []*models.CanonicalEventV2{
		{EventUID: "event-1", AgentID: "Agent-1", HostID: "Host-1", VictimAsset: "web-01", NormalizedDstIP: "10.0.0.8", TechniqueID: "T1190", StageHint: models.StageInitialAccess, RiskScore: 50, ObservedAt: base},
		{EventUID: "event-2", AgentID: "agent-1", VictimAsset: "WEB-01", NormalizedDstIP: "10.0.0.8", TechniqueID: "T1059", StageHint: models.StageExecution, RiskScore: 70, ObservedAt: base.Add(30 * time.Minute)},
		{EventUID: "event-3", AgentID: "agent-1", HostID: "host-1", TechniqueID: "T1003", StageHint: models.StageCredentialAccess, RiskScore: 90, ObservedAt: base.Add(time.Hour)},
	}
	return events, graph
}

func featureEvent(uid string, source contracts.EventSource, adapter, digest string, severity contracts.AlertSeverity, observed, ingested time.Time) contracts.CanonicalSecurityEvent {
	return contracts.CanonicalSecurityEvent{EventUID: uid, Severity: severity, Timestamps: contracts.EventTimestamps{ObservedAt: observed, IngestedAt: ingested}, Provenance: contracts.EventProvenance{Source: source, Adapter: adapter, NativeSchema: "native.v1", PayloadSHA256: digest}}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasExplanation(explanations []models.FeatureExplanation, name string) bool {
	for _, explanation := range explanations {
		if explanation.Name == name {
			return true
		}
	}
	return false
}
