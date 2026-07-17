package features

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestCompute_identifies_duplicate_single_source_and_staleness_without_thresholds(t *testing.T) {
	// Given
	base := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	events := []contracts.CanonicalSecurityEvent{
		featureEvent("duplicate-1", contracts.SourceWazuh, "adapter-a", "same-digest", contracts.SeverityHigh, base, base.Add(72*time.Hour)),
		featureEvent("duplicate-2", contracts.SourceWazuh, "adapter-a", "same-digest", contracts.SeverityHigh, base.Add(time.Minute), base.Add(72*time.Hour)),
	}
	graph := []*models.CanonicalEventV2{
		{EventUID: "duplicate-1", AgentID: "agent-1", TechniqueID: "T1190", StageHint: models.StageInitialAccess, ObservedAt: base, RiskScore: 70},
		{EventUID: "duplicate-2", AgentID: "agent-1", TechniqueID: "T1190", StageHint: models.StageInitialAccess, ObservedAt: base.Add(time.Minute), RiskScore: 70},
	}

	// When
	detail, err := Compute(Input{Events: events, GraphEvents: graph, InputChecksum: "duplicate-input"})
	if err != nil {
		t.Fatalf("compute features: %v", err)
	}

	// Then
	if detail.Duplicates.DuplicateRecordCount != 1 || detail.Duplicates.UniquePayloadCount != 1 {
		t.Fatalf("duplicate features=%+v", detail.Duplicates)
	}
	if !detail.Provenance.SingleSource || detail.Provenance.SourceCount != 1 {
		t.Fatalf("provenance features=%+v", detail.Provenance)
	}
	if detail.Staleness.MaxObservationAgeSeconds != 72*60*60 {
		t.Fatalf("staleness features=%+v", detail.Staleness)
	}
	if detail.Staleness.ThresholdApplied {
		t.Fatal("feature extraction invented a staleness threshold")
	}
}
