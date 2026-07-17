package contracts

import (
	"context"
	"testing"
	"time"
)

type todo7HorizonSource struct {
	horizon PersistedRetirementHorizon
}

func (source todo7HorizonSource) Load(context.Context) (PersistedRetirementHorizon, error) {
	return source.horizon, nil
}

func TestRetirementGateAllowsOnlyFullPersistedZeroReadHorizon(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	horizon, err := NewPersistedRetirementHorizon(24*time.Hour, now.Add(-24*time.Hour), true, now)
	if err != nil {
		t.Fatalf("construct persisted horizon: %v", err)
	}

	// When
	status := (RetirementGate{Enabled: true}).Evaluate(context.Background(), todo7HorizonSource{horizon: horizon}, now)

	// Then
	if !status.Allowed {
		t.Fatalf("full zero-read horizon did not permit retirement: %+v", status)
	}
}

func TestRetirementGateBlocksStaleOrIncompleteProducerHorizon(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	horizon, err := NewPersistedRetirementHorizon(24*time.Hour, now.Add(-48*time.Hour), false, now)
	if err != nil {
		t.Fatalf("construct persisted horizon: %v", err)
	}

	// When
	status := (RetirementGate{Enabled: true}).Evaluate(context.Background(), todo7HorizonSource{horizon: horizon}, now)

	// Then
	if status.Allowed {
		t.Fatalf("incomplete producer upgrade permitted retirement: %+v", status)
	}
}

func TestRetirementGateBlocksStalePersistedEvidence(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	horizon, err := NewPersistedRetirementHorizon(24*time.Hour, now.Add(-48*time.Hour), true, now.Add(-RetirementEvidenceFreshness-time.Second))
	if err != nil {
		t.Fatalf("construct persisted horizon: %v", err)
	}

	// When
	status := (RetirementGate{Enabled: true}).Evaluate(context.Background(), todo7HorizonSource{horizon: horizon}, now)

	// Then
	if status.Allowed || status.Reason != "persisted retirement evidence is stale" {
		t.Fatalf("stale persisted evidence permitted retirement: %+v", status)
	}
}
