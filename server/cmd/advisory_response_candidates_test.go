package main

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/server/advisoryresponse"
	xdrmodels "github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestActiveResponseCandidates_expose_governed_identity_and_provenance(t *testing.T) {
	// Given
	events := []*xdrmodels.CanonicalEventV2{
		{EventUID: "event-1", AgentID: "agent-1", VictimAsset: "asset-1"},
		{EventUID: "event-2", AgentID: "agent-1", VictimAsset: "asset-1"},
	}
	hypothesis := &xdrmodels.ChainHypothesisV2{
		HypothesisUID: "chain-1", ChainScore: 80, Severity: "high", HypothesisStatus: xdrmodels.HypothesisStatusCandidate,
		PathNodeUIDs: []string{"node-1", "node-2"},
		PathEvidence: &xdrmodels.PathEvidence{Stages: []string{"initial_access", "execution"}},
	}

	// When
	rows := activeXDRRows(events, []*xdrmodels.ChainHypothesisV2{hypothesis}, 1)

	// Then
	if len(rows) != 1 || len(rows[0].ResponseCandidates) == 0 {
		t.Fatalf("active response candidates=%+v", rows)
	}
	for _, candidate := range rows[0].ResponseCandidates {
		expectedID := advisoryresponse.CandidateID("inc-1", advisoryresponse.Action(candidate.Type), candidate.Target)
		if candidate.ID != expectedID || candidate.IncidentID != "inc-1" || candidate.AgentID != "agent-1" || candidate.Algorithm != advisoryresponse.ActiveAlgorithm {
			t.Fatalf("candidate governance fields=%+v", candidate)
		}
	}
}
