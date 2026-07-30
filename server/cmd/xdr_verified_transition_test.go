package main

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestVerifiedAttackTransitionIsScoredBeforeValidation(t *testing.T) {
	now := time.Now().UTC()
	events := []*models.CanonicalEventV2{
		{EventUID: "login", AgentID: "agent-1", VictimAsset: "host-1", TechniqueID: "T1078", StageHint: "initial_access", ObservedAt: now, RiskScore: 75, ConfidenceScore: 90},
		{EventUID: "sudo", AgentID: "agent-1", VictimAsset: "host-1", TechniqueID: "T1548.003", StageHint: "privilege_escalation", ObservedAt: now.Add(time.Second), RiskScore: 55, ConfidenceScore: 90},
	}
	_, edges := buildGraphEdges(nil, events, &Config{})
	if len(edges) != 1 || edges[0].EdgeType != models.EdgeTypeVerifiedAttackTransition {
		t.Fatalf("edges=%#v", edges)
	}
	hypotheses := boundedPathSearch(events, edges, &Config{})
	if len(hypotheses) == 0 || hypotheses[0].HypothesisStatus != models.HypothesisStatusCandidate {
		t.Fatalf("hypotheses=%#v", hypotheses)
	}
}
