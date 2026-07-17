package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"github.com/lyflow/ly-flow-platform/server/xdr/testdata"
)

func TestDeterministicEventUID(t *testing.T) {
	uid1 := deterministicEventUID("default", "traffic", "rule-1", "1.2.3.4", "web-server", "agent-1", testdata.FixedNow)
	uid2 := deterministicEventUID("default", "traffic", "rule-1", "1.2.3.4", "web-server", "agent-1", testdata.FixedNow)
	uid3 := deterministicEventUID("default", "traffic", "rule-2", "1.2.3.4", "web-server", "agent-1", testdata.FixedNow)

	if uid1 != uid2 {
		t.Errorf("same inputs produce different UIDs: %s vs %s", uid1, uid2)
	}
	if uid1 == uid3 {
		t.Errorf("different rule IDs produce same UID: %s", uid1)
	}
}

func TestNormalizerMissingFields(t *testing.T) {
	event := map[string]interface{}{
		"severity":           "high",
		"component_category": "traffic",
		"created_at":         testdata.FixedNow.Format("2006-01-02T15:04:05Z"),
		"score_hint":         75,
		"confidence":         0.85,
		"agent_id":           "",
		"host_id":            "",
		"mitre_technique":    "",
	}

	cfg := &Config{XDRDefaultTenant: "default"}
	canonical, err := normalizeComponentEvent(event, cfg)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	if canonical.ConfidenceScore >= 90 {
		t.Errorf("missing fields should reduce confidence, got %.2f", canonical.ConfidenceScore)
	}
	if canonical.RiskScore == 0 {
		t.Errorf("risk should remain evidence-based even with missing fields")
	}
}

func TestAttackTransitionLookup(t *testing.T) {
	forward := models.LookupAttackTransition("T1190", "T1059", models.AttackMappingVersionV1)
	if forward.TransitionClass != models.TransitionAllowed {
		t.Errorf("forward transition should be allowed, got %s", forward.TransitionClass)
	}

	reverse := models.LookupAttackTransition("T1485", "T1190", models.AttackMappingVersionV1)
	if reverse.TransitionClass != models.TransitionReverse {
		t.Errorf("reverse transition should be reverse, got %s", reverse.TransitionClass)
	}

	unknown := models.LookupAttackTransition("T9999", "T8888", models.AttackMappingVersionV1)
	if unknown.TransitionClass != models.TransitionUnknown {
		t.Errorf("unknown transition should be unknown, got %s", unknown.TransitionClass)
	}
}

func TestTransitionPenalty(t *testing.T) {
	penalty, confAdj := models.TransitionPenalty("T1485", "T1190", models.AttackMappingVersionV1)
	if penalty <= 0 {
		t.Errorf("reverse transition should have penalty > 0, got %.2f", penalty)
	}
	if confAdj >= 0 {
		t.Errorf("reverse transition should have negative confidence adjust, got %.2f", confAdj)
	}
}

func TestTemporalDecay(t *testing.T) {
	now := testdata.FixedNow
	fresh := computeTemporalDecay(now.Add(-30*time.Minute), now)
	old6h := computeTemporalDecay(now.Add(-6*time.Hour), now)
	old25h := computeTemporalDecay(now.Add(-25*time.Hour), now)
	old7d := computeTemporalDecay(now.Add(-168*time.Hour), now)

	if fresh != 0 {
		t.Errorf("fresh event (<1h) should have 0 decay, got %.2f", fresh)
	}
	if old25h <= old6h {
		t.Errorf("older event should have higher decay: 6h=%.2f, 25h=%.2f", old6h, old25h)
	}
	if old7d <= old25h {
		t.Errorf("very old event should decay more: 25h=%.2f, 7d=%.2f", old25h, old7d)
	}
}

func TestScoreChainHypothesisV2(t *testing.T) {
	cfg := &Config{XDRV2WindowHours: 24}
	events := []*models.CanonicalEventV2{
		{
			RiskScore: 60, ConfidenceScore: 80,
			ScoreDetail: &models.ScoreDetailV2{
				ImpactFactors: []models.ScoreFactor{{Name: "asset_importance", Value: 8, Weight: 0.15}},
			},
			ObservedAt: testdata.FixedNow,
		},
		{
			RiskScore: 75, ConfidenceScore: 85,
			ObservedAt: testdata.FixedNow.Add(5 * time.Minute),
		},
	}

	path := &ScoreablePath{
		Events:        events,
		EdgeTypes:     []string{models.EdgeTypeSameProcess},
		EdgeStrengths: []float64{models.EdgeStrengthStrong},
		FirstSeen:     testdata.FixedNow,
		LastSeen:      testdata.FixedNow.Add(5 * time.Minute),
		Depth:         2,
	}

	scoreChainHypothesisV2(path, cfg)

	if path.ChainScore <= 0 || path.ChainScore > 100 {
		t.Errorf("chain score out of range: %.2f", path.ChainScore)
	}
	if path.Severity == "" {
		t.Error("severity should not be empty")
	}
}

func TestValidatePathContinuity_NoStrongEdge(t *testing.T) {
	cfg := &Config{XDRV2WindowHours: 24}
	path := &ScoreablePath{
		Events:        make([]*models.CanonicalEventV2, 2),
		EdgeTypes:     []string{models.EdgeTypeWeakSameIP},
		EdgeStrengths: []float64{models.EdgeStrengthWeak},
		FirstSeen:     testdata.FixedNow,
		LastSeen:      testdata.FixedNow.Add(10 * time.Minute),
		Depth:         2,
	}
	path.Events[0] = &models.CanonicalEventV2{ObservedAt: testdata.FixedNow}
	path.Events[1] = &models.CanonicalEventV2{ObservedAt: testdata.FixedNow.Add(10 * time.Minute)}

	valid, reason := validatePathContinuity(path, cfg)
	if valid {
		t.Error("path with only weak same-IP edges should be rejected")
	}
	if reason != models.RejectionReasonNoStrongEdge {
		t.Errorf("expected rejection reason %s, got %s", models.RejectionReasonNoStrongEdge, reason)
	}
}

func TestValidatePathContinuity_ReverseOrder(t *testing.T) {
	cfg := &Config{XDRV2WindowHours: 24}
	path := &ScoreablePath{
		Events:        make([]*models.CanonicalEventV2, 3),
		EdgeTypes:     []string{models.EdgeTypeSameProcess, models.EdgeTypeSameProcess},
		EdgeStrengths: []float64{models.EdgeStrengthStrong, models.EdgeStrengthStrong},
		Transitions: []*models.AttackTransition{
			{TransitionClass: models.TransitionReverse},
			{TransitionClass: models.TransitionReverse},
		},
		FirstSeen: testdata.FixedNow,
		LastSeen:  testdata.FixedNow.Add(1 * time.Hour),
		Depth:     3,
	}
	path.Events[0] = &models.CanonicalEventV2{ObservedAt: testdata.FixedNow}
	path.Events[1] = &models.CanonicalEventV2{ObservedAt: testdata.FixedNow.Add(30 * time.Minute)}
	path.Events[2] = &models.CanonicalEventV2{ObservedAt: testdata.FixedNow.Add(1 * time.Hour)}

	valid, reason := validatePathContinuity(path, cfg)
	if valid {
		t.Error("path with 2+ reverse transitions should be rejected")
	}
	if reason != models.RejectionReasonReverseStageOrder {
		t.Errorf("expected rejection reason %s, got %s", models.RejectionReasonReverseStageOrder, reason)
	}
}

func TestValidatePathContinuity_OutsideWindow(t *testing.T) {
	cfg := &Config{XDRV2WindowHours: 24}
	path := &ScoreablePath{
		Events:        make([]*models.CanonicalEventV2, 2),
		EdgeTypes:     []string{models.EdgeTypeSameProcess},
		EdgeStrengths: []float64{models.EdgeStrengthStrong},
		FirstSeen:     testdata.FixedNow,
		LastSeen:      testdata.FixedNow.Add(30 * time.Hour),
		Depth:         2,
	}
	path.Events[0] = &models.CanonicalEventV2{ObservedAt: testdata.FixedNow}
	path.Events[1] = &models.CanonicalEventV2{ObservedAt: testdata.FixedNow.Add(30 * time.Hour)}

	valid, reason := validatePathContinuity(path, cfg)
	if valid {
		t.Error("path outside 24h window should be rejected")
	}
	if reason != models.RejectionReasonOutsideWindow {
		t.Errorf("expected rejection reason %s, got %s", models.RejectionReasonOutsideWindow, reason)
	}
}

func TestEdgeClassification_SameProcess(t *testing.T) {
	a := &models.CanonicalEventV2{
		EventUID: "a", AgentID: "agent-1", ActorIdentity: "root",
		EventType: "exec", ObservedAt: testdata.FixedNow,
	}
	b := &models.CanonicalEventV2{
		EventUID: "b", AgentID: "agent-1", ActorIdentity: "root",
		EventType: "exec", ObservedAt: testdata.FixedNow.Add(1 * time.Minute),
	}
	cand := classifyEdge(a, b)
	if cand == nil {
		t.Fatal("same-process events should create edge")
	}
	if cand.edgeType != models.EdgeTypeSameProcess {
		t.Errorf("expected same_process edge, got %s", cand.edgeType)
	}
	if cand.strength != models.EdgeStrengthStrong {
		t.Errorf("expected strong strength, got %.2f", cand.strength)
	}
}

func TestEdgeClassification_WeakSameIP(t *testing.T) {
	a := &models.CanonicalEventV2{
		EventUID: "a", AgentID: "agent-1", NormalizedSrcIP: "1.2.3.4",
		ObservedAt: testdata.FixedNow,
	}
	b := &models.CanonicalEventV2{
		EventUID: "b", AgentID: "agent-2", NormalizedSrcIP: "1.2.3.4",
		ObservedAt: testdata.FixedNow.Add(1 * time.Minute),
	}
	cand := classifyEdge(a, b)
	if cand == nil {
		t.Fatal("same-IP different-host events should create weak edge")
	}
	if cand.edgeType != models.EdgeTypeWeakSameIP {
		t.Errorf("expected weak_same_ip edge, got %s", cand.edgeType)
	}
	if cand.strength != models.EdgeStrengthWeak {
		t.Errorf("expected weak strength, got %.2f", cand.strength)
	}
}

func TestBoundedPathSearch(t *testing.T) {
	cfg := &Config{XDRV2MaxDepth: 4, XDRV2MaxPathsPerSeed: 10, XDRV2WindowHours: 24}
	fixtures := testdata.TrueMultiStepSameHost
	evPtrs := make([]*models.CanonicalEventV2, len(fixtures))
	for i := range fixtures {
		evPtrs[i] = &fixtures[i]
	}

	_, edges := buildGraphEdges(context.Background(), evPtrs, cfg)
	hypotheses := boundedPathSearch(evPtrs, edges, cfg)

	if len(hypotheses) == 0 {
		t.Error("true multi-step chain should produce hypotheses")
	}

	for _, h := range hypotheses {
		if h.ChainScore <= 0 || h.ChainScore > 100 {
			t.Errorf("hypothesis %s has invalid score: %.2f", h.HypothesisUID, h.ChainScore)
		}
		if h.HypothesisStatus == models.HypothesisStatusRejected && h.RejectionReason == "" {
			t.Error("rejected hypothesis should have rejection reason")
		}
	}
}

func TestFalseAggregationNoContinuity(t *testing.T) {
	cfg := &Config{XDRV2MaxDepth: 6, XDRV2MaxPathsPerSeed: 10, XDRV2WindowHours: 24}
	fixtures := testdata.FalseSameSourceNoContinuity
	evPtrs := make([]*models.CanonicalEventV2, len(fixtures))
	for i := range fixtures {
		evPtrs[i] = &fixtures[i]
	}

	_, edges := buildGraphEdges(context.Background(), evPtrs, cfg)
	hypotheses := boundedPathSearch(evPtrs, edges, cfg)

	for _, h := range hypotheses {
		if h.HypothesisStatus == models.HypothesisStatusCandidate && h.ChainScore >= 60 {
			t.Errorf("false same-source aggregation should NOT produce high-score chain: %s score=%.2f status=%s",
				h.HypothesisUID, h.ChainScore, h.HypothesisStatus)
		}
	}
}

func TestLateralMovementEdge(t *testing.T) {
	cfg := &Config{XDRV2MaxDepth: 6, XDRV2MaxPathsPerSeed: 10, XDRV2WindowHours: 24}
	fixtures := testdata.CrossHostLateralMovements
	evPtrs := make([]*models.CanonicalEventV2, len(fixtures))
	for i := range fixtures {
		evPtrs[i] = &fixtures[i]
	}

	_, edges := buildGraphEdges(context.Background(), evPtrs, cfg)
	hasLateral := false
	for _, e := range edges {
		if e.EdgeType == models.EdgeTypeLateralMovement {
			hasLateral = true
			if e.Strength < models.EdgeStrengthModerate {
				t.Errorf("lateral movement edge should have moderate+ strength, got %.2f", e.Strength)
			}
		}
	}
	if !hasLateral {
		t.Error("cross-host lateral movement should produce lateral edge")
	}
}

func TestTrustedProxyAttribution(t *testing.T) {
	for _, tc := range testdata.TrustedProxyXFFCases {
		t.Run(tc.Name, func(t *testing.T) {
			trustedCIDRs := []*net.IPNet{}
			for _, cidr := range tc.TrustedCIDRs {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatalf("invalid test CIDR %s: %v", cidr, err)
				}
				trustedCIDRs = append(trustedCIDRs, network)
			}

			result := resolveSourceAttribution(tc.RemoteAddr, tc.XFF, trustedCIDRs)
			if result.ClientIP != tc.Expected {
				t.Errorf("expected client IP %s, got %s (reason: %s)", tc.Expected, result.ClientIP, result.Reason)
			}
		})
	}
}

func TestMissingEnrichmentConfidence(t *testing.T) {
	event := map[string]interface{}{
		"severity":           "medium",
		"component_category": "traffic",
		"created_at":         testdata.FixedNow.Format("2006-01-02T15:04:05Z"),
		"score_hint":         50,
		"confidence":         0.6,
	}

	cfg := &Config{XDRDefaultTenant: "default"}
	canonical, _ := normalizeComponentEvent(event, cfg)

	if canonical.ConfidenceScore >= 60 {
		t.Errorf("missing all context fields should significantly reduce confidence, got %.2f", canonical.ConfidenceScore)
	}
}

func TestStageOrder(t *testing.T) {
	if models.StageOrder(models.StageRecon) >= models.StageOrder(models.StageInitialAccess) {
		t.Error("recon should come before initial_access")
	}
	if models.StageOrder(models.StageInitialAccess) >= models.StageOrder(models.StageExecution) {
		t.Error("initial_access should come before execution")
	}
	if models.StageOrder(models.StageLateralMovement) >= models.StageOrder(models.StageExfiltration) {
		t.Error("lateral_movement should come before exfiltration")
	}
	if models.StageOrder("nonexistent") != models.StageOrderUnknown {
		t.Error("unknown stage should return StageOrderUnknown")
	}
}
