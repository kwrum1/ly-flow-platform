package main

import (
	"math"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"github.com/lyflow/ly-flow-platform/server/xdr/testdata"
)

func TestScoreDetailPublishesReproducibleBreakdown(t *testing.T) {
	cfg := &Config{XDRV2WindowHours: 24}
	events := []*models.CanonicalEventV2{
		{
			RiskScore: 60, ConfidenceScore: 80,
			ScoreDetail: &models.ScoreDetailV2{
				ImpactFactors: []models.ScoreFactor{{Name: "asset_importance", Value: 8, Weight: 0.15}},
			},
			ObservedAt: testdata.FixedNow,
		},
		{RiskScore: 75, ConfidenceScore: 85, ObservedAt: testdata.FixedNow.Add(5 * time.Minute)},
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

	detail := path.ScoreDetail
	if detail == nil {
		t.Fatal("score detail must be built")
	}
	if detail.Version != ScoringModelVersionV2 {
		t.Fatalf("version = %q", detail.Version)
	}
	if len(detail.Components) != 4 {
		t.Fatalf("components = %d", len(detail.Components))
	}

	sum := 0.0
	weights := 0.0
	for _, c := range detail.Components {
		sum += c.Contribution
		weights += c.Weight
		if math.Abs(c.Contribution-roundScore(c.Value*c.Weight)) > 0.01 {
			t.Fatalf("%s contribution %.4f != value*weight", c.Name, c.Contribution)
		}
	}
	if math.Abs(weights-1.0) > 1e-9 {
		t.Fatalf("weights must sum to 1, got %.4f", weights)
	}
	if !detail.Capped && math.Abs(sum-path.ChainScore) > 0.05 {
		t.Fatalf("components sum %.4f != chain score %.4f", sum, path.ChainScore)
	}
	if math.Abs(detail.FinalScore-path.ChainScore) > 1e-9 {
		t.Fatalf("final score %.4f != chain score %.4f", detail.FinalScore, path.ChainScore)
	}
	if detail.EventCount != 2 {
		t.Fatalf("event count = %d", detail.EventCount)
	}
	if len(detail.RiskFactors) == 0 || len(detail.ContinuityFactors) == 0 {
		t.Fatal("risk and continuity factors must be explained")
	}
}

func TestScoreDetailRecordsDecayAndOrderingPenalty(t *testing.T) {
	cfg := &Config{XDRV2WindowHours: 24}
	events := []*models.CanonicalEventV2{
		{RiskScore: 50, ConfidenceScore: 70, ObservedAt: testdata.FixedNow},
		{RiskScore: 50, ConfidenceScore: 70, ObservedAt: testdata.FixedNow.Add(20 * time.Hour)},
	}
	path := &ScoreablePath{
		Events:        events,
		EdgeTypes:     []string{models.EdgeTypeSameProcess},
		EdgeStrengths: []float64{models.EdgeStrengthStrong},
		FirstSeen:     testdata.FixedNow,
		LastSeen:      testdata.FixedNow.Add(20 * time.Hour),
		Transitions: []*models.AttackTransition{
			{TransitionClass: models.TransitionAllowed, Penalty: 0.05},
		},
		Depth: 2,
	}

	scoreChainHypothesisV2(path, cfg)

	if path.TemporalDecay <= 0 {
		t.Fatalf("20h span inside a 24h window must decay, got %.3f", path.TemporalDecay)
	}
	if path.OrderingPenalty <= 0 {
		t.Fatalf("ordering penalty not captured: %.3f", path.OrderingPenalty)
	}
	if math.Abs(path.ScoreDetail.TemporalDecay-path.TemporalDecay) > 1e-9 {
		t.Fatal("detail must publish the same decay used by the score")
	}
	if math.Abs(path.ScoreDetail.OrderingPenalty-path.OrderingPenalty) > 1e-9 {
		t.Fatal("detail must publish the same penalty used by the score")
	}
}

func TestScoreDetailMarksClampedScores(t *testing.T) {
	cfg := &Config{XDRV2WindowHours: 24}
	events := []*models.CanonicalEventV2{
		{RiskScore: 100, ConfidenceScore: 100, ObservedAt: testdata.FixedNow},
	}
	path := &ScoreablePath{
		Events:        events,
		EdgeStrengths: []float64{models.EdgeStrengthStrong},
		EdgeTypes:     []string{models.EdgeTypeSameProcess},
		FirstSeen:     testdata.FixedNow,
		LastSeen:      testdata.FixedNow,
		// Production weights sum to 1, so a composite can never exceed 100.
		// The cap is a guard against misconfiguration; exercise it directly.
		Weights: scoringWeights{Risk: 0.6, Confidence: 0.6, Impact: 0.4, Continuity: 0.4},
	}
	scoreChainHypothesisV2(path, cfg)
	if path.ChainScore != 100 {
		t.Fatalf("chain score = %.2f", path.ChainScore)
	}
	if !path.ScoreCapped || !path.ScoreDetail.Capped {
		t.Fatal("clamped score must be flagged instead of silently truncated")
	}
}

func TestXDRChainScoreDetailRecomputesScore(t *testing.T) {
	row := &xdrChainAgg{
		MaxScore:   72,
		TotalScore: 120,
		Events:     []map[string]interface{}{{}, {}},
		Stages:     map[string]struct{}{"execution": {}, "lateral_movement": {}},
		Categories: map[string]struct{}{"traffic": {}, "runtime": {}},
		Evidence:   []map[string]interface{}{{}, {}, {}},
		SeedStage:  "execution",
	}
	detail := xdrChainScoreDetail(row)
	final := detail["final_score"].(int64)
	raw := detail["raw_score"].(int64)

	sum := int64(0)
	for _, c := range detail["components"].([]map[string]interface{}) {
		sum += c["contribution"].(int64)
	}
	if sum != raw {
		t.Fatalf("component contributions %d != raw %d", sum, raw)
	}
	if xdrChainScore(row) != final {
		t.Fatal("xdrChainScore must equal the published final score")
	}
	if detail["version"] != XDRScoringVersionV1 {
		t.Fatalf("version = %v", detail["version"])
	}
	if final > 100 || final < 0 {
		t.Fatalf("final out of range: %d", final)
	}
}

func TestScoreXDREventPublishesVersionedComponents(t *testing.T) {
	event := map[string]interface{}{
		"severity":   "high",
		"confidence": 0.9,
		"category":   "runtime",
		"stage_hint": "execution",
		"rule_id":    "r-1",
	}
	score, detail := scoreXDREvent(event)
	if detail["version"] != XDRScoringVersionV1 {
		t.Fatalf("version = %v", detail["version"])
	}
	if detail["final_score"].(int64) != score {
		t.Fatal("final_score must match returned score")
	}
	raw := detail["raw_score"].(int64)
	sum := int64(0)
	for _, c := range detail["components"].([]map[string]interface{}) {
		sum += c["contribution"].(int64)
	}
	if sum != raw {
		t.Fatalf("contributions %d != raw %d", sum, raw)
	}
}
