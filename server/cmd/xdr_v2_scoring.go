package main

import (
	"math"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

// ScoringModelVersionV2 pins the arithmetic that produces ChainScore. Bump it
// whenever a weight or factor changes so stored scores stay interpretable.
const ScoringModelVersionV2 = "xdr-score.v2.1"

// scoringWeights is the composite weighting. Exposed so the API can publish the
// exact weights alongside a score instead of documenting them out of band.
type scoringWeights struct {
	Risk       float64
	Confidence float64
	Impact     float64
	Continuity float64
}

func defaultScoringWeights() scoringWeights {
	return scoringWeights{Risk: 0.35, Confidence: 0.25, Impact: 0.20, Continuity: 0.20}
}

func (w scoringWeights) normalized() scoringWeights {
	if w.Risk == 0 && w.Confidence == 0 && w.Impact == 0 && w.Continuity == 0 {
		return defaultScoringWeights()
	}
	return w
}

func scoreChainHypothesisV2(path *ScoreablePath, config *Config) {
	path.Weights = path.Weights.normalized()
	path.RiskScore = computeRiskScore(path)
	path.ConfidenceScore = computeConfidenceScore(path)
	path.ImpactScore = computeImpactScore(path)
	path.PathContinuityScore = computeContinuityScore(path, config)
	raw := path.Weights.Risk*path.RiskScore +
		path.Weights.Confidence*path.ConfidenceScore +
		path.Weights.Impact*path.ImpactScore +
		path.Weights.Continuity*path.PathContinuityScore
	path.ChainScore = clampFloat(raw, 0, 100)
	path.ScoreCapped = raw < 0 || raw > 100
	path.Severity = severityFromScore(path.ChainScore)
	path.ScoreDetail = path.buildScoreDetail()
}

// buildScoreDetail publishes every factor and the weighted breakdown so a
// reviewer can recompute ChainScore without reading the scoring source.
func (s *ScoreablePath) buildScoreDetail() *models.ScoreDetailV2 {
	detail := s.ScoreDetail
	if detail == nil {
		detail = s.eventScoreDetail()
	}
	riskFactors := append([]models.ScoreFactor{
		{Name: "event_risk_avg", Value: s.RiskScore - s.EventCountBonus, Source: "event", Weight: 1.0},
		{Name: "event_count_bonus", Value: s.EventCountBonus, Source: "chain", Weight: 1.0},
	}, detail.RiskFactors...)
	confFactors := append([]models.ScoreFactor{}, detail.ConfidenceFactors...)
	missing := append([]string{}, detail.MissingContext...)
	if len(s.EdgeStrengths) == 0 && len(s.Events) > 1 {
		missing = append(missing, "edge_strength")
	}
	detail.RiskFactors = riskFactors
	detail.ConfidenceFactors = confFactors
	detail.MissingContext = uniqueStrings(missing)
	w := s.Weights.normalized()
	detail.Version = ScoringModelVersionV2
	detail.FinalScore = s.ChainScore
	detail.Capped = s.ScoreCapped
	detail.TemporalDecay = s.TemporalDecay
	detail.OrderingPenalty = s.OrderingPenalty
	detail.EventCount = len(s.Events)
	detail.EventCountBonus = s.EventCountBonus
	detail.ContinuityFactors = append([]models.ScoreFactor{
		{Name: "edge_strength_avg", Value: s.EdgeStrengthAverage, Source: "graph", Weight: 1.0},
		{Name: "temporal_decay", Value: -s.TemporalDecay, Source: "window", Weight: 1.0},
		{Name: "ordering_penalty", Value: -s.OrderingPenalty, Source: "transition", Weight: 1.0},
	}, detail.ContinuityFactors...)
	detail.Components = []models.ScoreComponent{
		{Name: "risk", Value: s.RiskScore, Weight: w.Risk, Contribution: roundScore(w.Risk * s.RiskScore)},
		{Name: "confidence", Value: s.ConfidenceScore, Weight: w.Confidence, Contribution: roundScore(w.Confidence * s.ConfidenceScore)},
		{Name: "impact", Value: s.ImpactScore, Weight: w.Impact, Contribution: roundScore(w.Impact * s.ImpactScore)},
		{Name: "continuity", Value: s.PathContinuityScore, Weight: w.Continuity, Contribution: roundScore(w.Continuity * s.PathContinuityScore)},
	}
	return detail
}

func roundScore(v float64) float64 {
	return math.Round(v*100) / 100
}

type ScoreablePath struct {
	Events        []*models.CanonicalEventV2
	EdgeTypes     []string
	EdgeStrengths []float64
	Depth         int
	FirstSeen     time.Time
	LastSeen      time.Time
	Transitions   []*models.AttackTransition

	RiskScore           float64
	ConfidenceScore     float64
	ImpactScore         float64
	PathContinuityScore float64
	ChainScore          float64
	Severity            string
	RejectionReason     string
	HypothesisStatus    string

	Weights             scoringWeights
	EventCountBonus     float64
	EdgeStrengthAverage float64
	TemporalDecay       float64
	OrderingPenalty     float64
	ScoreCapped         bool
	ScoreDetail         *models.ScoreDetailV2
}

func computeRiskScore(path *ScoreablePath) float64 {
	if len(path.Events) == 0 {
		return 0
	}
	total := 0.0
	for _, ev := range path.Events {
		total += ev.RiskScore
	}
	avg := total / float64(len(path.Events))
	bonus := clampFloat(float64(len(path.Events))*0.5, 0, 5)
	path.EventCountBonus = bonus
	return clampFloat(avg+bonus, 0, 100)
}

func computeConfidenceScore(path *ScoreablePath) float64 {
	if len(path.Events) == 0 {
		return 0
	}
	total := 0.0
	for _, ev := range path.Events {
		total += ev.ConfidenceScore
	}
	avg := total / float64(len(path.Events))
	for _, t := range path.Transitions {
		avg += t.ConfidenceAdjust * 100
	}
	return clampFloat(avg, 0, 100)
}

func computeImpactScore(path *ScoreablePath) float64 {
	impact := 0.0
	for _, ev := range path.Events {
		if ev.ScoreDetail == nil {
			continue
		}
		for _, f := range ev.ScoreDetail.ImpactFactors {
			impact += f.Value * f.Weight
		}
	}
	return clampFloat(impact, 0, 100)
}

func computeContinuityScore(path *ScoreablePath, config *Config) float64 {
	n := len(path.EdgeStrengths)
	if n == 0 {
		if len(path.Events) > 1 {
			return 10
		}
		return 0
	}
	total := 0.0
	for _, s := range path.EdgeStrengths {
		total += s * 100
	}
	avg := total / float64(n)
	path.EdgeStrengthAverage = avg

	penalty := 0.0
	for _, t := range path.Transitions {
		if t != nil {
			penalty += t.Penalty * 100
		}
	}
	path.OrderingPenalty = penalty
	avg -= penalty

	windowHours := config.XDRV2WindowHours
	if windowHours <= 0 {
		windowHours = 24
	}
	duration := path.LastSeen.Sub(path.FirstSeen)
	hours := duration.Hours()
	decay := 0.0
	if hours > float64(windowHours)*0.5 {
		decay = clampFloat((hours-float64(windowHours)*0.5)/float64(windowHours)*10, 0, 30)
		avg -= decay
	}
	path.TemporalDecay = decay

	return clampFloat(avg, 0, 100)
}

func computeTemporalDecay(eventTime, now time.Time) float64 {
	hours := now.Sub(eventTime).Hours()
	if hours < 1 {
		return 0
	}
	if hours < 6 {
		return hours * 0.5
	}
	if hours < 24 {
		return 3 + (hours-6)*0.3
	}
	if hours < 72 {
		return 8.4 + (hours-24)*0.15
	}
	if hours < 168 {
		return 15.6 + (hours-72)*0.08
	}
	return 23 + math.Log(hours-168+1)*5
}

func validatePathContinuity(path *ScoreablePath, config *Config) (bool, string) {
	if len(path.Events) < 2 {
		return true, ""
	}

	hasStrongEdge := false
	for i, edgeType := range path.EdgeTypes {
		if models.EdgeTypeIsStrong(edgeType) && i < len(path.EdgeStrengths) && path.EdgeStrengths[i] >= models.EdgeStrengthModerate {
			hasStrongEdge = true
			break
		}
	}
	if !hasStrongEdge {
		return false, models.RejectionReasonNoStrongEdge
	}

	reverseCount := 0
	for _, t := range path.Transitions {
		if t != nil && t.TransitionClass == models.TransitionReverse {
			reverseCount++
		}
	}
	if reverseCount >= 2 {
		return false, models.RejectionReasonReverseStageOrder
	}

	windowHours := config.XDRV2WindowHours
	if windowHours <= 0 {
		windowHours = 24
	}
	span := path.LastSeen.Sub(path.FirstSeen)
	if span.Hours() > float64(windowHours) {
		return false, models.RejectionReasonOutsideWindow
	}

	if path.ChainScore < 25 {
		return false, models.RejectionReasonBelowThreshold
	}

	if path.PathContinuityScore < 15 {
		return false, models.RejectionReasonMissingContinuity
	}

	return true, ""
}
