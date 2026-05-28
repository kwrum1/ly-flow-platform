package main

import (
	"math"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func scoreChainHypothesisV2(path *ScoreablePath, config *Config) {
	path.RiskScore = computeRiskScore(path)
	path.ConfidenceScore = computeConfidenceScore(path)
	path.ImpactScore = computeImpactScore(path)
	path.PathContinuityScore = computeContinuityScore(path, config)
	path.ChainScore = clampFloat(
		0.35*path.RiskScore+0.25*path.ConfidenceScore+0.20*path.ImpactScore+0.20*path.PathContinuityScore,
		0, 100,
	)
	path.Severity = severityFromScore(path.ChainScore)
}

type ScoreablePath struct {
	Events     []*models.CanonicalEventV2
	EdgeTypes  []string
	EdgeStrengths []float64
	Depth      int
	FirstSeen  time.Time
	LastSeen   time.Time
	Transitions []*models.AttackTransition

	RiskScore           float64
	ConfidenceScore     float64
	ImpactScore         float64
	PathContinuityScore float64
	ChainScore          float64
	Severity            string
	RejectionReason     string
	HypothesisStatus    string
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

	for _, t := range path.Transitions {
		if t != nil {
			avg -= t.Penalty * 100
		}
	}

	windowHours := config.XDRV2WindowHours
	if windowHours <= 0 {
		windowHours = 24
	}
	duration := path.LastSeen.Sub(path.FirstSeen)
	hours := duration.Hours()
	if hours > float64(windowHours)*0.5 {
		decay := (hours - float64(windowHours)*0.5) / float64(windowHours) * 10
		avg -= clampFloat(decay, 0, 30)
	}

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
