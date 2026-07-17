package features

import (
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func continuityFeatures(edges []*models.GraphEdgeV2) models.ContinuityFeatureSet {
	result := models.ContinuityFeatureSet{EdgeCount: len(edges)}
	connected := make(map[string]struct{})
	total := 0.0
	for _, edge := range edges {
		total += edge.Strength
		connected[edge.FromNodeUID] = struct{}{}
		connected[edge.ToNodeUID] = struct{}{}
		switch edge.Strength {
		case models.EdgeStrengthStrong:
			result.StrongEdgeCount++
		case models.EdgeStrengthModerate:
			result.ModerateEdgeCount++
		default:
			result.WeakEdgeCount++
		}
	}
	if len(edges) > 0 {
		result.AverageEdgeStrength = total / float64(len(edges))
	}
	result.ConnectedEventCount = len(connected)
	return result
}

func criticalityFeatures(events []contracts.CanonicalSecurityEvent, graphEvents []*models.CanonicalEventV2) models.CriticalityFeatureSet {
	result := models.CriticalityFeatureSet{}
	for _, event := range events {
		rank := severityRank(event.Severity)
		result.MaxSeverityRank = max(result.MaxSeverityRank, rank)
		switch event.Severity {
		case contracts.SeverityCritical:
			result.CriticalEventCount++
		case contracts.SeverityHigh:
			result.HighEventCount++
		}
	}
	for _, event := range graphEvents {
		result.AverageRiskScore += event.RiskScore
	}
	if len(graphEvents) > 0 {
		result.AverageRiskScore /= float64(len(graphEvents))
	}
	return result
}

func severityRank(severity contracts.AlertSeverity) int {
	switch contracts.AlertSeverity(strings.ToLower(string(severity))) {
	case contracts.SeverityLow:
		return 1
	case contracts.SeverityMedium:
		return 2
	case contracts.SeverityHigh:
		return 3
	case contracts.SeverityCritical:
		return 4
	default:
		return 0
	}
}
