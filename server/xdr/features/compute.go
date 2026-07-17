package features

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

var ErrMismatchedEvents = errors.New("feature input event sets do not match")

type Input struct {
	Events        []contracts.CanonicalSecurityEvent
	GraphEvents   []*models.CanonicalEventV2
	Edges         []*models.GraphEdgeV2
	InputChecksum string
}

func Compute(input Input) (models.ShadowScoringDetail, error) {
	if len(input.Events) != len(input.GraphEvents) {
		return models.ShadowScoringDetail{}, ErrMismatchedEvents
	}
	events := append([]contracts.CanonicalSecurityEvent(nil), input.Events...)
	graphEvents := append([]*models.CanonicalEventV2(nil), input.GraphEvents...)
	sort.Slice(events, func(left, right int) bool { return events[left].EventUID < events[right].EventUID })
	sort.Slice(graphEvents, func(left, right int) bool {
		if graphEvents[left].ObservedAt.Equal(graphEvents[right].ObservedAt) {
			return graphEvents[left].EventUID < graphEvents[right].EventUID
		}
		return graphEvents[left].ObservedAt.Before(graphEvents[right].ObservedAt)
	})
	eventUIDs := make(map[string]struct{}, len(events))
	for _, event := range events {
		eventUIDs[event.EventUID] = struct{}{}
	}
	for _, event := range graphEvents {
		if event == nil {
			return models.ShadowScoringDetail{}, ErrMismatchedEvents
		}
		if _, exists := eventUIDs[event.EventUID]; !exists {
			return models.ShadowScoringDetail{}, ErrMismatchedEvents
		}
	}
	entities := normalizedEntities(graphEvents)
	provenance, duplicates := provenanceFeatures(events)
	timeFeatures := exactTimeFeatures(events)
	transitions := transitionFeatures(graphEvents)
	continuity := continuityFeatures(input.Edges)
	criticality := criticalityFeatures(events, graphEvents)
	evidenceUIDs := make([]string, len(events))
	for index := range events {
		evidenceUIDs[index] = events[index].EventUID
	}
	tenantID := "default"
	if len(graphEvents) > 0 && graphEvents[0].TenantID != "" {
		tenantID = graphEvents[0].TenantID
	}
	detail := models.ShadowScoringDetail{
		TenantID: tenantID, AlgorithmVersion: models.AlgorithmV3Shadow.String(), FeatureVersion: models.FeatureVersionV1,
		InputChecksum: input.InputChecksum, Entities: entities, Provenance: provenance, Time: timeFeatures,
		Transitions: transitions, Diversity: models.DiversityFeatureSet{SourceCount: provenance.SourceCount, StageCount: uniqueGraphValueCount(graphEvents, func(event *models.CanonicalEventV2) string { return event.StageHint }), TechniqueCount: uniqueGraphValueCount(graphEvents, func(event *models.CanonicalEventV2) string { return event.TechniqueID }), EntityCount: entities.EntityCount},
		Duplicates: duplicates, Staleness: models.StalenessFeatureSet{MaxObservationAgeSeconds: timeFeatures.MaxObservationAgeSeconds, MaxIngestLagSeconds: timeFeatures.MaxIngestLagSeconds, ThresholdApplied: false},
		Continuity: continuity, Criticality: criticality,
	}
	detail.Explanations = explanations(detail, evidenceUIDs)
	encoded, err := json.Marshal(detail)
	if err != nil {
		return models.ShadowScoringDetail{}, fmt.Errorf("encode shadow scoring detail: %w", err)
	}
	digest := sha256.Sum256(encoded)
	detail.DetailChecksum = hex.EncodeToString(digest[:])
	detail.DetailUID = "feature-" + detail.DetailChecksum[:32]
	return detail, nil
}

func explanations(detail models.ShadowScoringDetail, evidence []string) []models.FeatureExplanation {
	values := []struct {
		name, value, source, definition string
	}{
		{"entity.alias_count", strconv.Itoa(detail.Entities.AliasCount), "canonical_entity_aliases", "distinct normalized aliases joined by shared entity identifiers"},
		{"provenance.source_count", strconv.Itoa(detail.Provenance.SourceCount), "canonical_event.provenance.source", "distinct canonical provenance sources"},
		{"time.max_observation_age_seconds", strconv.FormatInt(detail.Time.MaxObservationAgeSeconds, 10), "canonical_event.timestamps", "maximum exact age from observation to deterministic evaluation time"},
		{"transition.allowed", strconv.Itoa(detail.Transitions.Allowed), models.AttackMappingVersionV1, "allowed transitions in the versioned attack mapping"},
		{"diversity.stage_count", strconv.Itoa(detail.Diversity.StageCount), "canonical_graph.stage_hint", "distinct normalized attack stages"},
		{"duplicate.record_count", strconv.Itoa(detail.Duplicates.DuplicateRecordCount), "canonical_event.provenance.payload_sha256", "records beyond the first occurrence of each payload digest"},
		{"staleness.max_observation_age_seconds", strconv.FormatInt(detail.Staleness.MaxObservationAgeSeconds, 10), "canonical_event.timestamps", "exact observation age without a production threshold"},
		{"continuity.average_edge_strength", strconv.FormatFloat(detail.Continuity.AverageEdgeStrength, 'f', 6, 64), "versioned_graph.edges", "arithmetic mean of deterministic graph edge strengths"},
		{"criticality.max_severity_rank", strconv.Itoa(detail.Criticality.MaxSeverityRank), "canonical_event.severity", "maximum ordinal severity where low=1 and critical=4"},
	}
	out := make([]models.FeatureExplanation, 0, len(values))
	for _, value := range values {
		out = append(out, models.FeatureExplanation{Name: value.name, Value: value.value, Source: value.source, Definition: value.definition, EvidenceUIDs: append([]string(nil), evidence...)})
	}
	return out
}

func uniqueGraphValueCount(events []*models.CanonicalEventV2, value func(*models.CanonicalEventV2) string) int {
	unique := make(map[string]struct{})
	for _, event := range events {
		normalized := strings.ToLower(strings.TrimSpace(value(event)))
		if normalized != "" {
			unique[normalized] = struct{}{}
		}
	}
	return len(unique)
}
