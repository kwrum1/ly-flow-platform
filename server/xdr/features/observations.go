package features

import (
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func provenanceFeatures(events []contracts.CanonicalSecurityEvent) (models.ProvenanceFeatureSet, models.DuplicateFeatureSet) {
	sources := make(map[string]struct{})
	adapters := make(map[string]struct{})
	schemas := make(map[string]struct{})
	payloadCounts := make(map[string]int)
	for _, event := range events {
		addNonEmpty(sources, string(event.Provenance.Source))
		addNonEmpty(adapters, event.Provenance.Adapter)
		addNonEmpty(schemas, event.Provenance.NativeSchema)
		digest := event.Provenance.PayloadSHA256
		if digest == "" {
			digest = "event:" + event.EventUID
		}
		payloadCounts[digest]++
	}
	duplicateGroups := 0
	duplicateRecords := 0
	for _, count := range payloadCounts {
		if count > 1 {
			duplicateGroups++
			duplicateRecords += count - 1
		}
	}
	ratio := 0.0
	if len(events) > 0 {
		ratio = float64(duplicateRecords) / float64(len(events))
	}
	return models.ProvenanceFeatureSet{SourceCount: len(sources), AdapterCount: len(adapters), NativeSchemaCount: len(schemas), SingleSource: len(sources) == 1, Sources: sortedSet(sources)}, models.DuplicateFeatureSet{RecordCount: len(events), UniquePayloadCount: len(payloadCounts), DuplicateGroupCount: duplicateGroups, DuplicateRecordCount: duplicateRecords, DuplicateRatio: ratio}
}

func exactTimeFeatures(events []contracts.CanonicalSecurityEvent) models.TimeFeatureSet {
	if len(events) == 0 {
		return models.TimeFeatureSet{}
	}
	first := events[0].Timestamps.ObservedAt
	last := first
	evaluation := events[0].Timestamps.IngestedAt
	maxIngestLag := int64(0)
	for _, event := range events {
		observed := event.Timestamps.ObservedAt
		ingested := event.Timestamps.IngestedAt
		if observed.Before(first) {
			first = observed
		}
		if observed.After(last) {
			last = observed
		}
		if ingested.After(evaluation) {
			evaluation = ingested
		}
		maxIngestLag = max(maxIngestLag, nonNegativeSeconds(ingested.Sub(observed)))
	}
	return models.TimeFeatureSet{FirstObservedAt: first.UTC(), LastObservedAt: last.UTC(), EvaluationAt: evaluation.UTC(), SpanSeconds: nonNegativeSeconds(last.Sub(first)), MaxObservationAgeSeconds: nonNegativeSeconds(evaluation.Sub(first)), MaxIngestLagSeconds: maxIngestLag}
}

func transitionFeatures(events []*models.CanonicalEventV2) models.TransitionFeatureSet {
	result := models.TransitionFeatureSet{Sequence: make([]models.TransitionFeature, 0, max(0, len(events)-1))}
	for index := 0; index+1 < len(events); index++ {
		from := events[index]
		to := events[index+1]
		transition := models.LookupAttackTransition(from.TechniqueID, to.TechniqueID, models.AttackMappingVersionV1)
		result.Total++
		switch transition.TransitionClass {
		case models.TransitionAllowed:
			result.Allowed++
		case models.TransitionWeak:
			result.Weak++
		case models.TransitionReverse:
			result.Reverse++
		case models.TransitionInvalid:
			result.Invalid++
		case models.TransitionUnknown:
			result.Unknown++
		}
		result.Sequence = append(result.Sequence, models.TransitionFeature{FromEventUID: from.EventUID, ToEventUID: to.EventUID, FromTechnique: from.TechniqueID, ToTechnique: to.TechniqueID, Class: transition.TransitionClass})
	}
	return result
}

func addNonEmpty(values map[string]struct{}, raw string) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized != "" {
		values[normalized] = struct{}{}
	}
}

func nonNegativeSeconds(duration time.Duration) int64 {
	if duration < 0 {
		return 0
	}
	return int64(duration.Seconds())
}
