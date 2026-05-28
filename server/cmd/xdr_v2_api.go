package main

import (
	"context"
	"sort"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func normalizeAndEnrich(cfg *Config, events []map[string]interface{}) []*models.CanonicalEventV2 {
	canonicals := make([]*models.CanonicalEventV2, 0, len(events))
	for _, raw := range events {
		canonical, err := normalizeComponentEvent(raw, cfg)
		if err != nil {
			continue
		}
		enrichCanonicalEvent(context.Background(), canonical, cfg)
		canonicals = append(canonicals, canonical)
	}
	return canonicals
}

func xdrV2ChainsResponse(cfg *Config, limit int) []map[string]interface{} {
	maxEvents := 50
	events, _, err := loadXDRComponentEventsWithPolicy(cfg, maxEvents, loadXDRResponsePolicy(cfg))
	if err != nil || len(events) == 0 {
		return nil
	}
	return xdrV2ChainsFromEvents(cfg, events, limit)
}

func xdrV2ChainsFromEvents(cfg *Config, events []map[string]interface{}, limit int) []map[string]interface{} {
	if len(events) > 30 {
		events = events[:30]
	}
	canonicals := normalizeAndEnrich(cfg, events)

	if len(canonicals) < 2 {
		return eventOnlyChains(canonicals)
	}

	sort.Slice(canonicals, func(i, j int) bool {
		return canonicals[i].ObservedAt.Before(canonicals[j].ObservedAt)
	})

	nodes, edges := buildGraphEdges(context.Background(), canonicals, cfg)
	_ = persistGraphNodes(context.Background(), nodes, cfg)
	_ = persistGraphEdges(context.Background(), edges, cfg)

	hypotheses := boundedPathSearch(canonicals, edges, cfg)
	_ = persistChainHypotheses(context.Background(), hypotheses, cfg)

	hypLimit := limit
	if hypLimit <= 0 || hypLimit > len(hypotheses) {
		hypLimit = len(hypotheses)
	}

	out := make([]map[string]interface{}, 0, hypLimit)
	for _, hyp := range hypotheses[:hypLimit] {
		firstEvent := canonicals[0]
		row := map[string]interface{}{
			"id":                    hyp.HypothesisUID,
			"correlation_key":       hyp.SeedNodeUID,
			"entity":                firstEvent.VictimAsset,
			"victim":                firstEvent.VictimAsset,
			"score":                 hyp.ChainScore,
			"severity":              hyp.Severity,
			"stage_count":           len(hyp.PathNodeUIDs),
			"event_count":           len(hyp.PathNodeUIDs),
			"categories":            []string{},
			"stages":                safeStages(hyp),
			"source_ips":            []string{},
			"first_seen":            safeTime(hyp.FirstSeen),
			"last_seen":             safeTime(hyp.LastSeen),
			"summary":               "",
			"evidence":              []interface{}{},
			"response_candidates":   []interface{}{},
			"candidate_only":        true,
			"engine":                "v2",
			"score_detail":          hyp.ScoreDetail,
			"path_evidence":         hyp.PathEvidence,
			"confidence":            hyp.ConfidenceScore,
			"impact":                hyp.ImpactScore,
			"continuity":            hyp.PathContinuityScore,
			"attack_mapping_version": hyp.AttackMappingVersion,
			"hypothesis_status":     hyp.HypothesisStatus,
		}
		out = append(out, row)
	}

	return out
}

func eventOnlyChains(events []*models.CanonicalEventV2) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		out = append(out, map[string]interface{}{
			"id":              ev.EventUID,
			"score":           ev.RiskScore,
			"severity":        severityFromScore(ev.RiskScore),
			"stage_count":     1,
			"event_count":     1,
			"stages":          []string{ev.StageHint},
			"first_seen":      ev.ObservedAt.Format(time.RFC3339),
			"last_seen":       ev.ObservedAt.Format(time.RFC3339),
			"engine":          "v2",
			"score_detail":    ev.ScoreDetail,
			"confidence":      ev.ConfidenceScore,
			"hypothesis_status": models.HypothesisStatusCandidate,
		})
	}
	return out
}

func safeStages(hyp *models.ChainHypothesisV2) []string {
	if hyp.PathEvidence != nil {
		return hyp.PathEvidence.Stages
	}
	return []string{}
}

func safeTime(t *time.Time) string {
	if t != nil && !t.IsZero() {
		return formatOptionalTime(*t)
	}
	return ""
}

func mergeV2IntoChains(v1Chains []map[string]interface{}, v2Chains []map[string]interface{}) {
	if len(v2Chains) == 0 {
		return
	}
	v2ByEntity := map[string]map[string]interface{}{}
	for _, v2 := range v2Chains {
		if entity, ok := v2["entity"].(string); ok && entity != "" {
			v2ByEntity[entity] = v2
		}
		if victim, ok := v2["victim"].(string); ok && victim != "" {
			v2ByEntity[victim] = v2
		}
	}

	for _, v1 := range v1Chains {
		entity, _ := v1["entity"].(string)
		victim, _ := v1["victim"].(string)
		correlation, _ := v1["correlation_key"].(string)

		var matched map[string]interface{}
		for _, key := range []string{entity, victim, correlation} {
			if key == "" {
				continue
			}
			if v2, ok := v2ByEntity[key]; ok {
				matched = v2
				break
			}
		}

		if matched == nil && len(v2Chains) > 0 {
			matched = v2Chains[0]
		}

		if matched != nil {
			v1["score_detail"] = matched["score_detail"]
			v1["path_evidence"] = matched["path_evidence"]
			v1["confidence"] = matched["confidence"]
			v1["impact"] = matched["impact"]
			v1["continuity"] = matched["continuity"]
			v1["attack_mapping_version"] = matched["attack_mapping_version"]
			v1["hypothesis_status"] = matched["hypothesis_status"]
		}
	}
}
