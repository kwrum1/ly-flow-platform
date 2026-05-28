package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type pathCandidate struct {
	EventIndices   []int
	EdgeTypes      []string
	EdgeStrengths  []float64
	Transitions    []*models.AttackTransition
}

func boundedPathSearch(events []*models.CanonicalEventV2, edges []*models.GraphEdgeV2, config *Config) []*models.ChainHypothesisV2 {
	if len(events) == 0 {
		return nil
	}

	nodeEdges := buildAdjacency(edges)

	maxDepth := config.XDRV2MaxDepth
	if maxDepth <= 0 {
		maxDepth = 6
	}
	maxPaths := config.XDRV2MaxPathsPerSeed
	if maxPaths <= 0 {
		maxPaths = 50
	}
	windowHours := config.XDRV2WindowHours
	if windowHours <= 0 {
		windowHours = 24
	}
	window := time.Duration(windowHours) * time.Hour

	hypotheses := []*models.ChainHypothesisV2{}

	for seedIdx := 0; seedIdx < len(events); seedIdx++ {
		seedTime := events[seedIdx].ObservedAt
		candidates := []*pathCandidate{}
		queue := []*pathCandidate{{EventIndices: []int{seedIdx}}}
		seedHypotheses := 0

		for len(queue) > 0 && seedHypotheses < maxPaths {
			current := queue[0]
			queue = queue[1:]

			if len(current.EventIndices) > maxDepth {
				continue
			}

			lastIdx := current.EventIndices[len(current.EventIndices)-1]
			neighbors := nodeEdges[events[lastIdx].EventUID]

			for _, nb := range neighbors {
				nbIdx := eventIndexByUID(events, nb.ToEventUID)
				if nbIdx < 0 || containsIndex(current.EventIndices, nbIdx) {
					continue
				}

				nbTime := events[nbIdx].ObservedAt
				if nbTime.Before(seedTime) {
					continue
				}
				if nbTime.Sub(seedTime) > window {
					continue
				}

				newPath := &pathCandidate{
					EventIndices:  append(append([]int{}, current.EventIndices...), nbIdx),
					EdgeTypes:     append(append([]string{}, current.EdgeTypes...), nb.EdgeType),
					EdgeStrengths: append(append([]float64{}, current.EdgeStrengths...), nb.Strength),
				}

				newPath.Transitions = buildTransitions(events, newPath.EventIndices)

				candidates = append(candidates, newPath)
				seedHypotheses++

				if len(newPath.EventIndices) < maxDepth {
					queue = append(queue, newPath)
				}
			}
		}

		for _, cand := range candidates {
			hyp := pathToHypothesis(events, cand, config)
			if hyp != nil {
				hypotheses = append(hypotheses, hyp)
			}
		}
	}

	return deduceHypotheses(hypotheses)
}

type adjacencyEntry struct {
	ToEventUID string
	EdgeType   string
	Strength   float64
}

func buildAdjacency(edges []*models.GraphEdgeV2) map[string][]*adjacencyEntry {
	adj := map[string][]*adjacencyEntry{}
	for _, edge := range edges {
		fromUID := nodeToEventUID(edge.FromNodeUID)
		toUID := nodeToEventUID(edge.ToNodeUID)
		adj[fromUID] = append(adj[fromUID], &adjacencyEntry{
			ToEventUID: toUID,
			EdgeType:   edge.EdgeType,
			Strength:   edge.Strength,
		})
	}
	return adj
}

func nodeToEventUID(nodeUID string) string {
	if len(nodeUID) > 5 && nodeUID[:5] == "node-" {
		return nodeUID[5:]
	}
	return nodeUID
}

func eventIndexByUID(events []*models.CanonicalEventV2, uid string) int {
	for i, ev := range events {
		if ev.EventUID == uid {
			return i
		}
	}
	return -1
}

func containsIndex(indices []int, target int) bool {
	for _, i := range indices {
		if i == target {
			return true
		}
	}
	return false
}

func buildTransitions(events []*models.CanonicalEventV2, indices []int) []*models.AttackTransition {
	if len(indices) < 2 {
		return nil
	}
	transitions := make([]*models.AttackTransition, len(indices)-1)
	for i := 0; i < len(indices)-1; i++ {
		from := events[indices[i]]
		to := events[indices[i+1]]
		transitions[i] = models.LookupAttackTransition(from.TechniqueID, to.TechniqueID, models.AttackMappingVersionV1)
	}
	return transitions
}

func pathToHypothesis(events []*models.CanonicalEventV2, cand *pathCandidate, config *Config) *models.ChainHypothesisV2 {
	if len(cand.EventIndices) < 1 {
		return nil
	}

	pathEvents := make([]*models.CanonicalEventV2, len(cand.EventIndices))
	for i, idx := range cand.EventIndices {
		pathEvents[i] = events[idx]
	}

	firstTime := pathEvents[0].ObservedAt
	lastTime := pathEvents[len(pathEvents)-1].ObservedAt

	scoreable := &ScoreablePath{
		Events:        pathEvents,
		EdgeTypes:     cand.EdgeTypes,
		EdgeStrengths: cand.EdgeStrengths,
		Depth:         len(pathEvents),
		FirstSeen:     firstTime,
		LastSeen:      lastTime,
		Transitions:   cand.Transitions,
	}

	valid, reason := validatePathContinuity(scoreable, config)

	scoreChainHypothesisV2(scoreable, config)

	pathNodeUIDs := make([]string, len(cand.EventIndices))
	pathStages := make([]string, len(cand.EventIndices))
	for i, idx := range cand.EventIndices {
		pathNodeUIDs[i] = "node-" + events[idx].EventUID
		pathStages[i] = events[idx].StageHint
	}

	pathEvidence := buildPathEvidence(pathEvents, cand)
	status := models.HypothesisStatusCandidate
	if !valid {
		status = models.HypothesisStatusRejected
	}

	return &models.ChainHypothesisV2{
		TenantID:             pathEvents[0].TenantID,
		HypothesisUID:        fmt.Sprintf("hyp-%s", pathEvents[0].EventUID),
		SeedNodeUID:          "node-" + pathEvents[0].EventUID,
		PathNodeUIDs:         pathNodeUIDs,
		RiskScore:            scoreable.RiskScore,
		ConfidenceScore:      scoreable.ConfidenceScore,
		ImpactScore:          scoreable.ImpactScore,
		PathContinuityScore:  scoreable.PathContinuityScore,
		ChainScore:           scoreable.ChainScore,
		ScoreDetail:          scoreable.ScoreDetail(),
		Severity:             scoreable.Severity,
		HypothesisStatus:     status,
		RejectionReason:      reason,
		EvaluationVersion:    models.EvalVersionV2,
		AttackMappingVersion: models.AttackMappingVersionV1,
		TraversalDepth:       scoreable.Depth,
		PathEvidence:         pathEvidence,
		FirstSeen:            &firstTime,
		LastSeen:             &lastTime,
	}
}

func (s *ScoreablePath) ScoreDetail() *models.ScoreDetailV2 {
	riskFactors := []models.ScoreFactor{}
	confFactors := []models.ScoreFactor{}
	impFactors := []models.ScoreFactor{}
	missing := []string{}

	for _, ev := range s.Events {
		if ev.ScoreDetail == nil {
			continue
		}
		riskFactors = append(riskFactors, ev.ScoreDetail.RiskFactors...)
		confFactors = append(confFactors, ev.ScoreDetail.ConfidenceFactors...)
		impFactors = append(impFactors, ev.ScoreDetail.ImpactFactors...)
		missing = append(missing, ev.ScoreDetail.MissingContext...)
	}

	return &models.ScoreDetailV2{
		RiskFactors:       riskFactors,
		ConfidenceFactors: confFactors,
		ImpactFactors:     impFactors,
		ContinuityFactors: []models.ScoreFactor{
			{Name: "edge_strength_avg", Value: s.PathContinuityScore, Source: "graph", Weight: 1.0},
		},
		EventCount:      len(s.Events),
		EventCountBonus: clampFloat(float64(len(s.Events))*0.5, 0, 5),
	}
}

func buildPathEvidence(events []*models.CanonicalEventV2, cand *pathCandidate) *models.PathEvidence {
	timeline := make([]models.PathTimelineEntry, len(events))
	stages := make([]string, len(events))
	for i, ev := range events {
		entry := models.PathTimelineEntry{
			Order:       i,
			TechniqueID: ev.TechniqueID,
			TacticID:    ev.TacticID,
			Stage:       ev.StageHint,
			ObservedAt:  ev.ObservedAt,
			NodeUID:     "node-" + ev.EventUID,
		}
		if i < len(cand.EdgeTypes) {
			entry.EdgeUID = fmt.Sprintf("edge-%s", cand.EdgeTypes[i])
			entry.EdgeType = cand.EdgeTypes[i]
			entry.EdgeStrength = cand.EdgeStrengths[i]
		}
		timeline[i] = entry
		stages[i] = ev.StageHint
	}
	return &models.PathEvidence{
		Depth:    len(events),
		Stages:   stages,
		Timeline: timeline,
	}
}

func deduceHypotheses(hypotheses []*models.ChainHypothesisV2) []*models.ChainHypothesisV2 {
	if len(hypotheses) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]*models.ChainHypothesisV2, 0, len(hypotheses))
	for _, h := range hypotheses {
		if seen[h.HypothesisUID] {
			continue
		}
		seen[h.HypothesisUID] = true
		out = append(out, h)
	}
	return out
}

func persistChainHypotheses(ctx context.Context, hypotheses []*models.ChainHypothesisV2, config *Config) error {
	if config.DBPool == nil || len(hypotheses) == 0 {
		return nil
	}
	for _, h := range hypotheses {
		pathNodes, _ := json.Marshal(h.PathNodeUIDs)
		scoreDetail, _ := json.Marshal(h.ScoreDetail)
		pathEvidence, _ := json.Marshal(h.PathEvidence)
		firstSeen := "NULL"
		lastSeen := "NULL"
		if h.FirstSeen != nil && !h.FirstSeen.IsZero() {
			firstSeen = fmt.Sprintf("'%s'", h.FirstSeen.Format(time.RFC3339))
		}
		if h.LastSeen != nil && !h.LastSeen.IsZero() {
			lastSeen = fmt.Sprintf("'%s'", h.LastSeen.Format(time.RFC3339))
		}
		_, err := config.DBPool.Exec(ctx,
			`INSERT INTO xdr_chain_hypotheses (tenant_id, hypothesis_uid, seed_node_uid, path_node_uids, 
			 risk_score, confidence_score, impact_score, path_continuity_score, chain_score, score_detail,
			 severity, hypothesis_status, rejection_reason, evaluation_version, attack_mapping_version,
			 path_evidence, first_seen, last_seen, traversal_depth, created_at)
			 VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16::jsonb,
			 `+firstSeen+`::timestamptz, `+lastSeen+`::timestamptz, $17, NOW())
			 ON CONFLICT (tenant_id, hypothesis_uid) DO UPDATE SET chain_score=EXCLUDED.chain_score, severity=EXCLUDED.severity, hypothesis_status=EXCLUDED.hypothesis_status`,
			h.TenantID, h.HypothesisUID, h.SeedNodeUID, pathNodes,
			h.RiskScore, h.ConfidenceScore, h.ImpactScore, h.PathContinuityScore, h.ChainScore, scoreDetail,
			h.Severity, h.HypothesisStatus, h.RejectionReason, h.EvaluationVersion, h.AttackMappingVersion,
			pathEvidence, h.TraversalDepth)
		if err != nil {
			return fmt.Errorf("persist hypothesis %s: %w", h.HypothesisUID, err)
		}
	}
	return nil
}
