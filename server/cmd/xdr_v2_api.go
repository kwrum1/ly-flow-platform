package main

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/advisoryresponse"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type activeXDRRow struct {
	ID                   string                `json:"id"`
	CorrelationKey       string                `json:"correlation_key"`
	Entity               string                `json:"entity"`
	Victim               string                `json:"victim"`
	Score                float64               `json:"score"`
	Severity             string                `json:"severity"`
	StageCount           int                   `json:"stage_count"`
	EventCount           int                   `json:"event_count"`
	Categories           []string              `json:"categories"`
	Stages               []string              `json:"stages"`
	SourceIPs            []string              `json:"source_ips"`
	FirstSeen            string                `json:"first_seen"`
	LastSeen             string                `json:"last_seen"`
	Summary              string                `json:"summary"`
	Evidence             []interface{}         `json:"evidence"`
	ResponseCandidates   xdrResponseCandidates `json:"response_candidates"`
	CandidateOnly        bool                  `json:"candidate_only"`
	Algorithm            string                `json:"algorithm"`
	Engine               string                `json:"engine"`
	ScoreDetail          *models.ScoreDetailV2 `json:"score_detail"`
	PathEvidence         *models.PathEvidence  `json:"path_evidence"`
	Confidence           float64               `json:"confidence"`
	Impact               float64               `json:"impact"`
	Continuity           float64               `json:"continuity"`
	AttackMappingVersion string                `json:"attack_mapping_version"`
	HypothesisStatus     string                `json:"hypothesis_status"`
}

type xdrResponseCandidate struct {
	ID            string
	IncidentID    string
	AgentID       string
	Algorithm     string
	Type          string
	Target        string
	Reason        string
	Score         int64
	Evidence      []map[string]interface{}
	Safety        []string
	CandidateOnly bool
	ChainID       string
}

type xdrResponseCandidates []xdrResponseCandidate

func responseCandidateRows(values []map[string]interface{}) xdrResponseCandidates {
	out := make(xdrResponseCandidates, 0, len(values))
	for _, value := range values {
		out = append(out, xdrResponseCandidate{Type: asString(value["type"]), Target: asString(value["target"]), Reason: asString(value["reason"]), Score: xdrPickNumber(value, "score", 0), Evidence: mapSlice(value["evidence"]), Safety: stringListFromValue(value["safety"]), CandidateOnly: asBool(value["candidate_only"]), ChainID: asString(value["chain_id"])})
	}
	return out
}

func (candidate xdrResponseCandidate) jsonRow() map[string]interface{} {
	return map[string]interface{}{"candidate_id": candidate.ID, "incident_id": candidate.IncidentID, "agent_id": candidate.AgentID, "algorithm": candidate.Algorithm, "type": candidate.Type, "target": candidate.Target, "reason": candidate.Reason, "score": candidate.Score, "evidence": candidate.Evidence, "safety": candidate.Safety, "candidate_only": candidate.CandidateOnly, "chain_id": candidate.ChainID}
}

func (candidates xdrResponseCandidates) jsonRows() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.jsonRow())
	}
	return out
}

type xdrCanonicalInputSource interface {
	ReadCanonicalPayloads(context.Context, int64) ([][]byte, error)
}

func xdrActiveChainsResponse(ctx context.Context, cfg *Config, limit int) (xdrActiveRouteResult, error) {
	if cfg == nil || cfg.XDRGraph == nil || cfg.XDRInput == nil {
		return nil, fmt.Errorf("persistent XDR graph unavailable")
	}
	records, err := cfg.XDRInput.ReadCanonicalPayloads(ctx, 50)
	if err != nil {
		return nil, fmt.Errorf("read canonical XDR input: %w", err)
	}
	events, err := cfg.XDRGraph.decodeRaw(ctx, models.AlgorithmV2Active, records)
	if err != nil {
		return nil, fmt.Errorf("adapt canonical XDR input: %w", err)
	}
	return cfg.XDRGraph.RunActive(ctx, events, limit)
}

func xdrShadowChainsResponse(ctx context.Context, cfg *Config) (xdrShadowRouteResult, error) {
	if cfg == nil || cfg.XDRGraph == nil || cfg.XDRInput == nil {
		return nil, fmt.Errorf("persistent XDR graph unavailable")
	}
	records, err := cfg.XDRInput.ReadCanonicalPayloads(ctx, 50)
	if err != nil {
		return nil, fmt.Errorf("read canonical XDR input: %w", err)
	}
	events, err := cfg.XDRGraph.decodeRaw(ctx, models.AlgorithmV3Shadow, records)
	if err != nil {
		return nil, fmt.Errorf("adapt canonical XDR input: %w", err)
	}
	return cfg.XDRGraph.RunShadow(ctx, events)
}

func activeXDRRows(events []*models.CanonicalEventV2, hypotheses []*models.ChainHypothesisV2, limit int) activeXDRChains {
	return buildActiveRows(events, hypotheses, models.AlgorithmV2Active, limit)
}

func buildActiveRows(events []*models.CanonicalEventV2, hypotheses []*models.ChainHypothesisV2, identity models.AlgorithmIdentity, limit int) activeXDRChains {
	if len(events) < 2 {
		return activeEventOnlyChains(events, identity)
	}
	if limit <= 0 || limit > len(hypotheses) {
		limit = len(hypotheses)
	}
	out := make(activeXDRChains, 0, limit)
	for _, hypothesis := range hypotheses[:limit] {
		firstEvent := events[0]
		responseCandidates := make([]xdrResponseCandidate, 0)
		if identity.IncidentEligible() && hypothesis.HypothesisStatus == models.HypothesisStatusCandidate {
			for _, candidate := range buildResponseCandidatesFromFacts(
				int64(hypothesis.ChainScore), nil, firstEvent.VictimAsset, nil, safeStages(hypothesis), nil,
			) {
				row := responseCandidateRows([]map[string]interface{}{candidate})[0]
				row.ChainID = hypothesis.HypothesisUID
				row.IncidentID = "inc-" + strings.TrimPrefix(hypothesis.HypothesisUID, "chain-")
				row.AgentID = firstEvent.AgentID
				row.Algorithm = models.AlgorithmV2Active.String()
				row.ID = advisoryresponse.CandidateID(row.IncidentID, advisoryresponse.Action(row.Type), row.Target)
				responseCandidates = append(responseCandidates, row)
			}
		}
		out = append(out, activeXDRRow{ID: hypothesis.HypothesisUID, CorrelationKey: hypothesis.SeedNodeUID,
			Entity: firstEvent.VictimAsset, Victim: firstEvent.VictimAsset, Score: hypothesis.ChainScore,
			Severity: hypothesis.Severity, StageCount: len(hypothesis.PathNodeUIDs), EventCount: len(hypothesis.PathNodeUIDs),
			Categories: []string{}, Stages: safeStages(hypothesis), SourceIPs: []string{}, FirstSeen: safeTime(hypothesis.FirstSeen),
			LastSeen: safeTime(hypothesis.LastSeen), Summary: "", Evidence: []interface{}{}, ResponseCandidates: responseCandidates,
			CandidateOnly: true, Algorithm: identity.String(), Engine: identity.String(), ScoreDetail: hypothesis.ScoreDetail,
			PathEvidence: hypothesis.PathEvidence, Confidence: hypothesis.ConfidenceScore, Impact: hypothesis.ImpactScore,
			Continuity: hypothesis.PathContinuityScore, AttackMappingVersion: hypothesis.AttackMappingVersion,
			HypothesisStatus: hypothesis.HypothesisStatus})
	}
	return out
}

func activeEventOnlyChains(events []*models.CanonicalEventV2, identity models.AlgorithmIdentity) activeXDRChains {
	out := make(activeXDRChains, 0, len(events))
	for _, event := range events {
		out = append(out, activeXDRRow{ID: event.EventUID, Score: event.RiskScore, Severity: severityFromScore(event.RiskScore), StageCount: 1,
			EventCount: 1, Stages: []string{event.StageHint}, Categories: []string{}, SourceIPs: []string{}, FirstSeen: event.ObservedAt.Format(time.RFC3339),
			LastSeen: event.ObservedAt.Format(time.RFC3339), Algorithm: identity.String(), Engine: identity.String(), ScoreDetail: event.ScoreDetail,
			Confidence: event.ConfidenceScore, Evidence: []interface{}{}, ResponseCandidates: xdrResponseCandidates{}, CandidateOnly: true,
			HypothesisStatus: models.HypothesisStatusCandidate})
	}
	return out
}

func (row activeXDRRow) jsonRow() map[string]interface{} {
	return map[string]interface{}{"id": row.ID, "correlation_key": row.CorrelationKey, "entity": row.Entity, "victim": row.Victim, "score": row.Score, "severity": row.Severity, "stage_count": row.StageCount, "event_count": row.EventCount, "categories": row.Categories, "stages": row.Stages, "source_ips": row.SourceIPs, "first_seen": row.FirstSeen, "last_seen": row.LastSeen, "summary": row.Summary, "evidence": row.Evidence, "response_candidates": row.ResponseCandidates.jsonRows(), "candidate_only": row.CandidateOnly, "algorithm": row.Algorithm, "engine": row.Engine, "score_detail": row.ScoreDetail, "path_evidence": row.PathEvidence, "confidence": row.Confidence, "impact": row.Impact, "continuity": row.Continuity, "attack_mapping_version": row.AttackMappingVersion, "hypothesis_status": row.HypothesisStatus}
}

func (rows activeXDRChains) jsonRows() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.jsonRow())
	}
	return out
}
func safeStages(hypothesis *models.ChainHypothesisV2) []string {
	if hypothesis.PathEvidence != nil {
		return hypothesis.PathEvidence.Stages
	}
	return []string{}
}

func safeTime(value *time.Time) string {
	if value != nil && !value.IsZero() {
		return formatOptionalTime(*value)
	}
	return ""
}

func incidentsFromActiveXDR(result xdrIncidentInput) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0)
	for _, chain := range result.incidentChains() {
		if chain.HypothesisStatus == models.HypothesisStatusCandidate {
			rows = append(rows, chain.jsonRow())
		}
	}
	return incidentsFromXDRChains(rows)
}

func responseCandidatesFromActiveXDR(result xdrResponseCandidateInput) []map[string]interface{} {
	candidates := make([]map[string]interface{}, 0)
	for _, chain := range result.responseCandidateChains() {
		candidates = append(candidates, chain.ResponseCandidates.jsonRows()...)
	}
	return candidates
}

func xdrPostureFromChains(chains activeXDRChains) map[string]interface{} {
	active := 0
	totalScore := int64(0)
	for _, chain := range chains {
		if chain.HypothesisStatus != models.HypothesisStatusCandidate {
			continue
		}
		active++
		totalScore += int64(chain.Score)
	}
	riskScore := int64(0)
	if active > 0 {
		volumeAdjustment := int64(math.Min(20, math.Log2(float64(active)+1)*4))
		riskScore = clampInt64(totalScore/int64(active)+volumeAdjustment, 0, 100)
	}
	return map[string]interface{}{
		"active_chains": active,
		"risk_score":    riskScore,
		"risk_level":    severityFromScore(float64(riskScore)),
	}
}
