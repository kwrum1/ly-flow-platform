package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func normalizeComponentEvent(event map[string]interface{}, config *Config) (*models.CanonicalEventV2, error) {
	category := componentCategoryFromEvent(event)
	if category == "" {
		return nil, fmt.Errorf("unknown component category")
	}

	tenant := config.XDRDefaultTenant
	if tenant == "" {
		tenant = "default"
	}

	srcIP := xdrSourceIP(event)
	dstIP := xdrPickString(event, "dst_ip", "destination_ip", "entities.target_ip")
	agentID := xdrPickString(event, "agent_id")
	hostID := xdrPickString(event, "host_id")
	victim := xdrVictimEntity(event)
	technique := firstNonEmpty(strings.ToUpper(xdrPickString(event, "mitre_technique")), "")
	tactic := strings.ToLower(strings.TrimSpace(xdrPickString(event, "mitre_tactic")))
	stageHint := normalizeXDRStage(xdrPickString(event, "stage_hint"))
	confidence := xdrPickFloat(event, "confidence", 0.8)
	severity := xdrPickString(event, "severity")
	scoreHint := xdrPickNumber(event, "score_hint", 0)
	createdAt := parseXDRTime(firstNonEmpty(xdrPickString(event, "created_at"), xdrPickString(event, "timestamp")))
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	observedAt := parseXDRTime(firstNonEmpty(xdrPickString(event, "observed_at"), xdrPickString(event, "created_at"), xdrPickString(event, "timestamp")))
	if observedAt.IsZero() {
		observedAt = createdAt
	}

	ruleID := firstNonEmpty(xdrPickString(event, "component_rule_id"), xdrPickString(event, "rule_id"))
	eventUID, shadowUID := resolveEventUID(event, tenant, category, ruleID, srcIP, victim, agentID, observedAt)
	logEventUIDShadow(eventUID, shadowUID)

	riskScore := float64(scoreHint)
	if riskScore == 0 {
		riskScore = float64(severityBaseScore(severity))
	}

	confidenceScore := confidence * 100

	missingFields := []string{}
	if agentID == "" {
		missingFields = append(missingFields, "agent_id")
		confidenceScore -= 10
	}
	if hostID == "" {
		missingFields = append(missingFields, "host_id")
		confidenceScore -= 5
	}
	if technique == "" {
		missingFields = append(missingFields, "technique_id")
		confidenceScore -= 8
	}
	if srcIP == "" {
		missingFields = append(missingFields, "normalized_src_ip")
		confidenceScore -= 5
	}

	confidenceScore = clampFloat(confidenceScore, 0, 100)

	scoreDetail := &models.ScoreDetailV2{
		RiskFactors: []models.ScoreFactor{
			{Name: "evidence_severity", Value: riskScore, Source: "severity", Weight: 0.50},
			{Name: "rule_confidence", Value: confidenceScore, Source: "rule_score", Weight: 0.30},
		},
		ConfidenceFactors: []models.ScoreFactor{
			{Name: "component_confidence", Value: confidence * 100, Source: "component", Weight: 0.40},
			{Name: "field_completeness", Value: float64(100 - len(missingFields)*5), Source: "completeness", Weight: 0.30},
		},
		MissingContext: missingFields,
	}

	rawJSON, _ := json.Marshal(event)

	canonical := &models.CanonicalEventV2{
		TenantID:             tenant,
		EventUID:             eventUID,
		SourceComponent:      category,
		AgentID:              agentID,
		HostID:               hostID,
		ObservedAt:           observedAt,
		IngestedAt:           time.Now().UTC(),
		EventType:            xdrPickString(event, "event_type"),
		RawEvent:             rawJSON,
		NormalizedSrcIP:      srcIP,
		NormalizedDstIP:      dstIP,
		ActorIdentity:        xdrPickString(event, "user"),
		VictimAsset:          victim,
		TechniqueID:          technique,
		TacticID:             tactic,
		StageHint:            stageHint,
		StageConfidence:      confidence,
		RiskScore:            riskScore,
		ConfidenceScore:      confidenceScore,
		ScoreDetail:          scoreDetail,
		EvaluationVersion:    models.EvalVersionV2,
		AttackMappingVersion: models.AttackMappingVersionV1,
		CreatedAt:            createdAt,
	}

	return canonical, nil
}

func deterministicEventUID(tenant, category, ruleID, srcIP, victim, agentID string, t time.Time) string {
	ts := t.UTC().Truncate(time.Second).Format(time.RFC3339)
	parts := []string{tenant, category, firstOrEmpty(ruleID, "_"), srcIP, victim, agentID, ts}
	for i, p := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(p))
	}
	payload := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("xdr-%x", hash[:16])
}

func firstOrEmpty(a, fallback string) string {
	if a != "" {
		return a
	}
	return fallback
}
