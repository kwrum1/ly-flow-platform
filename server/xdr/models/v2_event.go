package models

import (
	"encoding/json"
	"sort"
	"time"
)

// CanonicalEventV2 is the normalized, immutable XDR v2 event used for graph construction.
type CanonicalEventV2 struct {
	ID                   int64           `json:"id,omitempty"`
	TenantID             string          `json:"tenant_id"`
	EventUID             string          `json:"event_uid"`
	SourceComponent      string          `json:"source_component"`
	AgentID              string          `json:"agent_id,omitempty"`
	HostID               string          `json:"host_id,omitempty"`
	ObservedAt           time.Time       `json:"observed_at"`
	IngestedAt           time.Time       `json:"ingested_at"`
	EventType            string          `json:"event_type,omitempty"`
	RawEvent             json.RawMessage `json:"raw_event,omitempty"`
	NormalizedSrcIP      string          `json:"normalized_src_ip,omitempty"`
	NormalizedDstIP      string          `json:"normalized_dst_ip,omitempty"`
	ActorIdentity        string          `json:"actor_identity,omitempty"`
	VictimAsset          string          `json:"victim_asset,omitempty"`
	TechniqueID          string          `json:"technique_id,omitempty"`
	TacticID             string          `json:"tactic_id,omitempty"`
	StageHint            string          `json:"stage_hint,omitempty"`
	StageConfidence      float64         `json:"stage_confidence"`
	RiskScore            float64         `json:"risk_score"`
	ConfidenceScore      float64         `json:"confidence_score"`
	ScoreDetail          *ScoreDetailV2  `json:"score_detail,omitempty"`
	EvaluationVersion    string          `json:"evaluation_version"`
	AttackMappingVersion string          `json:"attack_mapping_version,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
}

// ScoreDetailV2 holds every score factor for explainability.
type ScoreDetailV2 struct {
	RiskFactors       []ScoreFactor `json:"risk_factors"`
	ConfidenceFactors []ScoreFactor `json:"confidence_factors"`
	ImpactFactors     []ScoreFactor `json:"impact_factors"`
	ContinuityFactors []ScoreFactor `json:"continuity_factors"`
	EventCount        int           `json:"event_count"`
	EventCountBonus   float64       `json:"event_count_bonus"`
	TemporalDecay     float64       `json:"temporal_decay"`
	OrderingPenalty   float64       `json:"ordering_penalty"`
	MissingContext    []string      `json:"missing_context,omitempty"`
}

// ScoreFactor is a single named contributor to a score component.
type ScoreFactor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Source string  `json:"source"`
	Weight float64 `json:"weight"`
}

// PathEvidence holds the ordered attack path evidence for a chain hypothesis.
type PathEvidence struct {
	NodeUIDs []string            `json:"node_uids"`
	EdgeUIDs []string            `json:"edge_uids"`
	Stages   []string            `json:"stages"`
	Timeline []PathTimelineEntry `json:"timeline"`
	Depth    int                 `json:"depth"`
	Gaps     []string            `json:"gaps,omitempty"`
}

// PathTimelineEntry is a single step in the attack path timeline.
type PathTimelineEntry struct {
	Order        int       `json:"order"`
	TechniqueID  string    `json:"technique_id"`
	TacticID     string    `json:"tactic_id"`
	Stage        string    `json:"stage"`
	ObservedAt   time.Time `json:"observed_at"`
	NodeUID      string    `json:"node_uid"`
	EdgeUID      string    `json:"edge_uid,omitempty"`
	EdgeType     string    `json:"edge_type,omitempty"`
	EdgeStrength float64   `json:"edge_strength,omitempty"`
}

// EnrichmentSnapshotV2 captures enrichment state at event ingestion time.
type EnrichmentSnapshotV2 struct {
	ID                    int64     `json:"id,omitempty"`
	TenantID              string    `json:"tenant_id"`
	EventUID              string    `json:"event_uid"`
	AssetImportance       string    `json:"asset_importance,omitempty"`
	AssetRiskLevel        string    `json:"asset_risk_level,omitempty"`
	VulnCount             int       `json:"vuln_count"`
	VulnHighCount         int       `json:"vuln_high_count"`
	IdentityPrivilege     string    `json:"identity_privilege,omitempty"`
	AgentDisplayName      string    `json:"agent_display_name,omitempty"`
	AttributionConfidence float64   `json:"attribution_confidence"`
	AttributionReason     string    `json:"attribution_reason,omitempty"`
	EnrichmentErrors      []string  `json:"enrichment_errors,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

const (
	EvalVersionV2 = "xdr-eval.v2"

	StageRecon               = "recon"
	StageInitialAccess       = "initial_access"
	StageExecution           = "execution"
	StagePersistence         = "persistence"
	StagePrivilegeEscalation = "privilege_escalation"
	StageDefenseEvasion      = "defense_evasion"
	StageCredentialAccess    = "credential_access"
	StageDiscovery           = "discovery"
	StageLateralMovement     = "lateral_movement"
	StageCollection          = "collection"
	StageC2                  = "command_and_control"
	StageExfiltration        = "exfiltration"
	StageImpact              = "impact"

	StageOrderUnknown = -1
)

// StageOrderMap maps stage names to their canonical kill-chain order (0-indexed).
var StageOrderMap = map[string]int{
	StageRecon:               0,
	StageInitialAccess:       1,
	StageExecution:           2,
	StagePersistence:         3,
	StagePrivilegeEscalation: 4,
	StageDefenseEvasion:      5,
	StageCredentialAccess:    6,
	StageDiscovery:           7,
	StageLateralMovement:     8,
	StageCollection:          9,
	StageC2:                  10,
	StageExfiltration:        11,
	StageImpact:              12,
}

// StageOrder returns the canonical order of a stage, or StageOrderUnknown.
func StageOrder(stage string) int {
	if o, ok := StageOrderMap[stage]; ok {
		return o
	}
	return StageOrderUnknown
}

// StagedStages returns stages sorted by their canonical order.
func StagedStages(stages map[string]struct{}) []string {
	out := make([]string, 0, len(stages))
	for s := range stages {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return StageOrder(out[i]) < StageOrder(out[j])
	})
	return out
}
