package models

import "time"

type ChainHypothesisV2 struct {
	ID                   int64           `json:"id,omitempty"`
	TenantID             string          `json:"tenant_id"`
	HypothesisUID        string          `json:"hypothesis_uid"`
	SeedNodeUID          string          `json:"seed_node_uid,omitempty"`
	PathNodeUIDs         []string        `json:"path_node_uids,omitempty"`
	PathEdgeUIDs         []string        `json:"path_edge_uids,omitempty"`
	RiskScore            float64         `json:"risk_score"`
	ConfidenceScore      float64         `json:"confidence_score"`
	ImpactScore          float64         `json:"impact_score"`
	PathContinuityScore  float64         `json:"path_continuity_score"`
	ChainScore           float64         `json:"chain_score"`
	ScoreDetail          *ScoreDetailV2  `json:"score_detail,omitempty"`
	Severity             string          `json:"severity"`
	PathEvidence         *PathEvidence   `json:"path_evidence,omitempty"`
	HypothesisStatus     string          `json:"hypothesis_status"`
	RejectionReason      string          `json:"rejection_reason,omitempty"`
	EvaluationVersion    string          `json:"evaluation_version"`
	AttackMappingVersion string          `json:"attack_mapping_version,omitempty"`
	FirstSeen            *time.Time      `json:"first_seen,omitempty"`
	LastSeen             *time.Time      `json:"last_seen,omitempty"`
	TruncatedCandidates  int             `json:"truncated_candidates"`
	TraversalDepth       int             `json:"traversal_depth"`
	CreatedAt            time.Time       `json:"created_at"`
}

const (
	HypothesisStatusCandidate = "candidate"
	HypothesisStatusConfirmed = "confirmed"
	HypothesisStatusRejected  = "rejected"
	HypothesisStatusArchived  = "archived"

	RejectionReasonNoStrongEdge     = "no_strong_edge"
	RejectionReasonReverseStageOrder = "reverse_stage_order"
	RejectionReasonOutsideWindow     = "outside_window"
	RejectionReasonBelowThreshold   = "below_threshold"
	RejectionReasonMissingContinuity = "missing_continuity"
)

type TransitionClass string

const (
	TransitionAllowed    TransitionClass = "allowed"
	TransitionWeak       TransitionClass = "weak"
	TransitionReverse    TransitionClass = "reverse"
	TransitionInvalid    TransitionClass = "invalid"
	TransitionUnknown    TransitionClass = "unknown"
)

type AttackTransition struct {
	ID                   int64           `json:"id,omitempty"`
	FromTechnique        string          `json:"from_technique"`
	FromTactic           string          `json:"from_tactic,omitempty"`
	ToTechnique          string          `json:"to_technique"`
	ToTactic             string          `json:"to_tactic,omitempty"`
	TransitionClass      TransitionClass `json:"transition_class"`
	Penalty              float64         `json:"penalty"`
	ConfidenceAdjust     float64         `json:"confidence_adjust"`
	AttackMappingVersion string          `json:"attack_mapping_version"`
	CreatedAt            time.Time       `json:"created_at"`
}

type TrustedProxy struct {
	ID          int64     `json:"id,omitempty"`
	TenantID    string    `json:"tenant_id"`
	CIDR        string    `json:"cidr"`
	Description string    `json:"description,omitempty"`
	Priority    int       `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
}
