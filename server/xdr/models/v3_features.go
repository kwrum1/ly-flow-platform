package models

import "time"

const FeatureVersionV1 = "xdr-features.v1"

type ShadowScoringDetail struct {
	TenantID         string                `json:"tenant_id"`
	AlgorithmVersion string                `json:"algorithm_version"`
	FeatureVersion   string                `json:"feature_version"`
	InputChecksum    string                `json:"input_checksum"`
	DetailUID        string                `json:"detail_uid"`
	DetailChecksum   string                `json:"detail_checksum"`
	Entities         EntityFeatureSet      `json:"entities"`
	Provenance       ProvenanceFeatureSet  `json:"provenance"`
	Time             TimeFeatureSet        `json:"time"`
	Transitions      TransitionFeatureSet  `json:"transitions"`
	Diversity        DiversityFeatureSet   `json:"diversity"`
	Duplicates       DuplicateFeatureSet   `json:"duplicates"`
	Staleness        StalenessFeatureSet   `json:"staleness"`
	Continuity       ContinuityFeatureSet  `json:"continuity"`
	Criticality      CriticalityFeatureSet `json:"criticality"`
	Explanations     []FeatureExplanation  `json:"explanations"`
}

type EntityFeatureSet struct {
	EntityCount int                `json:"entity_count"`
	AliasCount  int                `json:"alias_count"`
	Entities    []NormalizedEntity `json:"normalized_entities"`
}

type NormalizedEntity struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	EventUIDs []string `json:"event_uids"`
}

type ProvenanceFeatureSet struct {
	SourceCount       int      `json:"source_count"`
	AdapterCount      int      `json:"adapter_count"`
	NativeSchemaCount int      `json:"native_schema_count"`
	SingleSource      bool     `json:"single_source"`
	Sources           []string `json:"sources"`
}

type TimeFeatureSet struct {
	FirstObservedAt          time.Time `json:"first_observed_at"`
	LastObservedAt           time.Time `json:"last_observed_at"`
	EvaluationAt             time.Time `json:"evaluation_at"`
	SpanSeconds              int64     `json:"span_seconds"`
	MaxObservationAgeSeconds int64     `json:"max_observation_age_seconds"`
	MaxIngestLagSeconds      int64     `json:"max_ingest_lag_seconds"`
}

type TransitionFeatureSet struct {
	Total    int                 `json:"total"`
	Allowed  int                 `json:"allowed"`
	Weak     int                 `json:"weak"`
	Reverse  int                 `json:"reverse"`
	Invalid  int                 `json:"invalid"`
	Unknown  int                 `json:"unknown"`
	Sequence []TransitionFeature `json:"sequence"`
}

type TransitionFeature struct {
	FromEventUID  string          `json:"from_event_uid"`
	ToEventUID    string          `json:"to_event_uid"`
	FromTechnique string          `json:"from_technique"`
	ToTechnique   string          `json:"to_technique"`
	Class         TransitionClass `json:"class"`
}

type DiversityFeatureSet struct {
	SourceCount    int `json:"source_count"`
	StageCount     int `json:"stage_count"`
	TechniqueCount int `json:"technique_count"`
	EntityCount    int `json:"entity_count"`
}

type DuplicateFeatureSet struct {
	RecordCount          int     `json:"record_count"`
	UniquePayloadCount   int     `json:"unique_payload_count"`
	DuplicateGroupCount  int     `json:"duplicate_group_count"`
	DuplicateRecordCount int     `json:"duplicate_record_count"`
	DuplicateRatio       float64 `json:"duplicate_ratio"`
}

type StalenessFeatureSet struct {
	MaxObservationAgeSeconds int64 `json:"max_observation_age_seconds"`
	MaxIngestLagSeconds      int64 `json:"max_ingest_lag_seconds"`
	ThresholdApplied         bool  `json:"threshold_applied"`
}

type ContinuityFeatureSet struct {
	EdgeCount           int     `json:"edge_count"`
	StrongEdgeCount     int     `json:"strong_edge_count"`
	ModerateEdgeCount   int     `json:"moderate_edge_count"`
	WeakEdgeCount       int     `json:"weak_edge_count"`
	AverageEdgeStrength float64 `json:"average_edge_strength"`
	ConnectedEventCount int     `json:"connected_event_count"`
}

type CriticalityFeatureSet struct {
	MaxSeverityRank    int     `json:"max_severity_rank"`
	CriticalEventCount int     `json:"critical_event_count"`
	HighEventCount     int     `json:"high_event_count"`
	AverageRiskScore   float64 `json:"average_risk_score"`
}

type FeatureExplanation struct {
	Name         string   `json:"name"`
	Value        string   `json:"value"`
	Source       string   `json:"source"`
	Definition   string   `json:"definition"`
	EvidenceUIDs []string `json:"evidence_uids"`
}
