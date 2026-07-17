package models

import "time"

type GraphNodeV2 struct {
	ID          int64     `json:"id,omitempty"`
	TenantID    string    `json:"tenant_id"`
	NodeUID     string    `json:"node_uid"`
	EventUID    string    `json:"event_uid,omitempty"`
	AssetID     string    `json:"asset_id,omitempty"`
	IP          string    `json:"ip,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Identity    string    `json:"identity,omitempty"`
	TechniqueID string    `json:"technique_id,omitempty"`
	TacticID    string    `json:"tactic_id,omitempty"`
	Metadata    string    `json:"metadata,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type GraphEdgeV2 struct {
	ID                    int64     `json:"id,omitempty"`
	TenantID              string    `json:"tenant_id"`
	EdgeUID               string    `json:"edge_uid"`
	FromNodeUID           string    `json:"from_node_uid"`
	ToNodeUID             string    `json:"to_node_uid"`
	EdgeType              string    `json:"edge_type"`
	Strength              float64   `json:"strength"`
	EvidenceEventUIDs     []string  `json:"evidence_event_uids,omitempty"`
	TemporalProximitySecs int       `json:"temporal_proximity_secs,omitempty"`
	Metadata              string    `json:"metadata,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

const (
	EdgeTypeSameSession      = "same_session"
	EdgeTypeSameProcess      = "same_process"
	EdgeTypeSameIdentity     = "same_identity"
	EdgeTypeSameHost         = "same_host"
	EdgeTypeNetworkFlow      = "network_flow"
	EdgeTypeCredentialReuse  = "credential_reuse"
	EdgeTypeLateralMovement  = "lateral_movement"
	EdgeTypeExploitToVuln    = "exploit_to_vuln"
	EdgeTypeParentChild      = "parent_child"
	EdgeTypeAttackTransition = "attack_transition"
	EdgeTypeWeakSameIP       = "weak_same_ip"

	EdgeStrengthStrong   = 0.80
	EdgeStrengthModerate = 0.50
	EdgeStrengthWeak     = 0.20
)

func EdgeTypeIsStrong(edgeType string) bool {
	switch edgeType {
	case EdgeTypeSameSession, EdgeTypeSameProcess, EdgeTypeParentChild,
		EdgeTypeCredentialReuse, EdgeTypeLateralMovement, EdgeTypeExploitToVuln:
		return true
	default:
		return false
	}
}

func EdgeTypeStrength(edgeType string) float64 {
	switch edgeType {
	case EdgeTypeSameSession, EdgeTypeParentChild, EdgeTypeExploitToVuln:
		return EdgeStrengthStrong
	case EdgeTypeSameProcess, EdgeTypeSameIdentity, EdgeTypeSameHost,
		EdgeTypeNetworkFlow, EdgeTypeCredentialReuse, EdgeTypeLateralMovement:
		return EdgeStrengthModerate
	case EdgeTypeAttackTransition:
		return EdgeStrengthModerate
	case EdgeTypeWeakSameIP:
		return EdgeStrengthWeak
	default:
		return 0.10
	}
}
