package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	SecurityEventSchemaVersion       = "lyflow.security_event.v1"
	LegacySecurityEventSchemaVersion = "lyflow.security_event.v0"
	RedactedValue                    = "***REDACTED***"
	AttackMappingVersion             = "enterprise-attack.v16"
	RetentionPolicySecurityEvent30D  = "security-event-30d"
	AccessPolicySecurityEventRead    = "security-event-read"
	DeletionPolicySecurityEvent      = "security-event-delete"
	ExportPolicySecurityEvent        = "security-event-export"
	EncryptionAlgorithmAES256GCM     = "AES-256-GCM"
)

type EventSource string

const (
	SourceAgentTraffic   EventSource = "agent.traffic"
	SourceAgentRuntime   EventSource = "agent.runtime"
	SourceAgentLogAudit  EventSource = "agent.log_audit"
	SourceAgentRASP      EventSource = "agent.rasp"
	SourceSuricata       EventSource = "adapter.suricata"
	SourceWazuh          EventSource = "adapter.wazuh"
	SourceYARA           EventSource = "adapter.yara"
	SourceDPIEngine      EventSource = "dpi_engine"
	SourceSecurityEngine EventSource = "security_engine"
	SourceUnifiedLegacy  EventSource = "server.unified_legacy"
	SourceXDRV2          EventSource = "server.xdr_v2"
)

type DataClassification string

const (
	ClassificationInternal   DataClassification = "internal"
	ClassificationRestricted DataClassification = "restricted"
)

type QualityFlag string

const (
	QualityNormalized     QualityFlag = "normalized"
	QualityPrincipalBound QualityFlag = "principal_bound"
	QualityLegacyAdapted  QualityFlag = "legacy_adapted"
)

type PrincipalIdentity string

type SourceIdentity struct {
	PrincipalID string `json:"principal_id"`
	AgentID     string `json:"agent_id,omitempty"`
	Component   string `json:"component"`
}

type EventTimestamps struct {
	EventAt    time.Time `json:"event_at"`
	ObservedAt time.Time `json:"observed_at"`
	IngestedAt time.Time `json:"ingested_at"`
}

type EventProvenance struct {
	Source        EventSource `json:"source"`
	NativeSchema  string      `json:"native_schema"`
	NativeEventID string      `json:"native_event_id"`
	Adapter       string      `json:"adapter"`
	PayloadSHA256 string      `json:"payload_sha256"`
}

type AttackMapping struct {
	TacticID    string `json:"tactic_id,omitempty"`
	TechniqueID string `json:"technique_id,omitempty"`
	Version     string `json:"version"`
}

type RetentionPolicy struct {
	PolicyID  string    `json:"policy_id"`
	ExpiresAt time.Time `json:"expires_at"`
	LegalHold bool      `json:"legal_hold"`
}

type EncryptionMetadata struct {
	Required  bool   `json:"required"`
	Algorithm string `json:"algorithm"`
	KeyRef    string `json:"key_ref"`
}

type GovernanceMetadata struct {
	Classification   DataClassification `json:"classification"`
	Retention        RetentionPolicy    `json:"retention"`
	Encryption       EncryptionMetadata `json:"encryption"`
	AccessPolicyID   string             `json:"access_policy_id"`
	DeletionPolicyID string             `json:"deletion_policy_id"`
	ExportPolicyID   string             `json:"export_policy_id"`
	RedactedFields   []string           `json:"redacted_fields"`
}

type CanonicalSecurityEvent struct {
	SchemaVersion string             `json:"schema_version"`
	EventUID      string             `json:"event_uid"`
	CorrelationID string             `json:"correlation_id"`
	EventType     string             `json:"event_type"`
	Severity      AlertSeverity      `json:"severity"`
	Identity      SourceIdentity     `json:"identity"`
	Timestamps    EventTimestamps    `json:"timestamps"`
	Provenance    EventProvenance    `json:"provenance"`
	Attack        AttackMapping      `json:"attack"`
	QualityFlags  []QualityFlag      `json:"quality_flags"`
	Governance    GovernanceMetadata `json:"governance"`
	Payload       json.RawMessage    `json:"payload"`
}

func (event CanonicalSecurityEvent) Validate() error {
	if event.SchemaVersion != SecurityEventSchemaVersion {
		return fmt.Errorf("security event schema: %w", ErrUnsupportedSchema)
	}
	if event.EventUID == "" || event.CorrelationID == "" || event.EventType == "" {
		return errors.New("security event: missing stable identity")
	}
	if event.Identity.PrincipalID == "" || event.Identity.AgentID == "" || event.Identity.Component == "" {
		return ErrMissingIdentity
	}
	if event.Identity.AgentID != event.Identity.PrincipalID {
		return ErrIdentityConflict
	}
	if event.Timestamps.EventAt.IsZero() || event.Timestamps.ObservedAt.IsZero() || event.Timestamps.IngestedAt.IsZero() {
		return ErrMissingTimestamp
	}
	if !isKnownAlertSeverity(event.Severity) || !isKnownSource(event.Provenance.Source) || !isKnownClassification(event.Governance.Classification) {
		return ErrInvalidEnum
	}
	if err := validateCanonicalMetadata(event); err != nil {
		return err
	}
	if !event.Governance.Encryption.Required || event.Governance.Encryption.Algorithm != EncryptionAlgorithmAES256GCM || event.Governance.Encryption.KeyRef == "" {
		return errors.New("security event: encryption metadata required")
	}
	if event.Governance.Retention.PolicyID != RetentionPolicySecurityEvent30D || event.Governance.Retention.ExpiresAt.IsZero() {
		return errors.New("security event: retention metadata required")
	}
	if event.Governance.AccessPolicyID != AccessPolicySecurityEventRead || event.Governance.DeletionPolicyID != DeletionPolicySecurityEvent || event.Governance.ExportPolicyID != ExportPolicySecurityEvent {
		return errors.New("security event: governance policy metadata invalid")
	}
	if err := validateCanonicalPayloadGovernance(event.Payload, event.Governance.RedactedFields); err != nil {
		return err
	}
	return nil
}

func MarshalCanonical(event CanonicalSecurityEvent) ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, fmt.Errorf("marshal canonical security event: %w", err)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical security event: %w", err)
	}
	return encoded, nil
}

func isKnownAlertSeverity(severity AlertSeverity) bool {
	switch severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func isKnownClassification(classification DataClassification) bool {
	switch classification {
	case ClassificationInternal, ClassificationRestricted:
		return true
	default:
		return false
	}
}

func isKnownSource(source EventSource) bool {
	switch source {
	case SourceAgentTraffic, SourceAgentRuntime, SourceAgentLogAudit, SourceAgentRASP, SourceSuricata, SourceWazuh, SourceYARA, SourceDPIEngine, SourceSecurityEngine, SourceUnifiedLegacy, SourceXDRV2:
		return true
	default:
		return false
	}
}
