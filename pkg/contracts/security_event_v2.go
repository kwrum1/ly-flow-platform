package contracts

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SecurityEventSchemaV2 is the canonical multi-source event contract used by
// the NDR/EDR/XDR pipeline. It is additive: v1 remains readable.
const SecurityEventSchemaV2 = "lyflow.security_event.v2"

// AttackStage is the kill-chain / ATT&CK stage assigned after correlation.
// Producers may leave it empty; normalization derives it from TacticID.
type AttackStage string

const (
	StageUnknown             AttackStage = "unknown"
	StageRecon               AttackStage = "recon"
	StageInitialAccess       AttackStage = "initial_access"
	StageExecution           AttackStage = "execution"
	StagePersistence         AttackStage = "persistence"
	StagePrivilegeEscalation AttackStage = "privilege_escalation"
	StageDefenseEvasion      AttackStage = "defense_evasion"
	StageCredentialAccess    AttackStage = "credential_access"
	StageDiscovery           AttackStage = "discovery"
	StageLateralMovement     AttackStage = "lateral_movement"
	StageCollection          AttackStage = "collection"
	StageCommandControl      AttackStage = "command_and_control"
	StageExfiltration        AttackStage = "exfiltration"
	StageImpact              AttackStage = "impact"
)

// IsKnownAttackStage reports whether the stage is part of the supported set.
func IsKnownAttackStage(stage AttackStage) bool {
	switch stage {
	case StageUnknown, StageRecon, StageInitialAccess, StageExecution,
		StagePersistence, StagePrivilegeEscalation, StageDefenseEvasion,
		StageCredentialAccess, StageDiscovery, StageLateralMovement,
		StageCollection, StageCommandControl, StageExfiltration, StageImpact:
		return true
	default:
		return false
	}
}

// StageForTactic maps an ATT&CK tactic ID to the default stage. Correlation may
// override the result with evidence-based progression.
func StageForTactic(tacticID string) AttackStage {
	switch strings.TrimSpace(strings.ToUpper(tacticID)) {
	case "TA0043":
		return StageRecon
	case "TA0001":
		return StageInitialAccess
	case "TA0002":
		return StageExecution
	case "TA0003":
		return StagePersistence
	case "TA0004":
		return StagePrivilegeEscalation
	case "TA0005":
		return StageDefenseEvasion
	case "TA0006":
		return StageCredentialAccess
	case "TA0007":
		return StageDiscovery
	case "TA0008":
		return StageLateralMovement
	case "TA0009":
		return StageCollection
	case "TA0011":
		return StageCommandControl
	case "TA0010":
		return StageExfiltration
	case "TA0040":
		return StageImpact
	default:
		return StageUnknown
	}
}

// EventV2 is the canonical event written to ClickHouse and consumed by the
// correlation service.
type EventV2 struct {
	SchemaVersion string             `json:"schema_version"`
	EventUID      string             `json:"event_uid"`
	CorrelationID string             `json:"correlation_id,omitempty"`
	TenantID      string             `json:"tenant_id"`
	Source        EventSource        `json:"source"`
	EventType     string             `json:"event_type"`
	Timestamps    EventTimestamps    `json:"timestamps"`
	Entities      Entities           `json:"entities"`
	Detection     Detection          `json:"detection"`
	Evidence      []EvidenceRef      `json:"evidence,omitempty"`
	Payload       json.RawMessage    `json:"payload,omitempty"`
	Raw           RawRef             `json:"raw"`
	QualityFlags  []QualityFlag      `json:"quality_flags,omitempty"`
	Governance    GovernanceMetadata `json:"governance"`
}

// Entities describes the security-relevant objects attached to an event.
type Entities struct {
	Asset   *AssetEntity   `json:"asset,omitempty"`
	User    *UserEntity    `json:"user,omitempty"`
	Process *ProcessEntity `json:"process,omitempty"`
	File    *FileEntity    `json:"file,omitempty"`
	Network *NetworkEntity `json:"network,omitempty"`
	App     *AppEntity     `json:"app,omitempty"`
}

type AssetEntity struct {
	ID          string   `json:"id"`
	IP          string   `json:"ip,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	OS          string   `json:"os,omitempty"`
	Criticality string   `json:"criticality,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type UserEntity struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Privilege string `json:"privilege,omitempty"`
}

type ProcessEntity struct {
	PID       int    `json:"pid,omitempty"`
	PPID      int    `json:"ppid,omitempty"`
	Exe       string `json:"exe,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Signer    string `json:"signer,omitempty"`
	User      string `json:"user,omitempty"`
	Session   string `json:"session,omitempty"`
	Container string `json:"container,omitempty"`
}

type FileEntity struct {
	Path   string `json:"path,omitempty"`
	Hash   string `json:"hash,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Signer string `json:"signer,omitempty"`
}

type NetworkEntity struct {
	SrcIP     string `json:"src_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	Proto     string `json:"proto,omitempty"`
	Direction string `json:"direction,omitempty"`
}

type AppEntity struct {
	Protocol  string `json:"protocol,omitempty"`
	Method    string `json:"method,omitempty"`
	Host      string `json:"host,omitempty"`
	URI       string `json:"uri,omitempty"`
	Status    int    `json:"status,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Detection carries the rule that produced the event and its ATT&CK mapping.
type Detection struct {
	RuleID        string        `json:"rule_id,omitempty"`
	RuleVersion   string        `json:"rule_version,omitempty"`
	RuleSource    string        `json:"rule_source,omitempty"`
	Severity      AlertSeverity `json:"severity"`
	Confidence    float64       `json:"confidence,omitempty"`
	TacticID      string        `json:"tactic_id,omitempty"`
	TechniqueID   string        `json:"technique_id,omitempty"`
	Stage         AttackStage   `json:"stage,omitempty"`
	Description   string        `json:"description,omitempty"`
	MappingSource string        `json:"mapping_source,omitempty"`
}

// EvidenceType names a retrievable evidence artifact.
type EvidenceType string

const (
	EvidencePCAP        EvidenceType = "pcap"
	EvidenceFlow        EvidenceType = "flow"
	EvidenceHTTP        EvidenceType = "http"
	EvidenceProcessTree EvidenceType = "process_tree"
	EvidenceFile        EvidenceType = "file"
	EvidenceLog         EvidenceType = "log"
	EvidenceRASP        EvidenceType = "rasp"
	EvidenceTI          EvidenceType = "ti"
)

func IsKnownEvidenceType(value EvidenceType) bool {
	switch value {
	case EvidencePCAP, EvidenceFlow, EvidenceHTTP, EvidenceProcessTree,
		EvidenceFile, EvidenceLog, EvidenceRASP, EvidenceTI:
		return true
	default:
		return false
	}
}

type EvidenceRef struct {
	Type       EvidenceType `json:"type"`
	Ref        string       `json:"ref"`
	SHA256     string       `json:"sha256,omitempty"`
	Size       int64        `json:"size,omitempty"`
	TTLSeconds int64        `json:"ttl_seconds,omitempty"`
	Redaction  string       `json:"redaction,omitempty"`
	CreatedAt  time.Time    `json:"created_at,omitempty"`
}

// RawRef points back to the native record that produced this event.
type RawRef struct {
	NativeSchema  string `json:"native_schema"`
	NativeEventID string `json:"native_event_id"`
	Adapter       string `json:"adapter"`
	PayloadSHA256 string `json:"payload_sha256"`
}

// Validate enforces the v2 contract. It does not mutate the event.
func (event EventV2) Validate() error {
	if event.SchemaVersion != SecurityEventSchemaV2 {
		return fmt.Errorf("security event v2: %w", ErrUnsupportedSchema)
	}
	if event.EventUID == "" || event.TenantID == "" || event.EventType == "" {
		return errors.New("security event v2: missing stable identity")
	}
	if !isKnownSource(event.Source) {
		return ErrInvalidEnum
	}
	if event.Timestamps.EventAt.IsZero() || event.Timestamps.ObservedAt.IsZero() || event.Timestamps.IngestedAt.IsZero() {
		return ErrMissingTimestamp
	}
	if !event.Entities.HasAny() {
		return errors.New("security event v2: at least one entity is required")
	}
	if !isKnownAlertSeverity(event.Detection.Severity) {
		return ErrInvalidEnum
	}
	if event.Detection.Confidence < 0 || event.Detection.Confidence > 1 {
		return errors.New("security event v2: confidence must be between 0 and 1")
	}
	if err := validateAttackTacticID(event.Detection.TacticID); err != nil {
		return err
	}
	if err := validateAttackTechniqueID(event.Detection.TechniqueID); err != nil {
		return err
	}
	if event.Detection.Stage != "" && !IsKnownAttackStage(event.Detection.Stage) {
		return ErrInvalidEnum
	}
	for _, evidence := range event.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
	}
	if err := event.Raw.Validate(); err != nil {
		return err
	}
	if err := validateQualityFlags(event.QualityFlags); err != nil {
		return err
	}
	if err := validateGovernanceV2(event.Governance); err != nil {
		return err
	}
	if len(event.Payload) > 0 {
		if err := validateCanonicalPayloadGovernance(event.Payload, event.Governance.RedactedFields); err != nil {
			return err
		}
	}
	return nil
}

func (entities Entities) HasAny() bool {
	return entities.Asset != nil || entities.User != nil || entities.Process != nil ||
		entities.File != nil || entities.Network != nil || entities.App != nil
}

func (evidence EvidenceRef) Validate() error {
	if !IsKnownEvidenceType(evidence.Type) {
		return ErrInvalidEnum
	}
	if strings.TrimSpace(evidence.Ref) == "" {
		return errors.New("security event v2: evidence ref required")
	}
	if (evidence.Type == EvidencePCAP || evidence.Type == EvidenceFile) && evidence.SHA256 == "" {
		return errors.New("security event v2: evidence hash required for pcap/file")
	}
	if evidence.Size < 0 || evidence.TTLSeconds < 0 {
		return errors.New("security event v2: evidence size/ttl must be non-negative")
	}
	return nil
}

func (raw RawRef) Validate() error {
	if strings.TrimSpace(raw.NativeSchema) == "" || strings.TrimSpace(raw.NativeEventID) == "" || strings.TrimSpace(raw.Adapter) == "" {
		return errors.New("security event v2: raw provenance required")
	}
	digest, err := hex.DecodeString(raw.PayloadSHA256)
	if err != nil || len(digest) != 32 {
		return errors.New("security event v2: raw payload digest invalid")
	}
	return nil
}

func validateQualityFlags(flags []QualityFlag) error {
	seen := make(map[QualityFlag]struct{}, len(flags))
	for _, flag := range flags {
		if !isKnownQualityFlag(flag) {
			return ErrInvalidEnum
		}
		if _, exists := seen[flag]; exists {
			return errors.New("security event v2: duplicate quality flag")
		}
		seen[flag] = struct{}{}
	}
	return nil
}

func validateGovernanceV2(governance GovernanceMetadata) error {
	if !isKnownClassification(governance.Classification) {
		return ErrInvalidEnum
	}
	if governance.Retention.PolicyID == "" || governance.Retention.ExpiresAt.IsZero() {
		return errors.New("security event v2: retention metadata required")
	}
	if !governance.Encryption.Required ||
		governance.Encryption.Algorithm != EncryptionAlgorithmAES256GCM ||
		governance.Encryption.KeyRef == "" {
		return errors.New("security event v2: encryption metadata required")
	}
	if governance.AccessPolicyID == "" || governance.DeletionPolicyID == "" || governance.ExportPolicyID == "" {
		return errors.New("security event v2: governance policy metadata invalid")
	}
	return nil
}

// FromCanonicalV1 adapts a validated v1 event into v2. It preserves identity,
// timestamps, provenance, attack mapping and governance, and synthesizes the
// asset entity from the v1 agent identity.
func FromCanonicalV1(v1 CanonicalSecurityEvent) (EventV2, error) {
	if err := v1.Validate(); err != nil {
		return EventV2{}, fmt.Errorf("adapt v1 event: %w", err)
	}
	stage := StageForTactic(v1.Attack.TacticID)
	event := EventV2{
		SchemaVersion: SecurityEventSchemaV2,
		EventUID:      v1.EventUID,
		CorrelationID: v1.CorrelationID,
		TenantID:      "default",
		Source:        v1.Provenance.Source,
		EventType:     v1.EventType,
		Timestamps:    v1.Timestamps,
		Entities: Entities{
			Asset: &AssetEntity{ID: v1.Identity.AgentID},
		},
		Detection: Detection{
			RuleID:        v1.EventType,
			RuleSource:    string(v1.Provenance.Source),
			Severity:      v1.Severity,
			Confidence:    0.5,
			TacticID:      v1.Attack.TacticID,
			TechniqueID:   v1.Attack.TechniqueID,
			Stage:         stage,
			Description:   v1.EventType,
			MappingSource: "v1_adapter",
		},
		Payload:      v1.Payload,
		QualityFlags: append([]QualityFlag(nil), v1.QualityFlags...),
		Raw: RawRef{
			NativeSchema:  v1.Provenance.NativeSchema,
			NativeEventID: v1.Provenance.NativeEventID,
			Adapter:       v1.Provenance.Adapter,
			PayloadSHA256: v1.Provenance.PayloadSHA256,
		},
		Governance: v1.Governance,
	}
	if err := event.Validate(); err != nil {
		return EventV2{}, err
	}
	return event, nil
}
