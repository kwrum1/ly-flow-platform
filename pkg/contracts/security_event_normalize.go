package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrUnsupportedSchema = errors.New("unsupported schema")
	ErrIdentityConflict  = errors.New("payload identity conflicts with authenticated principal")
	ErrMissingIdentity   = errors.New("missing identity")
	ErrMissingTimestamp  = errors.New("missing timestamp")
	ErrInvalidEnum       = errors.New("invalid enum")
	ErrInvalidField      = errors.New("invalid field")
)

type QuarantineReason string

const (
	QuarantineMalformed        QuarantineReason = "malformed_input"
	QuarantineMissingIdentity  QuarantineReason = "missing_identity"
	QuarantineMissingTimestamp QuarantineReason = "missing_timestamp"
	QuarantineFutureSchema     QuarantineReason = "future_schema"
	QuarantineInvalidEnum      QuarantineReason = "invalid_enum"
	QuarantineInvalidField     QuarantineReason = "invalid_field"
	QuarantineIdentityConflict QuarantineReason = "identity_conflict"
)

type QuarantineError struct {
	Reason QuarantineReason
	Source EventSource
	Err    error
}

func (err *QuarantineError) Error() string {
	return fmt.Sprintf("quarantine %s from %s: %v", err.Reason, err.Source, err.Err)
}

func (err *QuarantineError) Unwrap() error { return err.Err }

type WarningCode string

const WarningOldSchema WarningCode = "old_schema"

type ContractWarning struct {
	Code    WarningCode `json:"code"`
	Message string      `json:"message"`
}

type SourceFixture struct {
	Source        EventSource     `json:"source"`
	SchemaVersion string          `json:"schema_version"`
	NativeSchema  string          `json:"native_schema,omitempty"`
	Payload       json.RawMessage `json:"payload"`
}

type normalizedSourceRecord struct {
	EventID     string          `json:"event_id"`
	AgentID     string          `json:"agent_id"`
	EventType   string          `json:"event_type"`
	EventAt     time.Time       `json:"event_at"`
	ObservedAt  time.Time       `json:"observed_at,omitempty"`
	Severity    AlertSeverity   `json:"severity"`
	Correlation string          `json:"correlation_id,omitempty"`
	TacticID    string          `json:"tactic_id,omitempty"`
	TechniqueID string          `json:"technique_id,omitempty"`
	Details     json.RawMessage `json:"details,omitempty"`
}

func NormalizeFixture(input SourceFixture, principal PrincipalIdentity, ingestedAt time.Time) (CanonicalSecurityEvent, []ContractWarning, error) {
	warnings, err := negotiateSchema(input.Source, input.SchemaVersion)
	if err != nil {
		return CanonicalSecurityEvent{}, nil, err
	}
	if !isKnownSource(input.Source) {
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, QuarantineInvalidEnum, ErrInvalidEnum)
	}

	payload, adapter, nativeSchema, err := decodeVersionedSourcePayload(input, input.Payload)
	if err != nil {
		reason := QuarantineMalformed
		if strings.Contains(err.Error(), "unknown field") {
			reason = QuarantineInvalidField
		}
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, reason, errors.Join(ErrInvalidField, err))
	}
	if payload.AgentID == "" || principal == "" {
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, QuarantineMissingIdentity, ErrMissingIdentity)
	}
	if payload.AgentID != string(principal) {
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, QuarantineIdentityConflict, ErrIdentityConflict)
	}
	if payload.EventAt.IsZero() || payload.ObservedAt.IsZero() {
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, QuarantineMissingTimestamp, ErrMissingTimestamp)
	}
	if payload.EventID == "" || payload.EventType == "" {
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, QuarantineMalformed, errors.New("missing event identity"))
	}
	if !isKnownAlertSeverity(payload.Severity) {
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, QuarantineInvalidEnum, ErrInvalidEnum)
	}

	redacted, fields, err := RedactJSON(payload.Details)
	if err != nil {
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, QuarantineMalformed, err)
	}
	eventUID := DeterministicEventUID(input.Source, payload.AgentID, payload.EventID)
	correlationID := payload.Correlation
	if correlationID == "" {
		correlationID = "corr-" + strings.TrimPrefix(eventUID, "evt-")
	}
	flags := []QualityFlag{QualityNormalized, QualityPrincipalBound}
	if input.SchemaVersion == LegacySecurityEventSchemaVersion {
		flags = append(flags, QualityLegacyAdapted)
	}
	digest := sha256.Sum256(input.Payload)
	event := CanonicalSecurityEvent{
		SchemaVersion: SecurityEventSchemaVersion,
		EventUID:      eventUID,
		CorrelationID: correlationID,
		EventType:     payload.EventType,
		Severity:      payload.Severity,
		Identity:      SourceIdentity{PrincipalID: string(principal), AgentID: string(principal), Component: string(input.Source)},
		Timestamps:    EventTimestamps{EventAt: payload.EventAt.UTC(), ObservedAt: payload.ObservedAt.UTC(), IngestedAt: ingestedAt.UTC()},
		Provenance: EventProvenance{Source: input.Source, NativeSchema: nativeSchema, NativeEventID: payload.EventID,
			Adapter: adapter, PayloadSHA256: hex.EncodeToString(digest[:])},
		Attack:       AttackMapping{TacticID: payload.TacticID, TechniqueID: payload.TechniqueID, Version: AttackMappingVersion},
		QualityFlags: flags,
		Governance: GovernanceMetadata{
			Classification: ClassificationRestricted,
			Retention:      RetentionPolicy{PolicyID: RetentionPolicySecurityEvent30D, ExpiresAt: ingestedAt.UTC().Add(30 * 24 * time.Hour)},
			Encryption:     EncryptionMetadata{Required: true, Algorithm: EncryptionAlgorithmAES256GCM, KeyRef: "event-data-current"},
			AccessPolicyID: AccessPolicySecurityEventRead, DeletionPolicyID: DeletionPolicySecurityEvent, ExportPolicyID: ExportPolicySecurityEvent, RedactedFields: fields,
		},
		Payload: redacted,
	}
	if err := event.Validate(); err != nil {
		return CanonicalSecurityEvent{}, nil, quarantine(input.Source, QuarantineMalformed, err)
	}
	return event, warnings, nil
}

func ParseCanonical(data []byte, principal PrincipalIdentity) (CanonicalSecurityEvent, []ContractWarning, error) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return CanonicalSecurityEvent{}, nil, quarantine("canonical", QuarantineMalformed, err)
	}
	warnings, err := negotiateSchema("canonical", header.SchemaVersion)
	if err != nil {
		return CanonicalSecurityEvent{}, nil, err
	}
	event, err := decodeVersionedCanonical(header.SchemaVersion, data)
	if err != nil {
		return CanonicalSecurityEvent{}, nil, quarantine("canonical", QuarantineInvalidField, err)
	}
	if principal == "" {
		return CanonicalSecurityEvent{}, nil, quarantine("canonical", QuarantineMissingIdentity, ErrMissingIdentity)
	}
	if event.Identity.PrincipalID != string(principal) || event.Identity.AgentID != string(principal) {
		return CanonicalSecurityEvent{}, nil, quarantine("canonical", QuarantineIdentityConflict, ErrIdentityConflict)
	}
	if err := event.Validate(); err != nil {
		return CanonicalSecurityEvent{}, nil, quarantine("canonical", QuarantineMalformed, err)
	}
	return event, warnings, nil
}

func DeterministicEventUID(source EventSource, principalID, nativeEventID string) string {
	digest := sha256.Sum256([]byte(string(source) + "\x00" + principalID + "\x00" + nativeEventID))
	return "evt-" + hex.EncodeToString(digest[:16])
}

func negotiateSchema(source EventSource, version string) ([]ContractWarning, error) {
	switch version {
	case SecurityEventSchemaVersion:
		return nil, nil
	case LegacySecurityEventSchemaVersion:
		return []ContractWarning{{Code: WarningOldSchema, Message: "legacy security event schema normalized; upgrade producer"}}, nil
	default:
		return nil, quarantine(source, QuarantineFutureSchema, fmt.Errorf("%s: %w", version, ErrUnsupportedSchema))
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func quarantine(source EventSource, reason QuarantineReason, err error) error {
	return &QuarantineError{Reason: reason, Source: source, Err: err}
}
