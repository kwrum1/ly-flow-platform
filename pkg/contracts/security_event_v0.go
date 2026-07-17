package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

type legacySourcePayloadV0 struct {
	ID           string          `json:"id"`
	Agent        string          `json:"agent"`
	Type         string          `json:"type"`
	EventTime    json.RawMessage `json:"event_time"`
	ObservedTime json.RawMessage `json:"observed_time"`
	Level        AlertSeverity   `json:"level"`
	Correlation  string          `json:"correlation,omitempty"`
	Tactic       string          `json:"tactic,omitempty"`
	Technique    string          `json:"technique,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
}

type canonicalSecurityEventV0 struct {
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

func decodeVersionedSourcePayload(input SourceFixture, data []byte) (normalizedSourceRecord, string, string, error) {
	if input.SchemaVersion == SecurityEventSchemaVersion && input.NativeSchema != "" {
		return decodeNativeSourceRecord(input.Source, input.NativeSchema, data)
	}
	if input.SchemaVersion == SecurityEventSchemaVersion {
		var payload normalizedSourceRecord
		if err := decodeStrictJSON(data, &payload); err != nil {
			return normalizedSourceRecord{}, "", "", err
		}
		return payload, "contracts.v1SourceAdapter", SecurityEventSchemaVersion, nil
	}
	var legacy legacySourcePayloadV0
	if err := decodeStrictJSON(data, &legacy); err != nil {
		return normalizedSourceRecord{}, "", "", err
	}
	var eventAt, observedAt jsonTime
	if err := json.Unmarshal(legacy.EventTime, &eventAt); err != nil {
		return normalizedSourceRecord{}, "", "", fmt.Errorf("decode v0 event_time: %w", err)
	}
	if err := json.Unmarshal(legacy.ObservedTime, &observedAt); err != nil {
		return normalizedSourceRecord{}, "", "", fmt.Errorf("decode v0 observed_time: %w", err)
	}
	return normalizedSourceRecord{EventID: legacy.ID, AgentID: legacy.Agent, EventType: legacy.Type, EventAt: eventAt.Time,
		ObservedAt: observedAt.Time, Severity: legacy.Level, Correlation: legacy.Correlation, TacticID: legacy.Tactic,
		TechniqueID: legacy.Technique, Details: legacy.Data}, "contracts.v0SourceAdapter", LegacySecurityEventSchemaVersion, nil
}

func decodeVersionedCanonical(version string, data []byte) (CanonicalSecurityEvent, error) {
	if version == SecurityEventSchemaVersion {
		var event CanonicalSecurityEvent
		if err := decodeStrictJSON(data, &event); err != nil {
			return CanonicalSecurityEvent{}, err
		}
		return event, nil
	}
	var legacy canonicalSecurityEventV0
	if err := decodeStrictJSON(data, &legacy); err != nil {
		return CanonicalSecurityEvent{}, err
	}
	flags := append([]QualityFlag(nil), legacy.QualityFlags...)
	if !hasQualityFlag(flags, QualityLegacyAdapted) {
		flags = append(flags, QualityLegacyAdapted)
	}
	legacy.Provenance.Adapter = "contracts.v0CanonicalAdapter"
	return CanonicalSecurityEvent{SchemaVersion: SecurityEventSchemaVersion, EventUID: legacy.EventUID,
		CorrelationID: legacy.CorrelationID, EventType: legacy.EventType, Severity: legacy.Severity,
		Identity: legacy.Identity, Timestamps: legacy.Timestamps, Provenance: legacy.Provenance,
		Attack: legacy.Attack, QualityFlags: flags, Governance: legacy.Governance, Payload: legacy.Payload}, nil
}

func decodeStrictJSON(data []byte, destination interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

type jsonTime struct{ Time time.Time }

func (value *jsonTime) UnmarshalJSON(data []byte) error { return json.Unmarshal(data, &value.Time) }

func hasQualityFlag(flags []QualityFlag, expected QualityFlag) bool {
	for _, flag := range flags {
		if flag == expected {
			return true
		}
	}
	return false
}
