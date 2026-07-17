package contracts

import (
	"encoding/json"
	"fmt"
	"time"
)

func (envelope TelemetryEnvelope) Canonical(principal PrincipalIdentity, ingestedAt time.Time) (CanonicalSecurityEvent, error) {
	if err := envelope.Validate(); err != nil {
		return CanonicalSecurityEvent{}, fmt.Errorf("normalize telemetry envelope: %w", err)
	}
	details, err := json.Marshal(struct {
		Fields  map[string]interface{} `json:"fields,omitempty"`
		Excerpt string                 `json:"excerpt,omitempty"`
		Labels  []string               `json:"labels,omitempty"`
	}{Fields: envelope.Fields, Excerpt: envelope.Excerpt, Labels: envelope.Labels})
	if err != nil {
		return CanonicalSecurityEvent{}, fmt.Errorf("marshal telemetry details: %w", err)
	}
	payload, err := json.Marshal(normalizedSourceRecord{
		EventID: envelope.ID, AgentID: envelope.Entities.AgentID, EventType: envelope.EventType,
		EventAt: envelope.ObservedAt, ObservedAt: envelope.ObservedAt, Severity: SeverityLow, Details: details,
	})
	if err != nil {
		return CanonicalSecurityEvent{}, fmt.Errorf("marshal telemetry adapter payload: %w", err)
	}
	event, _, err := NormalizeFixture(SourceFixture{Source: sourceForTelemetry(envelope), SchemaVersion: SecurityEventSchemaVersion, Payload: payload}, principal, ingestedAt)
	if err != nil {
		return CanonicalSecurityEvent{}, fmt.Errorf("normalize telemetry adapter payload: %w", err)
	}
	event.Provenance.NativeSchema = envelope.SchemaVersion
	event.Provenance.Adapter = "contracts.TelemetryEnvelope.Canonical"
	return event, nil
}

func (alert ComponentAlert) Canonical(principal PrincipalIdentity, ingestedAt time.Time) (CanonicalSecurityEvent, error) {
	if err := alert.Validate(); err != nil {
		return CanonicalSecurityEvent{}, fmt.Errorf("normalize component alert: %w", err)
	}
	details, err := json.Marshal(struct {
		RuleID      string                 `json:"rule_id"`
		RuleName    string                 `json:"rule_name"`
		Summary     string                 `json:"summary"`
		Details     map[string]interface{} `json:"details,omitempty"`
		Evidence    []RawReference         `json:"evidence_refs,omitempty"`
		PolicyState PolicyState            `json:"policy_state,omitempty"`
	}{RuleID: alert.RuleID, RuleName: alert.RuleName, Summary: alert.Summary, Details: alert.Details, Evidence: alert.EvidenceRefs, PolicyState: alert.PolicyState})
	if err != nil {
		return CanonicalSecurityEvent{}, fmt.Errorf("marshal component alert details: %w", err)
	}
	payload, err := json.Marshal(normalizedSourceRecord{
		EventID: alert.ID, AgentID: alert.Entities.AgentID, EventType: "component.alert",
		EventAt: alert.OccurredAt, ObservedAt: alert.OccurredAt, Severity: alert.Severity,
		Correlation: alert.Entities.TraceID, Details: details,
	})
	if err != nil {
		return CanonicalSecurityEvent{}, fmt.Errorf("marshal component alert adapter payload: %w", err)
	}
	event, _, err := NormalizeFixture(SourceFixture{Source: sourceForComponentAlert(alert), SchemaVersion: SecurityEventSchemaVersion, Payload: payload}, principal, ingestedAt)
	if err != nil {
		return CanonicalSecurityEvent{}, fmt.Errorf("normalize component alert adapter payload: %w", err)
	}
	event.Provenance.NativeSchema = alert.SchemaVersion
	event.Provenance.Adapter = "contracts.ComponentAlert.Canonical"
	return event, nil
}

func sourceForTelemetry(envelope TelemetryEnvelope) EventSource {
	switch envelope.Category {
	case TelemetryTraffic, TelemetryNetwork:
		return SourceAgentTraffic
	case TelemetryRuntime, TelemetryHost:
		return SourceAgentRuntime
	case TelemetryLog, TelemetryLogAudit:
		return SourceAgentLogAudit
	case TelemetryRASP:
		return SourceAgentRASP
	case TelemetryArtifact:
		return SourceYARA
	default:
		return SourceSecurityEngine
	}
}

func sourceForComponentAlert(alert ComponentAlert) EventSource {
	switch alert.SourceEngine {
	case SourceEngineSuricata:
		return SourceSuricata
	case SourceEngineDPIEngine:
		return SourceDPIEngine
	case SourceEngineWazuh:
		return SourceWazuh
	case SourceEngineYARA:
		return SourceYARA
	case SourceEngineRASP:
		return SourceAgentRASP
	case SourceEngineRuntime, SourceEngineAgent:
		return SourceAgentRuntime
	case SourceEngineLogAudit:
		return SourceAgentLogAudit
	case SourceEngineLyFlow, SourceEngineSigma, "":
		return SourceSecurityEngine
	default:
		return SourceSecurityEngine
	}
}
