package contracts

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

const (
	NativeTelemetryV1      = "lyflow.telemetry.v1"
	NativeComponentAlertV1 = "lyflow.component_alert.v1"
	NativeSuricataEVE      = "suricata.eve.v7"
	NativeWazuhAlert       = "wazuh.alert.v4"
	NativeYARAMatch        = "yara.match.v1"
	NativeDPIAlert         = "lyflow.dpi_alert.v1"
	NativeUnifiedEvent     = "lyflow.unified.v1"
	NativeXDREventV2       = "xdr-eval.v2"
)

type nativeSuricataEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	Alert     struct {
		SignatureID int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
	AgentID string `json:"agent_id"`
}

type nativeWazuhEvent struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Agent     struct {
		ID string `json:"id"`
	} `json:"agent"`
	Rule struct {
		ID          string `json:"id"`
		Level       int    `json:"level"`
		Description string `json:"description"`
	} `json:"rule"`
	FullLog string `json:"full_log"`
}

type nativeYARAEvent struct {
	MatchID   string    `json:"match_id"`
	AgentID   string    `json:"agent_id"`
	Rule      string    `json:"rule"`
	Namespace string    `json:"namespace"`
	FilePath  string    `json:"file_path"`
	FileHash  string    `json:"file_hash"`
	Tags      []string  `json:"tags"`
	MatchedAt time.Time `json:"matched_at"`
}

type nativeUnifiedEvent struct {
	ID             string        `json:"id"`
	EventType      string        `json:"event_type"`
	Severity       AlertSeverity `json:"severity"`
	Timestamp      time.Time     `json:"timestamp"`
	CreatedAt      time.Time     `json:"created_at"`
	AgentID        string        `json:"agent_id"`
	MitreTactic    string        `json:"mitre_tactic"`
	MitreTechnique string        `json:"mitre_technique"`
}

type nativeXDREvent struct {
	EventUID        string    `json:"event_uid"`
	AgentID         string    `json:"agent_id"`
	ObservedAt      time.Time `json:"observed_at"`
	IngestedAt      time.Time `json:"ingested_at"`
	EventType       string    `json:"event_type"`
	TechniqueID     string    `json:"technique_id"`
	TacticID        string    `json:"tactic_id"`
	RiskScore       float64   `json:"risk_score"`
	SourceComponent string    `json:"source_component"`
}

func decodeNativeSourceRecord(source EventSource, schema string, data []byte) (normalizedSourceRecord, string, string, error) {
	switch source {
	case SourceAgentTraffic, SourceAgentRuntime, SourceAgentLogAudit, SourceAgentRASP:
		return decodeNativeTelemetry(source, schema, data)
	case SourceSuricata:
		var value nativeSuricataEvent
		if err := decodeExpectedNative(schema, NativeSuricataEVE, data, &value); err != nil {
			return normalizedSourceRecord{}, "", "", err
		}
		occurredAt, err := time.Parse(time.RFC3339Nano, value.Timestamp)
		if err != nil {
			return normalizedSourceRecord{}, "", "", fmt.Errorf("parse Suricata timestamp: %w", err)
		}
		return nativeRecord(strconv.Itoa(value.Alert.SignatureID), value.AgentID, "network.signature", occurredAt, suricataNativeSeverity(value.Alert.Severity), data, "", ""), "contracts.suricataEVEAdapter", schema, nil
	case SourceWazuh:
		var value nativeWazuhEvent
		if err := decodeExpectedNative(schema, NativeWazuhAlert, data, &value); err != nil {
			return normalizedSourceRecord{}, "", "", err
		}
		occurredAt, err := time.Parse(time.RFC3339Nano, value.Timestamp)
		if err != nil {
			return normalizedSourceRecord{}, "", "", fmt.Errorf("parse Wazuh timestamp: %w", err)
		}
		return nativeRecord(value.ID, value.Agent.ID, "host.rule", occurredAt, wazuhNativeSeverity(value.Rule.Level), data, "", ""), "contracts.wazuhAlertAdapter", schema, nil
	case SourceYARA:
		var value nativeYARAEvent
		if err := decodeExpectedNative(schema, NativeYARAMatch, data, &value); err != nil {
			return normalizedSourceRecord{}, "", "", err
		}
		return nativeRecord(value.MatchID, value.AgentID, "artifact.match", value.MatchedAt, SeverityHigh, data, "", ""), "contracts.yaraMatchAdapter", schema, nil
	case SourceDPIEngine:
		return decodeNativeDPIAlert(schema, data)
	case SourceSecurityEngine:
		var value ComponentAlert
		if err := decodeExpectedNative(schema, NativeComponentAlertV1, data, &value); err != nil {
			return normalizedSourceRecord{}, "", "", err
		}
		if err := value.Validate(); err != nil {
			return normalizedSourceRecord{}, "", "", err
		}
		return nativeRecord(value.ID, value.Entities.AgentID, "component.alert", value.OccurredAt, value.Severity, data, "", ""), "contracts.componentAlertAdapter", schema, nil
	case SourceUnifiedLegacy:
		var value nativeUnifiedEvent
		if err := decodeExpectedNative(schema, NativeUnifiedEvent, data, &value); err != nil {
			return normalizedSourceRecord{}, "", "", err
		}
		return nativeRecord(value.ID, value.AgentID, value.EventType, value.Timestamp, value.Severity, data, value.MitreTactic, value.MitreTechnique), "contracts.unifiedEventAdapter", schema, nil
	case SourceXDRV2:
		var value nativeXDREvent
		if err := decodeExpectedNative(schema, NativeXDREventV2, data, &value); err != nil {
			return normalizedSourceRecord{}, "", "", err
		}
		return nativeRecord(value.EventUID, value.AgentID, value.EventType, value.ObservedAt, riskSeverity(value.RiskScore), data, value.TacticID, value.TechniqueID), "contracts.xdrV2Adapter", schema, nil
	default:
		return normalizedSourceRecord{}, "", "", ErrInvalidEnum
	}
}

func decodeNativeTelemetry(source EventSource, schema string, data []byte) (normalizedSourceRecord, string, string, error) {
	var value TelemetryEnvelope
	if err := decodeExpectedNative(schema, NativeTelemetryV1, data, &value); err != nil {
		return normalizedSourceRecord{}, "", "", err
	}
	if err := value.Validate(); err != nil || sourceForTelemetry(value) != source {
		return normalizedSourceRecord{}, "", "", ErrInvalidEnum
	}
	severity := SeverityLow
	if raw, ok := value.Fields["severity"].(string); ok && isKnownAlertSeverity(AlertSeverity(raw)) {
		severity = AlertSeverity(raw)
	}
	return nativeRecord(value.ID, value.Entities.AgentID, value.EventType, value.ObservedAt, severity, data, "", ""), "contracts.telemetryEnvelopeAdapter", schema, nil
}

func decodeExpectedNative(actual, expected string, data []byte, destination interface{}) error {
	if actual != expected {
		return fmt.Errorf("native schema %s, expected %s: %w", actual, expected, ErrUnsupportedSchema)
	}
	return decodeStrictJSON(data, destination)
}

func nativeRecord(id, agentID, eventType string, occurredAt time.Time, severity AlertSeverity, details []byte, tactic, technique string) normalizedSourceRecord {
	return normalizedSourceRecord{EventID: id, AgentID: agentID, EventType: eventType, EventAt: occurredAt,
		ObservedAt: occurredAt, Severity: severity, TacticID: tactic, TechniqueID: technique, Details: append(json.RawMessage(nil), details...)}
}

func suricataNativeSeverity(value int) AlertSeverity {
	if value <= 1 {
		return SeverityCritical
	}
	if value == 2 {
		return SeverityHigh
	}
	if value == 3 {
		return SeverityMedium
	}
	return SeverityLow
}
func wazuhNativeSeverity(value int) AlertSeverity {
	if value >= 12 {
		return SeverityCritical
	}
	if value >= 8 {
		return SeverityHigh
	}
	if value >= 4 {
		return SeverityMedium
	}
	return SeverityLow
}
func riskSeverity(value float64) AlertSeverity {
	if value >= 90 {
		return SeverityCritical
	}
	if value >= 70 {
		return SeverityHigh
	}
	if value >= 40 {
		return SeverityMedium
	}
	return SeverityLow
}
