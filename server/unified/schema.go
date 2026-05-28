package unified

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	SchemaVersionV1 = "lyflow.stream.v1"

	StreamFlowsRaw         = "flows:raw"
	StreamFlowsSemantic    = "flows:semantic"
	StreamSessionsSemantic = "sessions:semantic"
	StreamAlertsDPI        = "alerts:dpi"
	StreamAlertsRuntime    = "alerts:runtime"
	StreamAlertsRASP       = "alerts:rasp"
	StreamAlertsXDR        = "alerts:xdr"
	StreamEventsXDR        = "events:xdr"
)

type StreamSchema struct {
	Name               string
	SchemaVersion      string
	PayloadTypes       []string
	RequiredDataFields []string
	OneOfDataFields    [][]string
	SeverityField      string
}

var streamSchemaRegistry = map[string]StreamSchema{
	StreamFlowsRaw: {
		Name:               StreamFlowsRaw,
		SchemaVersion:      SchemaVersionV1,
		PayloadTypes:       []string{"raw_flow"},
		RequiredDataFields: []string{"id", "timestamp", "sensor_id", "src_ip", "dst_ip", "protocol", "source"},
	},
	StreamFlowsSemantic: {
		Name:               StreamFlowsSemantic,
		SchemaVersion:      SchemaVersionV1,
		PayloadTypes:       []string{"semantic_flow"},
		RequiredDataFields: []string{"id", "flow_id", "timestamp", "agent_id", "sensor_id", "src_ip", "dst_ip", "business_action", "risk_level", "source"},
	},
	StreamSessionsSemantic: {
		Name:               StreamSessionsSemantic,
		SchemaVersion:      SchemaVersionV1,
		PayloadTypes:       []string{"semantic_session"},
		RequiredDataFields: []string{"id", "timestamp", "agent_id", "hostname", "business_action", "event_count", "mode", "risk_level", "source"},
	},
	StreamAlertsDPI: {
		Name:               StreamAlertsDPI,
		SchemaVersion:      SchemaVersionV1,
		PayloadTypes:       []string{"dpi_alert", "alert"},
		RequiredDataFields: []string{"type", "timestamp", "signature", "category", "severity", "status", "sensor_id"},
		SeverityField:      "severity",
	},
	StreamAlertsRuntime: {
		Name:               StreamAlertsRuntime,
		SchemaVersion:      SchemaVersionV1,
		RequiredDataFields: []string{"type", "agent_id", "hostname", "severity", "mode"},
		OneOfDataFields:    [][]string{{"occurred_at", "timestamp"}},
		SeverityField:      "severity",
	},
	StreamAlertsRASP: {
		Name:               StreamAlertsRASP,
		SchemaVersion:      SchemaVersionV1,
		RequiredDataFields: []string{"agent_id", "attack_type", "severity", "blocked", "language"},
		OneOfDataFields:    [][]string{{"occurred_at", "timestamp"}},
		SeverityField:      "severity",
	},
	StreamAlertsXDR: unifiedEventStreamSchema(StreamAlertsXDR),
	StreamEventsXDR: unifiedEventStreamSchema(StreamEventsXDR),
}

func unifiedEventStreamSchema(name string) StreamSchema {
	return StreamSchema{
		Name:               name,
		SchemaVersion:      SchemaVersionV1,
		RequiredDataFields: []string{"id", "module", "event_type", "source", "severity", "timestamp"},
		SeverityField:      "severity",
	}
}

func KnownStreamSchemas() []StreamSchema {
	names := make([]string, 0, len(streamSchemaRegistry))
	for name := range streamSchemaRegistry {
		names = append(names, name)
	}
	sort.Strings(names)

	schemas := make([]StreamSchema, 0, len(names))
	for _, name := range names {
		schemas = append(schemas, streamSchemaRegistry[name])
	}
	return schemas
}

func ValidateStreamPayload(stream string, entry map[string]interface{}) error {
	schema, ok := streamSchemaRegistry[stream]
	if !ok {
		return fmt.Errorf("stream %q: unknown stream schema", stream)
	}

	if len(schema.PayloadTypes) > 0 {
		if err := validatePayloadType(schema, entry); err != nil {
			return err
		}
	}

	payload, err := decodeStreamData(stream, entry)
	if err != nil {
		return err
	}

	for _, field := range schema.RequiredDataFields {
		if !hasMeaningfulValue(payload[field]) {
			return fmt.Errorf("stream %q data.%s: required field missing or empty", stream, field)
		}
	}

	for _, alternatives := range schema.OneOfDataFields {
		if !hasAnyMeaningfulValue(payload, alternatives) {
			return fmt.Errorf("stream %q data.%s: one of these fields is required", stream, strings.Join(alternatives, "|"))
		}
	}

	if schema.SeverityField != "" {
		if err := validateSeverity(stream, schema.SeverityField, payload[schema.SeverityField]); err != nil {
			return err
		}
	}

	return nil
}

func validatePayloadType(schema StreamSchema, entry map[string]interface{}) error {
	rawType, ok := entry["type"]
	if !ok || !hasMeaningfulValue(rawType) {
		return fmt.Errorf("stream %q type: required field missing or empty", schema.Name)
	}
	payloadType, ok := rawType.(string)
	if !ok {
		return fmt.Errorf("stream %q type: expected string", schema.Name)
	}
	for _, allowed := range schema.PayloadTypes {
		if payloadType == allowed {
			return nil
		}
	}
	return fmt.Errorf("stream %q type: %q is not one of %s", schema.Name, payloadType, strings.Join(schema.PayloadTypes, ","))
}

func decodeStreamData(stream string, entry map[string]interface{}) (map[string]interface{}, error) {
	rawData, ok := entry["data"]
	if !ok || !hasMeaningfulValue(rawData) {
		return nil, fmt.Errorf("stream %q data: required field missing or empty", stream)
	}
	data, ok := rawData.(string)
	if !ok {
		return nil, fmt.Errorf("stream %q data: expected JSON string", stream)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, fmt.Errorf("stream %q data: invalid JSON: %w", stream, err)
	}
	return payload, nil
}

func hasAnyMeaningfulValue(payload map[string]interface{}, fields []string) bool {
	for _, field := range fields {
		if hasMeaningfulValue(payload[field]) {
			return true
		}
	}
	return false
}

func hasMeaningfulValue(value interface{}) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	default:
		return true
	}
}

func validateSeverity(stream, field string, value interface{}) error {
	switch typed := value.(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "critical", "high", "medium", "low", "info":
			return nil
		default:
			return fmt.Errorf("stream %q data.%s: invalid severity %q", stream, field, typed)
		}
	case float64:
		if typed >= 1 && typed <= 4 {
			return nil
		}
		return fmt.Errorf("stream %q data.%s: numeric severity must be 1-4", stream, field)
	case int:
		if typed >= 1 && typed <= 4 {
			return nil
		}
		return fmt.Errorf("stream %q data.%s: numeric severity must be 1-4", stream, field)
	default:
		return fmt.Errorf("stream %q data.%s: expected string or numeric severity", stream, field)
	}
}
