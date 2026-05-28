package unified

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKnownStreamSchemasCoversArchitectureStreams(t *testing.T) {
	want := map[string]bool{
		StreamFlowsRaw:         false,
		StreamFlowsSemantic:    false,
		StreamSessionsSemantic: false,
		StreamAlertsDPI:        false,
		StreamAlertsRuntime:    false,
		StreamAlertsRASP:       false,
		StreamAlertsXDR:        false,
		StreamEventsXDR:        false,
	}

	for _, schema := range KnownStreamSchemas() {
		if _, ok := want[schema.Name]; ok {
			want[schema.Name] = true
		}
		if schema.SchemaVersion != SchemaVersionV1 {
			t.Fatalf("schema %s version = %q, want %q", schema.Name, schema.SchemaVersion, SchemaVersionV1)
		}
	}

	for stream, found := range want {
		if !found {
			t.Fatalf("missing schema for %s", stream)
		}
	}
}

func TestValidateStreamPayloadAcceptsKnownGoodSamples(t *testing.T) {
	tests := []struct {
		name   string
		stream string
		entry  map[string]interface{}
	}{
		{
			name:   "raw flow",
			stream: StreamFlowsRaw,
			entry: streamEntry("raw_flow", map[string]interface{}{
				"id": "flow-1", "timestamp": "2026-05-13T01:00:00Z", "sensor_id": "agent-1",
				"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP", "source": "ly-agent-packet-capture",
			}),
		},
		{
			name:   "semantic flow",
			stream: StreamFlowsSemantic,
			entry: streamEntry("semantic_flow", map[string]interface{}{
				"id": "semantic-flow-1", "flow_id": "flow-1", "timestamp": "2026-05-13T01:00:00Z",
				"agent_id": "agent-1", "sensor_id": "agent-1", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
				"business_action": "login", "risk_level": "low", "source": "ly-agent-business-semantics",
			}),
		},
		{
			name:   "semantic session",
			stream: StreamSessionsSemantic,
			entry: streamEntry("semantic_session", map[string]interface{}{
				"id": "session-1", "timestamp": "2026-05-13T01:00:00Z", "agent_id": "agent-1",
				"hostname": "host-1", "business_action": "login", "event_count": 1, "mode": "behavior_aggregate",
				"risk_level": "low", "source": "ly-agent-session-aggregate",
			}),
		},
		{
			name:   "dpi alert",
			stream: StreamAlertsDPI,
			entry: streamEntry("dpi_alert", map[string]interface{}{
				"type": "dpi", "timestamp": "2026-05-13T01:00:00Z", "signature": "DomainAudit.suspicious",
				"category": "suspicious", "severity": 3, "status": "new", "sensor_id": "agent-1",
			}),
		},
		{
			name:   "runtime alert",
			stream: StreamAlertsRuntime,
			entry: streamEntry("", map[string]interface{}{
				"type": "runtime.monitor.sample", "agent_id": "agent-1", "hostname": "host-1",
				"severity": "low", "mode": "monitor", "occurred_at": "2026-05-13T01:00:00Z",
			}),
		},
		{
			name:   "rasp alert",
			stream: StreamAlertsRASP,
			entry: streamEntry("", map[string]interface{}{
				"agent_id": "agent-1", "attack_type": "sql_injection", "severity": "medium",
				"blocked": false, "language": "python", "timestamp": "2026-05-13T01:00:00Z",
			}),
		},
		{
			name:   "events xdr",
			stream: StreamEventsXDR,
			entry: streamEntry("", map[string]interface{}{
				"id": "evt-1", "module": "dpi", "event_type": "flows:semantic.event",
				"source": "ly-agent-business-semantics", "severity": "low", "timestamp": "2026-05-13T01:00:00Z",
			}),
		},
		{
			name:   "alerts xdr",
			stream: StreamAlertsXDR,
			entry: streamEntry("", map[string]interface{}{
				"id": "xdr-1", "module": "xdr", "event_type": "xdr.behavior_chain.alert",
				"source": "lyflow-xdr", "severity": "high", "timestamp": "2026-05-13T01:00:00Z",
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateStreamPayload(tt.stream, tt.entry); err != nil {
				t.Fatalf("ValidateStreamPayload() error = %v", err)
			}
		})
	}
}

func TestValidateStreamPayloadRejectsMissingRequiredSeverity(t *testing.T) {
	entry := streamEntry("", map[string]interface{}{
		"id": "xdr-1", "module": "xdr", "event_type": "xdr.behavior_chain.alert",
		"source": "lyflow-xdr", "timestamp": "2026-05-13T01:00:00Z",
	})

	err := ValidateStreamPayload(StreamAlertsXDR, entry)
	if err == nil {
		t.Fatal("expected missing severity error, got nil")
	}
	if !strings.Contains(err.Error(), "data.severity") {
		t.Fatalf("error = %q, want data.severity path", err.Error())
	}
}

func TestValidateStreamPayloadRejectsInvalidPayloadType(t *testing.T) {
	entry := streamEntry("wrong_type", map[string]interface{}{
		"id": "flow-1", "timestamp": "2026-05-13T01:00:00Z", "sensor_id": "agent-1",
		"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP", "source": "ly-agent-packet-capture",
	})

	err := ValidateStreamPayload(StreamFlowsRaw, entry)
	if err == nil {
		t.Fatal("expected invalid type error, got nil")
	}
	if !strings.Contains(err.Error(), "wrong_type") {
		t.Fatalf("error = %q, want invalid type value", err.Error())
	}
}

func streamEntry(payloadType string, payload map[string]interface{}) map[string]interface{} {
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	entry := map[string]interface{}{"data": string(data)}
	if payloadType != "" {
		entry["type"] = payloadType
	}
	return entry
}
