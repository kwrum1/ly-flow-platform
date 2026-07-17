package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/unified"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

func TestToUnifiedXDREventNormalizesMixedSignals(t *testing.T) {
	consumer := &ConsumerState{}
	timestamp := "2026-05-13T12:00:00Z"

	tests := []struct {
		name         string
		stream       string
		payload      map[string]interface{}
		wantModule   unified.ModuleType
		wantAction   string
		wantSeverity unified.Severity
	}{
		{
			name:   "semantic flow keeps business action",
			stream: unified.StreamFlowsSemantic,
			payload: map[string]interface{}{
				"id": "semantic-1", "flow_id": "flow-1", "timestamp": timestamp,
				"agent_id": "agent-1", "sensor_id": "agent-1", "hostname": "host-1",
				"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 54321, "dst_port": 8080,
				"business_action": "login", "risk_level": "medium", "severity": "medium", "source": "ly-agent-business-semantics",
			},
			wantModule:   unified.ModuleDPI,
			wantAction:   "login",
			wantSeverity: unified.SeverityMedium,
		},
		{
			name:   "runtime alert maps to runtime module",
			stream: unified.StreamAlertsRuntime,
			payload: map[string]interface{}{
				"type": "runtime.process.exec", "agent_id": "agent-1", "hostname": "host-1",
				"severity": "high", "mode": "monitor", "occurred_at": timestamp, "pid": 1234, "process": "bash",
			},
			wantModule:   unified.ModuleRuntime,
			wantAction:   "",
			wantSeverity: unified.SeverityHigh,
		},
		{
			name:   "rasp alert keeps attack type",
			stream: unified.StreamAlertsRASP,
			payload: map[string]interface{}{
				"agent_id": "agent-1", "hostname": "host-1", "attack_type": "sql_injection",
				"severity": "critical", "blocked": true, "language": "python", "timestamp": timestamp,
			},
			wantModule:   unified.ModuleRASP,
			wantAction:   "sql_injection",
			wantSeverity: unified.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := consumer.toUnifiedXDREvent(tt.stream, "1770000000000-0", tt.payload)
			if event.Module != tt.wantModule || event.SourceModule != tt.wantModule {
				t.Fatalf("module = %q/%q, want %q", event.Module, event.SourceModule, tt.wantModule)
			}
			if event.Severity != tt.wantSeverity {
				t.Fatalf("severity = %q, want %q", event.Severity, tt.wantSeverity)
			}
			if event.BehaviorContext == nil || event.BehaviorContext.Action != tt.wantAction {
				t.Fatalf("action = %+v, want %q", event.BehaviorContext, tt.wantAction)
			}
			if event.RawReference == nil || event.RawReference.Stream != tt.stream || event.RawReference.PayloadHash == "" {
				t.Fatalf("raw reference missing stream/hash: %+v", event.RawReference)
			}
			if event.Timestamp.Format(time.RFC3339) != timestamp {
				t.Fatalf("timestamp = %s, want %s", event.Timestamp.Format(time.RFC3339), timestamp)
			}
		})
	}
}

func TestBuildDeadLetterValuesKeepsSourceAndReason(t *testing.T) {
	values := buildDeadLetterValues(unified.StreamAlertsRuntime, "1-0", map[string]interface{}{"data": "{bad-json"}, errors.New("invalid json"))
	if values["source_stream"] != unified.StreamAlertsRuntime || values["source_message_id"] != "1-0" {
		t.Fatalf("source fields not preserved: %+v", values)
	}
	if values["reason"] != string(transport.ReasonHandlerRejected) || !strings.Contains(values["detail"].(string), "invalid json") {
		t.Fatalf("reason = %q", values["reason"])
	}
	if !json.Valid([]byte(values["raw"].(string))) {
		t.Fatalf("raw is not valid json: %q", values["raw"])
	}
}
