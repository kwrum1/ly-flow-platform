package contracts

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLegacyContractFixturesRemainAPICompatible(t *testing.T) {
	observed := time.Date(2026, 7, 13, 9, 59, 0, 0, time.UTC)
	telemetry := TelemetryEnvelope{SchemaVersion: TelemetrySchemaVersion, ID: "telemetry-1", Category: TelemetryRuntime, EventType: "runtime.process", ObservedAt: observed, Source: "agent", SourceEngine: SourceEngineRuntime, Entities: EntityRef{AgentID: "agent-1"}}
	alert := ComponentAlert{SchemaVersion: ComponentAlertSchemaVersion, ID: "alert-1", Category: TelemetryRuntime, SourceEngine: SourceEngineRuntime, RuleID: "rule-1", RuleName: "Runtime rule", Severity: SeverityHigh, ScoreHint: 80, OccurredAt: observed, Source: "security-engine", Summary: "runtime alert"}

	for _, value := range []interface{}{telemetry, alert} {
		encoded, err := json.Marshal(value)
		if err != nil || !json.Valid(encoded) {
			t.Fatalf("legacy fixture API changed: %s (%v)", encoded, err)
		}
	}
}
