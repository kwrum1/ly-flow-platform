package contracts

import (
	"testing"
	"time"
)

func TestTelemetryEnvelopeValidate(t *testing.T) {
	env := TelemetryEnvelope{SchemaVersion: TelemetrySchemaVersion, ID: "t1", Category: TelemetryRASP, EventType: "rasp.sql", ObservedAt: time.Now(), Source: "java-probe", SourceEngine: SourceEngineRASP, Entities: EntityRef{AgentID: "agent-1"}}
	if err := env.Validate(); err != nil {
		t.Fatalf("valid telemetry rejected: %v", err)
	}
	env.Category = "unknown"
	if err := env.Validate(); err == nil {
		t.Fatal("expected unknown category to be rejected")
	}
}

func TestComponentAlertValidate(t *testing.T) {
	alert := ComponentAlert{SchemaVersion: ComponentAlertSchemaVersion, ID: "a1", Category: TelemetryRuntime, SourceEngine: SourceEngineWazuh, RuleID: "runtime-1", RuleName: "Suspicious process", Severity: SeverityHigh, ScoreHint: 80, OccurredAt: time.Now(), Source: "ly-security-engine", Summary: "reverse shell pattern", CandidateOnly: true}
	if err := alert.Validate(); err != nil {
		t.Fatalf("valid alert rejected: %v", err)
	}
	alert.ScoreHint = 101
	if err := alert.Validate(); err == nil {
		t.Fatal("expected invalid score to be rejected")
	}
}

func TestComponentAlertValidateEngineDomains(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		category TelemetryCategory
		engine   SourceEngine
		native   *RuleReference
	}{
		{name: "suricata network", category: TelemetryNetwork, engine: SourceEngineSuricata, native: &RuleReference{Engine: SourceEngineSuricata, ID: "2010935", Revision: "3", Category: "trojan-activity"}},
		{name: "wazuh host", category: TelemetryHost, engine: SourceEngineWazuh, native: &RuleReference{Engine: SourceEngineWazuh, ID: "5710", Category: "authentication_failed"}},
		{name: "yara artifact", category: TelemetryArtifact, engine: SourceEngineYARA, native: &RuleReference{Engine: SourceEngineYARA, ID: "webshell_php_eval", Category: "webshell"}},
		{name: "rasp application", category: TelemetryRASP, engine: SourceEngineRASP, native: &RuleReference{Engine: SourceEngineRASP, ID: "rasp-command-exec", Category: "command_exec"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alert := ComponentAlert{
				SchemaVersion: ComponentAlertSchemaVersion,
				ID:            "alert-" + tc.name,
				Category:      tc.category,
				SourceEngine:  tc.engine,
				RuleID:        tc.native.ID,
				RuleName:      tc.name,
				NativeRule:    tc.native,
				Severity:      SeverityHigh,
				ScoreHint:     80,
				OccurredAt:    now,
				Source:        string(tc.engine),
				Entities:      EntityRef{AgentID: "agent-1", Hostname: "endpoint-1"},
				RawReference:  &RawReference{Path: "/var/log/lyflow/raw.json", SourceEngine: tc.engine},
				Summary:       tc.name,
				Action:        string(ActionAudit),
				PolicyState:   PolicyAuditOnly,
				CandidateOnly: true,
			}
			if err := alert.Validate(); err != nil {
				t.Fatalf("valid %s alert rejected: %v", tc.name, err)
			}
		})
	}
}

func TestComponentAlertRejectsUnknownSourceEngine(t *testing.T) {
	alert := ComponentAlert{SchemaVersion: ComponentAlertSchemaVersion, ID: "a1", Category: TelemetryNetwork, SourceEngine: "unknown", RuleID: "r1", RuleName: "bad engine", Severity: SeverityHigh, ScoreHint: 80, OccurredAt: time.Now(), Source: "bad", Summary: "bad"}
	if err := alert.Validate(); err == nil {
		t.Fatal("expected unknown source engine to be rejected")
	}
}
