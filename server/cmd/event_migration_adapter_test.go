package main

import (
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestComponentAlertDualWriteCanonicalPayloadUsesBoundPrincipalAndGovernance(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	alert := contracts.ComponentAlert{
		SchemaVersion: contracts.ComponentAlertSchemaVersion, ID: "alert-1", Category: contracts.TelemetryNetwork,
		SourceEngine: contracts.SourceEngineSuricata, RuleID: "rule-1", RuleName: "network rule", Severity: contracts.SeverityHigh,
		OccurredAt: now.Add(-time.Minute), Source: "suricata", Entities: contracts.EntityRef{AgentID: "agent-1"},
		Summary: "network alert", Details: map[string]interface{}{"authorization": "Bearer secret"},
	}

	event, payload, err := canonicalComponentAlertPayload(alert, now)
	if err != nil {
		t.Fatalf("canonical component alert: %v", err)
	}
	if event.Identity.PrincipalID != "agent-1" || event.Provenance.Source != contracts.SourceSuricata {
		t.Fatalf("principal/source not preserved: %+v", event)
	}
	if strings.Contains(string(payload), "Bearer secret") || !event.Governance.Encryption.Required {
		t.Fatalf("governance not applied: %s", payload)
	}
}
