package engine

import (
	"context"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/transportreliability/conformancetest"
	"ly-flow-platform/security-engine/config"
)

func TestSecurityEngineCrashReplayPreservesUIDAndOneDurableOutcome(t *testing.T) {
	harness := conformancetest.Redis(t)
	stream := "todo7:security-engine"
	engine := New(config.Config{RuntimeStream: stream}, harness.Client)
	alert := contracts.ComponentAlert{
		SchemaVersion: contracts.ComponentAlertSchemaVersion,
		ID:            "security-alert-stable", Category: contracts.TelemetryRuntime,
		SourceEngine: contracts.SourceEngineRuntime, RuleID: "rule-1", RuleName: "stable",
		Severity: contracts.SeverityHigh, OccurredAt: time.Now().UTC(), Source: "runtime",
		Summary: "stable replay",
	}

	conformancetest.RunCrashReplay(t, harness, conformancetest.Adapter{
		Name: "security-engine",
		Publish: func(ctx context.Context) error {
			return engine.emitAlert(ctx, alert)
		},
		Sinks: []conformancetest.Sink{{Stream: stream, UIDField: "event_uid", UID: alert.ID, DeliveryCount: 1}},
	})
}
