package main

import (
	"context"
	"fmt"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

func (a *Agent) publishControlHealth(health runtimeControlHealthSnapshot) error {
	now := time.Now().UTC()
	event := contracts.TelemetryEnvelope{
		SchemaVersion: contracts.TelemetrySchemaVersion, ID: fmt.Sprintf("control-health-%s-%d", a.agentID, now.UnixNano()),
		Category: contracts.TelemetryRuntime, EventType: controlHealthEventType, ObservedAt: now, ReceivedAt: now,
		Source: "ly-agent", SourceEngine: contracts.SourceEngineAgent,
		Entities: contracts.EntityRef{AgentID: a.agentID, Hostname: a.hostname}, Fields: structToMap(health),
		Excerpt: "runtime control health degraded",
	}
	policy := transport.RetryPolicy{MaxAttempts: 3, BaseDelay: 10 * time.Millisecond, MaxDelay: 40 * time.Millisecond}
	err := policy.Do(a.ctx, event.ID, func(ctx context.Context) error {
		publishErr := a.publishAgentStream(ctx, firstNonEmpty(a.cfg.RuntimeTelemetryStream, "telemetry:runtime"), structToMap(event), "telemetry_runtime")
		if publishErr != nil {
			a.runtimeHealth.recordPublicationFailure(publishErr)
		}
		return publishErr
	}, nil)
	if err != nil {
		return &controlHealthPublicationError{Cause: err}
	}
	a.runtimeHealth.recordPublicationSuccess()
	return nil
}
