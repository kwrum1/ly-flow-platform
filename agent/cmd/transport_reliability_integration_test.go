package main

import (
	"context"
	"testing"

	"github.com/lyflow/ly-flow-platform/transportreliability/conformancetest"
)

func TestAgentLiveDeliveryCrashReplayPreservesUIDAndOneDurableOutcome(t *testing.T) {
	harness := conformancetest.Redis(t)
	record := spoolRecord{RecordID: "agent-live-stable", Stream: "todo7:agent-live", Type: "raw_flow", Data: `{"id":"flow-live"}`}
	spool := &durableTrafficSpool{client: harness.Client, ctx: harness.Context}

	conformancetest.RunCrashReplay(t, harness, conformancetest.Adapter{
		Name: "agent-live",
		Publish: func(context.Context) error {
			return spool.deliver(record, map[string]interface{}{"type": record.Type, "data": record.Data})
		},
		Sinks: []conformancetest.Sink{{Stream: record.Stream, UIDField: "event_uid", UID: record.RecordID, DeliveryCount: 2}},
	})
}
