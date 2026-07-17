package main

import (
	"context"
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/lyflow/ly-flow-platform/transportreliability/conformancetest"
	"github.com/redis/go-redis/v9"
)

func TestServerConsumerBridgeCrashReplayPreservesUIDAndOneDurableOutcome(t *testing.T) {
	harness := conformancetest.Redis(t)
	message := redis.XMessage{ID: "raw-flow-stable", Values: map[string]interface{}{"data": `{"id":"flow-1"}`}}
	uid := transportreliability.DeterministicUID("flow_bridge", "flows:raw", message.ID)
	consumer := &ConsumerState{cfg: &Config{Redis: harness.Client}}

	conformancetest.RunCrashReplay(t, harness, conformancetest.Adapter{
		Name: "server-consumer-bridge",
		Publish: func(ctx context.Context) error {
			return consumer.bridgeRawFlow(ctx, message)
		},
		Sinks: []conformancetest.Sink{
			{Stream: "flows:semantic", UIDField: "event_uid", UID: uid, DeliveryCount: 1},
			{Stream: "sessions:semantic", UIDField: "event_uid", UID: uid, DeliveryCount: 1},
		},
	})
}

func TestMigrationLuaCrashReplayPreservesUIDAndOneDurableOutcome(t *testing.T) {
	runtime, client, ctx := disposableMigrationRuntime(t)
	if err := runtime.Advance(ctx, contracts.PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	alert := migrationTestAlert("migration-stable")
	uid := eventUIDForAlert(alert.ID)

	conformancetest.RunCrashReplay(t, conformancetest.RedisHarness{Client: client, Context: ctx}, conformancetest.Adapter{
		Name: "migration-lua",
		Publish: func(ctx context.Context) error {
			_, err := runtime.WriteComponentAlert(ctx, alert, migrationRuntimeTestTime)
			return err
		},
		Sinks: []conformancetest.Sink{
			{Stream: legacyComponentAlertStream, UIDField: "event_uid", UID: uid, DeliveryCount: 1},
			{Stream: canonicalEventStream, UIDField: "event_uid", UID: uid, DeliveryCount: 1},
		},
	})
}
