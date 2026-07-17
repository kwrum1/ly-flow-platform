package consumer

import (
	"context"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/unified"
	"github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/lyflow/ly-flow-platform/transportreliability/conformancetest"
)

func TestServerUnifiedCrashReplayPreservesUIDAndOneDurableOutcome(t *testing.T) {
	harness := conformancetest.Redis(t)
	spool, err := transportreliability.NewEncryptedSpool(transportreliability.SpoolConfig{
		Dir: t.TempDir(), Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 1 << 20, MaxAge: time.Hour,
	})
	if err != nil {
		t.Fatalf("create producer spool: %v", err)
	}
	producer, err := transportreliability.NewRedisProducer(transportreliability.ProducerConfig{
		Client: harness.Client, Name: "server-unified", Spool: spool, Retry: transportreliability.RetryPolicy{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatalf("create unified producer: %v", err)
	}
	consumer := &UnifiedConsumer{client: harness.Client, producer: producer}
	event := &unified.UnifiedEvent{ID: "unified-stable", Module: unified.ModuleXDR, EventType: "xdr.test", Severity: unified.SeverityHigh, Timestamp: time.Now().UTC()}
	uid := transportreliability.DeterministicUID("server-unified", "events:unified", event.ID)

	conformancetest.RunCrashReplay(t, harness, conformancetest.Adapter{
		Name: "server-unified",
		Publish: func(context.Context) error {
			return consumer.PublishEvent(event)
		},
		Sinks: []conformancetest.Sink{{Stream: "events:unified", UIDField: "event_uid", UID: uid, DeliveryCount: 2}},
	})
}
