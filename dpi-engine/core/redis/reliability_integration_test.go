package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/lyflow/ly-flow-platform/transportreliability/conformancetest"
	"ly-flow-platform/dpi-engine/core/output"
)

func TestDPIRedisCrashReplayPreservesOutputUIDAndOneDurableOutcome(t *testing.T) {
	harness := conformancetest.Redis(t)
	stream := "todo7:dpi-redis-output"
	alert := &output.Alert{ID: 43, Type: "dpi_alert", Signature: "redis replay", Severity: 2}
	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("encode expected alert: %v", err)
	}
	sum := sha256.Sum256(append([]byte(stream+"\x00dpi_alert\x00"), data...))
	uid := "dpi-" + hex.EncodeToString(sum[:16])
	out := output.New(harness.Client, stream)
	consumer := &Consumer{client: harness.Client}
	consumer.onFlowReliable = func(context.Context, XMessage) error { return out.SendDirect(alert) }
	delivery := transportreliability.Delivery{Stream: "flows:raw", MessageID: "stable-flow", Values: map[string]interface{}{"data": "payload"}}

	conformancetest.RunCrashReplay(t, harness, conformancetest.Adapter{
		Name: "dpi-redis",
		Publish: func(ctx context.Context) error {
			_, publishErr := consumer.handleDelivery(ctx, delivery)
			return publishErr
		},
		Sinks: []conformancetest.Sink{{Stream: stream, UIDField: "event_uid", UID: uid, DeliveryCount: 1}},
	})
}
