package xdr

import (
	"context"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"github.com/lyflow/ly-flow-platform/transportreliability/conformancetest"
)

func TestServerXDRCrashReplayPreservesUIDAndOneDurableOutcome(t *testing.T) {
	harness := conformancetest.Redis(t)
	uid := "xdr-alert-stable"
	processor := &XDRProcessor{redis: harness.Client}
	event := &models.XDREvent{EventType: "xdr.test", Severity: models.SeverityHigh, Message: "stable", CreatedAt: time.Now().UTC()}

	conformancetest.RunCrashReplay(t, harness, conformancetest.Adapter{
		Name: "server-xdr",
		Publish: func(ctx context.Context) error {
			return processor.publishAlert(ctx, event, uid)
		},
		Sinks: []conformancetest.Sink{{Stream: "alerts:xdr", UIDField: "event_uid", UID: uid, DeliveryCount: 1}},
	})
	if count, err := harness.Client.LLen(harness.Context, "alerts:list").Result(); err != nil || count != 1 {
		t.Fatalf("server-xdr durable list outcomes = %d, want 1: %v", count, err)
	}
}
