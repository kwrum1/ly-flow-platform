package output

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lyflow/ly-flow-platform/transportreliability/conformancetest"
)

func TestDPIOutputCrashReplayPreservesUIDAndOneDurableOutcome(t *testing.T) {
	harness := conformancetest.Redis(t)
	alert := &Alert{ID: 42, Type: "dpi_alert", Signature: "stable replay", Severity: 2}
	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("encode expected alert: %v", err)
	}
	stream := "todo7:dpi-output"
	sum := sha256.Sum256(append([]byte(stream+"\x00dpi_alert\x00"), data...))
	uid := "dpi-" + hex.EncodeToString(sum[:16])
	adapter := New(harness.Client, stream)

	conformancetest.RunCrashReplay(t, harness, conformancetest.Adapter{
		Name: "dpi-output",
		Publish: func(context.Context) error {
			return adapter.SendDirect(alert)
		},
		Sinks: []conformancetest.Sink{{Stream: stream, UIDField: "event_uid", UID: uid, DeliveryCount: 1}},
	})
}
