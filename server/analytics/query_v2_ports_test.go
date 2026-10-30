package analytics

import (
	"encoding/json"
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestEventV2ViewKeepsUnknownPortsNil(t *testing.T) {
	row := eventV2QueryRow{
		EventUID: "evt-1", TenantID: "default", Source: "adapter.suricata",
		EventType: "network.signature", EventAt: "2026-10-19 12:00:00.000",
		ObservedAt: "2026-10-19 12:00:00.000", IngestedAt: "2026-10-19 12:00:00.000",
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 0, DstPort: 0,
		SrcPortKnown: 0, DstPortKnown: 0,
		Severity: "high",
	}
	view := row.view()
	if view.SrcPort != nil || view.DstPort != nil {
		t.Fatalf("unknown ports must be nil, got src=%v dst=%v", view.SrcPort, view.DstPort)
	}

	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal view: %v", err)
	}
	for _, field := range []string{"src_port", "dst_port"} {
		value, exists := decoded[field]
		if !exists {
			t.Fatalf("%s must be present as null, body=%s", field, encoded)
		}
		if value != nil {
			t.Fatalf("%s must be null, got %v", field, value)
		}
	}
}

func TestEventV2ViewSurfacesKnownPorts(t *testing.T) {
	row := eventV2QueryRow{
		EventUID: "evt-2", TenantID: "default", Source: "adapter.suricata",
		EventType: "network.signature", EventAt: "2026-10-19 12:00:00.000",
		ObservedAt: "2026-10-19 12:00:00.000", IngestedAt: "2026-10-19 12:00:00.000",
		SrcPort: 51515, DstPort: 443,
		SrcPortKnown: 1, DstPortKnown: 1,
		Severity: "high",
	}
	view := row.view()
	if view.SrcPort == nil || *view.SrcPort != 51515 {
		t.Fatalf("src port not surfaced: %v", view.SrcPort)
	}
	if view.DstPort == nil || *view.DstPort != 443 {
		t.Fatalf("dst port not surfaced: %v", view.DstPort)
	}
}

func TestPortKnownRequiresRealObservation(t *testing.T) {
	cases := []struct {
		name     string
		port     int
		flags    []contracts.QualityFlag
		expected uint8
	}{
		{"real port", 443, nil, 1},
		{"zero is missing", 0, nil, 0},
		{"negative is missing", -1, nil, 0},
		{"out of range is missing", 70000, nil, 0},
		{"explicit missing flag wins", 443, []contracts.QualityFlag{contracts.QualityMissingDstPort}, 0},
	}
	for _, tc := range cases {
		event := contracts.EventV2{QualityFlags: tc.flags}
		if got := portKnown(event, contracts.QualityMissingDstPort, tc.port); got != tc.expected {
			t.Fatalf("%s: portKnown=%d want %d", tc.name, got, tc.expected)
		}
	}
}
