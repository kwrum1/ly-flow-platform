package lateral

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestTrackerEmitsFindingOncePerCooldown(t *testing.T) {
	now := time.Now().UTC()
	tracker := NewTracker(Config{Window: 10 * time.Minute, MinTargets: 3})
	events := make([]contracts.EventV2, 0, 3)
	for index, target := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		events = append(events, contracts.EventV2{
			SchemaVersion: contracts.SecurityEventSchemaV2, EventUID: "e" + string(rune('1'+index)),
			TenantID: "default", Source: contracts.SourceAgentTraffic, EventType: "traffic.flow",
			Timestamps: contracts.EventTimestamps{EventAt: now.Add(-time.Minute), ObservedAt: now, IngestedAt: now},
			Entities: contracts.Entities{
				Asset:   &contracts.AssetEntity{ID: "asset-1"},
				Network: &contracts.NetworkEntity{DstIP: target, DstPort: 445, Proto: "tcp"},
			},
			Detection: contracts.Detection{Severity: contracts.SeverityLow},
		})
	}
	findings := tracker.Observe(events)
	if len(findings) != 1 || findings[0].Type != "lateral_movement" || len(findings[0].Targets) != 3 {
		t.Fatalf("first findings: %+v", findings)
	}
	if second := tracker.Observe(events); len(second) != 0 {
		t.Fatalf("duplicate findings escaped cooldown: %+v", second)
	}
}
