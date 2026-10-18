package lateral

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func lateralEvent(uid, asset, target string, port int, technique string, at time.Time) contracts.EventV2 {
	return contracts.EventV2{
		EventUID: uid, Source: contracts.SourceSuricata, EventType: "network.flow",
		Timestamps: contracts.EventTimestamps{EventAt: at, ObservedAt: at, IngestedAt: at},
		Entities: contracts.Entities{
			Asset:   &contracts.AssetEntity{ID: asset},
			Network: &contracts.NetworkEntity{SrcIP: "10.0.0.1", DstIP: target, DstPort: port, Proto: "tcp"},
		},
		Detection: contracts.Detection{Severity: contracts.SeverityHigh, TechniqueID: technique},
	}
}

func TestDetectSMBLateralMovement(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	events := []contracts.EventV2{
		lateralEvent("e1", "asset-1", "10.0.0.2", 445, "", start),
		lateralEvent("e2", "asset-1", "10.0.0.3", 445, "", start.Add(time.Minute)),
		lateralEvent("e3", "asset-1", "10.0.0.4", 445, "", start.Add(2*time.Minute)),
	}
	findings := Detect(events, Config{Window: 10 * time.Minute, MinTargets: 3})
	if len(findings) != 1 || findings[0].Type != "lateral_movement" {
		t.Fatalf("findings = %+v", findings)
	}
	if len(findings[0].Targets) != 3 || findings[0].Techniques[0] != "T1021.002" {
		t.Fatalf("finding = %+v", findings[0])
	}
}

func TestDetectNeedsMinTargets(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	events := []contracts.EventV2{
		lateralEvent("e1", "asset-1", "10.0.0.2", 445, "", start),
		lateralEvent("e2", "asset-1", "10.0.0.3", 445, "", start.Add(time.Minute)),
	}
	if findings := Detect(events, Config{MinTargets: 3}); len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestDetectCredentialBurst(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	events := make([]contracts.EventV2, 0, 3)
	for index := 0; index < 3; index++ {
		event := lateralEvent("f"+string(rune('1'+index)), "asset-1", "10.0.0.2", 22, "T1110", start.Add(time.Duration(index)*time.Second))
		event.EventType = "auth.failure"
		event.Detection.Severity = contracts.SeverityLow
		events = append(events, event)
	}
	findings := Detect(events, Config{MinFailures: 3})
	if len(findings) != 1 || findings[0].Type != "credential_burst" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestDetectWindow(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	events := []contracts.EventV2{
		lateralEvent("e1", "asset-1", "10.0.0.2", 445, "", start),
		lateralEvent("e2", "asset-1", "10.0.0.3", 445, "", start.Add(20*time.Minute)),
		lateralEvent("e3", "asset-1", "10.0.0.4", 445, "", start.Add(21*time.Minute)),
	}
	if findings := Detect(events, Config{Window: 10 * time.Minute, MinTargets: 3}); len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}
