package unified

import (
	"testing"
	"time"
)

func TestEmptyThreatIntelResponseHasNoFakeRows(t *testing.T) {
	resp := EmptyThreatIntelResponse(ThreatIntelCombined)
	if resp.Total != 0 || len(resp.Items) != 0 {
		t.Fatalf("empty threat intelligence should have no rows: %#v", resp)
	}
	if resp.EmptyState == nil || resp.EmptyState.Reason != "NO_THREAT_INTELLIGENCE" {
		t.Fatalf("empty threat intelligence should explain no-data state: %#v", resp.EmptyState)
	}
}

func TestMergeThreatIntelOnlyUsesProvidedItems(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	rasp := []ThreatIntelItem{{ID: "r1", View: ThreatIntelRASPApps, Source: ModuleRASP, AssetID: "a1", Timestamp: now, Title: "rasp event"}}
	runtime := []ThreatIntelItem{{ID: "h1", View: ThreatIntelRuntimeHosts, Source: ModuleTrace, AssetID: "a1", Timestamp: now, Title: "runtime event"}}

	merged := MergeThreatIntel(rasp, runtime)
	if len(merged) != 2 {
		t.Fatalf("expected exactly provided items, got %#v", merged)
	}
	if merged[0].ID != "r1" || merged[1].ID != "h1" {
		t.Fatalf("merge should preserve real provided items: %#v", merged)
	}
}
