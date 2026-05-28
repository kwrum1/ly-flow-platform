package unified

import (
	"testing"
	"time"
)

func TestUnifiedEventJSONRoundTrip(t *testing.T) {
	original := &UnifiedEvent{
		ID:            "evt-1",
		SchemaVersion: "v1",
		Module:        ModuleXDR,
		SourceModule:  ModuleAsset,
		EventType:     "suspicious_login",
		Source:        "xdr-agent",
		Severity:      SeverityHigh,
		Timestamp:     time.Unix(1715000000, 0).UTC(),
		Alert:         true,
		EntityIDs: &EntityIDs{
			AgentID: "agent-1",
			HostID:  "host-1",
		},
		BehaviorContext: &BehaviorContext{
			Scenario:   "auth",
			Action:     "login",
			Stage:      "post-auth",
			Confidence: 0.92,
			Labels:     []string{"credential", "risk"},
			Details: map[string]interface{}{
				"attempts": float64(3),
			},
		},
		RawReference: &RawReference{
			Stream:    "events:xdr",
			MessageID: "1700000000000-0",
		},
		Status: StatusNew,
	}

	blob, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	var restored UnifiedEvent
	if err := restored.FromJSON(blob); err != nil {
		t.Fatalf("FromJSON() error = %v", err)
	}

	if restored.ID != original.ID || restored.Module != original.Module || restored.Severity != original.Severity {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", restored, original)
	}
	if restored.EntityIDs == nil || restored.EntityIDs.AgentID != "agent-1" {
		t.Fatalf("EntityIDs not restored correctly: %+v", restored.EntityIDs)
	}
	if restored.RawReference == nil || restored.RawReference.Stream != "events:xdr" {
		t.Fatalf("Raw reference not restored correctly: %+v", restored.RawReference)
	}
	if restored.Status != StatusNew {
		t.Fatalf("Status = %q, want %q", restored.Status, StatusNew)
	}
}

func TestUnifiedEventFromJSONInvalid(t *testing.T) {
	var evt UnifiedEvent
	if err := evt.FromJSON([]byte("{bad-json")); err == nil {
		t.Fatal("expected invalid json error, got nil")
	}
}
