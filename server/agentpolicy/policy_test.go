package agentpolicy

import "testing"

func TestDefaultPolicyContainsServerManagedSwitches(t *testing.T) {
	policy := DefaultPolicy("agent-1")
	if !policy.Traffic.Enabled || policy.Traffic.CaptureEngine == "" || policy.Streams["raw"] != "flows:raw" {
		t.Fatalf("traffic policy incomplete: %#v", policy)
	}
	if policy.RASP.Mode != "monitor" || !policy.RASP.Languages["python"] {
		t.Fatalf("rasp policy incomplete: %#v", policy.RASP)
	}
	if !policy.Runtime.Enabled || policy.Asset.IntervalSeconds <= 0 || !policy.Retention.EvidenceEnabled {
		t.Fatalf("runtime/asset/retention policy incomplete: %#v", policy)
	}
}

func TestDriftDetected(t *testing.T) {
	if !DriftDetected(Policy{Version: 3}, 2) {
		t.Fatal("expected drift when applied version differs")
	}
	if DriftDetected(Policy{Version: 3}, 3) {
		t.Fatal("did not expect drift when versions match")
	}
}
