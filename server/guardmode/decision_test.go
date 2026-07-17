package guardmode

import "testing"

func TestSafetyGateHardDisablesTemporaryBlock(t *testing.T) {
	decision, err := ParseDecision([]byte(`{"action":"temporary_block","confidence":0.91,"target_ip":"198.51.100.8","reason":"P0 multi-signal"}`))
	if err != nil {
		t.Fatalf("ParseDecision() error = %v", err)
	}
	ctx := SafetyContext{Severity: "critical", RuleHit: true, MultiSignal: true, WhitelistPassed: true, AllowedWindow: true}
	if Allowed(decision, ctx, 0.8) {
		t.Fatal("temporary block must remain advisory-only")
	}
}

func TestSafetyGateAllowsNotifyOnlyAdvisory(t *testing.T) {
	decision := Decision{Action: "notify_only", Confidence: 0.91}
	ctx := SafetyContext{Severity: "critical", RuleHit: true, MultiSignal: true, WhitelistPassed: true, AllowedWindow: true}
	if !Allowed(decision, ctx, 0.8) {
		t.Fatal("notify-only advisory should pass")
	}
}

func TestSafetyGateRejectsUnsafeActions(t *testing.T) {
	decision := Decision{Action: "delete_data", Confidence: 1}
	ctx := SafetyContext{Severity: "critical", RuleHit: true, MultiSignal: true, WhitelistPassed: true, AllowedWindow: true}
	if Allowed(decision, ctx, 0.8) {
		t.Fatal("unsafe action should not pass")
	}
}
