package advisoryresponse

import (
	"errors"
	"testing"
)

func TestNewCandidate_rejects_shadow_and_unsupported_actions(t *testing.T) {
	// Given
	base := CandidateInput{
		ID: CandidateID("inc-1", ActionIncreaseMonitoring, "agent-1"), IncidentID: "inc-1", AgentID: "agent-1",
		Algorithm: ActiveAlgorithm, Action: ActionIncreaseMonitoring,
		Target: "agent-1", Reason: "elevated chain score",
	}

	// When
	shadow := base
	shadow.Algorithm = "v3-shadow"
	_, shadowErr := NewCandidate(shadow)
	unsupported := base
	unsupported.Action = Action("firewall_block")
	_, unsupportedErr := NewCandidate(unsupported)

	// Then
	if !errors.Is(shadowErr, ErrActiveInputRequired) {
		t.Fatalf("shadow error=%v, want active input required", shadowErr)
	}
	if !errors.Is(unsupportedErr, ErrUnsupportedAction) {
		t.Fatalf("unsupported error=%v, want unsupported action", unsupportedErr)
	}
}

func TestSupportedAction_accepts_only_advisory_candidate_types(t *testing.T) {
	// Given
	want := map[Action]bool{
		ActionAnalystReview: true, ActionIncreaseMonitoring: true,
		ActionCollectForensicBundle: true, ActionSuggestProxyACL: true,
		ActionSuggestHostIsolation: true,
	}

	// When / Then
	for action, expected := range want {
		if SupportedAction(action) != expected {
			t.Fatalf("supported action %q=%v, want %v", action, SupportedAction(action), expected)
		}
	}
	for _, action := range []Action{"firewall_block", "process_kill", "file_delete", "account_disable", "namespace_isolate"} {
		if SupportedAction(action) {
			t.Fatalf("host action %q is supported", action)
		}
	}
}
