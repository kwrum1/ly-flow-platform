package contracts

import "testing"

func TestCanonicalEventValidateAcceptsTypedAttackIDs(t *testing.T) {
	if err := validateAttackTacticID("TA0001"); err != nil {
		t.Fatalf("valid tactic rejected: %v", err)
	}
	if err := validateAttackTechniqueID("TA0001"); err == nil {
		t.Fatal("tactic accepted as technique")
	}

	input := fixture(SourceAgentRuntime, `{"event_id":"runtime-1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`)
	event, _, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil {
		t.Fatalf("normalize fixture: %v", err)
	}

	for _, techniqueID := range []string{"T1059", "T1059.001"} {
		t.Run(techniqueID, func(t *testing.T) {
			if err := validateAttackTechniqueID(techniqueID); err != nil {
				t.Fatalf("valid technique rejected: %v", err)
			}
			if err := validateAttackTacticID(techniqueID); err == nil {
				t.Fatal("technique accepted as tactic")
			}

			candidate := event
			candidate.Attack.TacticID = "TA0001"
			candidate.Attack.TechniqueID = techniqueID
			if err := candidate.Validate(); err != nil {
				t.Fatalf("valid typed ATT&CK mapping rejected: %v", err)
			}
		})
	}
}

func TestCanonicalEventValidateRejectsSwappedAttackIDs(t *testing.T) {
	input := fixture(SourceAgentRuntime, `{"event_id":"runtime-1","agent_id":"agent-1","event_type":"runtime.process","event_at":"2026-07-13T09:59:00Z","observed_at":"2026-07-13T09:59:01Z","severity":"high"}`)
	event, _, err := NormalizeFixture(input, PrincipalIdentity("agent-1"), migrationTestTime)
	if err != nil {
		t.Fatalf("normalize fixture: %v", err)
	}

	tests := []struct {
		name        string
		tacticID    string
		techniqueID string
	}{
		{name: "tactic used as technique", tacticID: "TA0001", techniqueID: "TA0001"},
		{name: "technique used as tactic", tacticID: "T1059", techniqueID: "T1059"},
		{name: "sub-technique used as tactic", tacticID: "T1059.001", techniqueID: "T1059.001"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := event
			candidate.Attack.TacticID = test.tacticID
			candidate.Attack.TechniqueID = test.techniqueID
			if err := candidate.Validate(); err == nil {
				t.Fatal("swapped ATT&CK mapping accepted")
			}
		})
	}
}
