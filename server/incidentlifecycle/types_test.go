package incidentlifecycle

import (
	"errors"
	"testing"
	"time"
)

func TestStatusTransitionMatrix_allows_only_legal_lifecycle_edges(t *testing.T) {
	// Given
	tests := []struct {
		from    Status
		to      Status
		allowed bool
	}{
		{StatusOpen, StatusTriaged, true},
		{StatusOpen, StatusProcessing, true},
		{StatusTriaged, StatusProcessing, true},
		{StatusTriaged, StatusOpen, true},
		{StatusProcessing, StatusResolved, true},
		{StatusProcessing, StatusOpen, true},
		{StatusProcessing, StatusTriaged, true},
		{StatusResolved, StatusProcessing, true},
		{StatusResolved, StatusClosed, true},
		{StatusResolved, StatusOpen, true},
		{StatusClosed, StatusOpen, true},
		{StatusOpen, StatusResolved, false},
		{StatusTriaged, StatusResolved, false},
		{StatusProcessing, StatusClosed, false},
	}

	for _, testCase := range tests {
		// When
		allowed := LegalTransition(testCase.from, testCase.to)

		// Then
		if allowed != testCase.allowed {
			t.Fatalf("transition %s -> %s allowed=%t, want %t", testCase.from, testCase.to, allowed, testCase.allowed)
		}
	}
}

func TestNewActiveSnapshot_rejects_shadow_incident_input(t *testing.T) {
	// Given
	candidate := Candidate{IncidentID: "inc-1", SourceChainID: "hyp-1", FirstSeen: time.Now(), LastSeen: time.Now()}

	// When
	_, err := NewActiveSnapshot("v3-shadow", []Candidate{candidate})

	// Then
	if !errors.Is(err, ErrActiveInputRequired) {
		t.Fatalf("shadow input error=%v", err)
	}
}

func TestDedupKey_is_stable_when_evidence_order_changes(t *testing.T) {
	// Given
	first := Candidate{SourceChainID: "hyp-stable", CorrelationKey: "asset-1"}
	second := first
	first.Evidence = []Evidence{{EventUID: "event-1"}, {EventUID: "event-2"}}
	second.Evidence = []Evidence{{EventUID: "event-2"}, {EventUID: "event-1"}}

	// When
	left := DedupKey("default", first)
	right := DedupKey("default", second)

	// Then
	if left == "" || left != right {
		t.Fatalf("dedup keys left=%q right=%q", left, right)
	}
}

func TestAuthorizeRoleActionMatrix_allows_system_only_for_legacy_snapshot_import(t *testing.T) {
	// Given
	roles := []Role{RoleAdmin, RoleAnalyst, RoleViewer, RoleSystem}
	actions := []Action{ActionCreate, ActionTransition, ActionAssign, ActionSuppress, ActionSnapshot}
	allowed := map[Role]map[Action]bool{
		RoleAdmin:   {ActionTransition: true, ActionAssign: true, ActionSuppress: true},
		RoleAnalyst: {ActionTransition: true, ActionAssign: true, ActionSuppress: true},
		RoleViewer:  {},
		RoleSystem:  {ActionSnapshot: true},
	}

	for _, role := range roles {
		for _, action := range actions {
			// When
			err := authorize(Actor{ID: "actor-1", Role: role}, action)

			// Then
			wantAllowed := allowed[role][action]
			if wantAllowed && err != nil {
				t.Fatalf("role=%s action=%s error=%v, want allowed", role, action, err)
			}
			if !wantAllowed && !errors.Is(err, ErrForbidden) {
				t.Fatalf("role=%s action=%s error=%v, want forbidden", role, action, err)
			}
		}
	}
}

func TestCommandPayloadHash_changes_for_every_semantic_field(t *testing.T) {
	// Given
	base := Command{
		IncidentID: "inc-1", IdempotencyKey: "caller-key", Actor: Actor{ID: "user:7", Role: RoleAnalyst},
		Action: ActionSuppress, To: StatusProcessing, Assignee: "analyst-7", Reason: "maintenance",
		SuppressUntil: time.Date(2026, 7, 16, 11, 0, 0, 0, time.UTC), ExpectedVersion: 4,
	}
	mutations := []struct {
		name   string
		mutate func(*Command)
	}{
		{"incident", func(command *Command) { command.IncidentID = "inc-2" }},
		{"actor id", func(command *Command) { command.Actor.ID = "user:8" }},
		{"actor role", func(command *Command) { command.Actor.Role = RoleAdmin }},
		{"action", func(command *Command) { command.Action = ActionAssign }},
		{"status body", func(command *Command) { command.To = StatusResolved }},
		{"assignee body", func(command *Command) { command.Assignee = "analyst-8" }},
		{"reason body", func(command *Command) { command.Reason = "approved maintenance" }},
		{"suppression body", func(command *Command) { command.SuppressUntil = command.SuppressUntil.Add(time.Minute) }},
		{"expected version", func(command *Command) { command.ExpectedVersion++ }},
	}
	baseline := CommandPayloadHash(base)

	for _, testCase := range mutations {
		// When
		changed := base
		testCase.mutate(&changed)
		got := CommandPayloadHash(changed)

		// Then
		if got == "" || got == baseline {
			t.Fatalf("%s did not change command payload hash: %q", testCase.name, got)
		}
	}
}
