package main

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

func TestIncidentCommandIdempotencyKey_includes_reason_and_command_semantics(t *testing.T) {
	// Given
	first := incidentlifecycle.Command{
		IncidentID: "inc-1", Actor: incidentlifecycle.Actor{ID: "user:7", Role: incidentlifecycle.RoleAnalyst},
		Action: incidentlifecycle.ActionTransition, To: incidentlifecycle.StatusTriaged, Reason: "first review", ExpectedVersion: 1,
	}
	second := first
	second.Reason = "different review"

	// When
	firstKey := incidentCommandIdempotencyKey(first)
	secondKey := incidentCommandIdempotencyKey(second)

	// Then
	if firstKey == "" || secondKey == "" || firstKey == secondKey {
		t.Fatalf("generated keys first=%q second=%q", firstKey, secondKey)
	}
}
