package models

import (
	"strings"
	"testing"
)

func TestEventInsertUsesEventUIDConflictMaterialization(t *testing.T) {
	// Given / When
	query := EventMaterializationSQL

	// Then
	if !strings.Contains(query, "event_uid") || !strings.Contains(query, "ON CONFLICT (event_uid)") {
		t.Fatalf("event insert is not idempotent by UID: %s", query)
	}
}
