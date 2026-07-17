package analytics

import (
	"strings"
	"testing"
)

func TestClickHouseEventTableMaterializesByEventID(t *testing.T) {
	// Given / When
	ddl := EventTableDDL

	// Then
	if !strings.Contains(ddl, "ReplacingMergeTree(version)") || !strings.Contains(ddl, "ORDER BY (event_id)") {
		t.Fatalf("ClickHouse sink is not idempotent by event_id: %s", ddl)
	}
}
