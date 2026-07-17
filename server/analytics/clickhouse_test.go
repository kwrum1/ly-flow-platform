package analytics

import (
	"strings"
	"testing"
)

func TestEventTableDDLKeepsTimelineAndTopologyColumns(t *testing.T) {
	for _, column := range []string{"timestamp", "source_module", "chain_id", "entity_id", "raw_reference", "payload_json"} {
		if !strings.Contains(EventTableDDL, column) {
			t.Fatalf("DDL missing column %s: %s", column, EventTableDDL)
		}
	}
	if !strings.Contains(EventTableDDL, "ReplacingMergeTree") || !strings.Contains(EventTableDDL, "ORDER BY (event_id)") {
		t.Fatalf("DDL missing analytics ordering: %s", EventTableDDL)
	}
}
