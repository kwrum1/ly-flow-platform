package materialization

import (
	"strings"
	"testing"
)

func TestNamedSinksHaveDeterministicUIDConflictContracts(t *testing.T) {
	// Given / When
	sinks := NamedSinks()

	// Then
	want := map[string]string{"threat_events": "event_uid", "traffic_sessions": "session_uid", "xdr_events_v2": "event_uid", "clickhouse_events": "event_id"}
	for name, uidColumn := range want {
		sink, ok := sinks[name]
		if !ok || sink.UIDColumn != uidColumn || sink.ConflictClause == "" {
			t.Fatalf("sink %s lacks idempotent UID contract: %+v", name, sink)
		}
	}
	if !strings.Contains(sinks["clickhouse_events"].ConflictClause, "FINAL") {
		t.Fatalf("ClickHouse sink lacks query-time strict dedup policy: %+v", sinks["clickhouse_events"])
	}
}
