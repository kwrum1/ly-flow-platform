package materialization

type SinkContract struct {
	Name           string
	UIDColumn      string
	ConflictClause string
}

func NamedSinks() map[string]SinkContract {
	return map[string]SinkContract{
		"threat_events": {
			Name: "threat_events", UIDColumn: "event_uid", ConflictClause: "ON CONFLICT (event_uid) DO UPDATE",
		},
		"traffic_sessions": {
			Name: "traffic_sessions", UIDColumn: "session_uid", ConflictClause: "ON CONFLICT (session_uid) DO UPDATE",
		},
		"xdr_events_v2": {
			Name: "xdr_events_v2", UIDColumn: "event_uid", ConflictClause: "UNIQUE (event_uid)",
		},
		"clickhouse_events": {
			Name: "clickhouse_events", UIDColumn: "event_id", ConflictClause: "ReplacingMergeTree ORDER BY event_id; SELECT FROM lyflow_events FINAL",
		},
	}
}
