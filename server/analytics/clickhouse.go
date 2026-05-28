package analytics

import (
	"database/sql"
	"fmt"
	"time"
)

const EventTableDDL = `CREATE TABLE IF NOT EXISTS lyflow_events (
  event_id String,
  timestamp DateTime64(3, 'UTC'),
  source_module LowCardinality(String),
  event_type String,
  severity LowCardinality(String),
  agent_id String,
  host_id String,
  chain_id String,
  entity_id String,
  raw_reference String,
  message String,
  payload_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_module, event_id)`

type EventRecord struct {
	ID           string
	Timestamp    time.Time
	SourceModule string
	EventType    string
	Severity     string
	AgentID      string
	HostID       string
	ChainID      string
	EntityID     string
	RawReference string
	Message      string
	PayloadJSON  string
}

func EnsureEventTable(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("clickhouse db is nil")
	}
	_, err := db.Exec(EventTableDDL)
	return err
}

func InsertEvent(db *sql.DB, event EventRecord) error {
	if db == nil {
		return fmt.Errorf("clickhouse db is nil")
	}
	if event.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	_, err := db.Exec(`INSERT INTO lyflow_events (event_id, timestamp, source_module, event_type, severity, agent_id, host_id, chain_id, entity_id, raw_reference, message, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.Timestamp.UTC(), event.SourceModule, event.EventType, event.Severity, event.AgentID, event.HostID, event.ChainID, event.EntityID, event.RawReference, event.Message, event.PayloadJSON)
	return err
}
