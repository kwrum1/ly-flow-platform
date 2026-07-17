package analytics

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const EventTableDDL = `CREATE TABLE IF NOT EXISTS lyflow_events (
  event_id String,
  version UInt64,
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
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (event_id)`

const EventQuery = `SELECT event_id, version, timestamp, source_module, event_type, severity, agent_id, host_id, chain_id, entity_id, raw_reference, message, payload_json FROM lyflow_events FINAL ORDER BY timestamp DESC LIMIT ?`

type EventRecord struct {
	ID           string
	Version      uint64
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
	_, err := db.Exec(`INSERT INTO lyflow_events (event_id, version, timestamp, source_module, event_type, severity, agent_id, host_id, chain_id, entity_id, raw_reference, message, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.Version, event.Timestamp.UTC(), event.SourceModule, event.EventType, event.Severity, event.AgentID, event.HostID, event.ChainID, event.EntityID, event.RawReference, event.Message, event.PayloadJSON)
	return err
}

func QueryEvents(ctx context.Context, db *sql.DB, limit int) ([]EventRecord, error) {
	if db == nil {
		return nil, fmt.Errorf("clickhouse db is nil")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("event query limit must be positive")
	}
	rows, err := db.QueryContext(ctx, EventQuery, limit)
	if err != nil {
		return nil, fmt.Errorf("query finalized clickhouse events: %w", err)
	}
	defer rows.Close()
	events := make([]EventRecord, 0, limit)
	for rows.Next() {
		var event EventRecord
		if err := rows.Scan(&event.ID, &event.Version, &event.Timestamp, &event.SourceModule, &event.EventType, &event.Severity, &event.AgentID, &event.HostID, &event.ChainID, &event.EntityID, &event.RawReference, &event.Message, &event.PayloadJSON); err != nil {
			return nil, fmt.Errorf("scan finalized clickhouse event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finalized clickhouse events: %w", err)
	}
	return events, nil
}
