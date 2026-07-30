package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const TrafficSessionTableDDL = `CREATE TABLE IF NOT EXISTS lyflow_traffic_sessions (
  session_uid String,
  version UInt64,
  observed_at DateTime64(6, 'UTC'),
  agent_id String,
  src_ip String,
  dst_ip String,
  src_port UInt16,
  dst_port UInt16,
  protocol LowCardinality(String),
  raw_event String,
  ingested_at DateTime64(6, 'UTC')
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(observed_at)
ORDER BY (observed_at, session_uid)`

type TrafficSessionRecord struct {
	SessionUID string
	Version    uint64
	ObservedAt time.Time
	AgentID    string
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Protocol   string
	RawEvent   string
	IngestedAt time.Time
}

type clickHouseTrafficSessionRow struct {
	SessionUID string `json:"session_uid"`
	Version    uint64 `json:"version"`
	ObservedAt string `json:"observed_at"`
	AgentID    string `json:"agent_id"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Protocol   string `json:"protocol"`
	RawEvent   string `json:"raw_event"`
	IngestedAt string `json:"ingested_at"`
}

func (client *HTTPClickHouse) EnsureTrafficSessionTable(ctx context.Context) error {
	if client == nil {
		return fmt.Errorf("ClickHouse session client is nil")
	}
	if _, err := client.execute(ctx, TrafficSessionTableDDL); err != nil {
		return fmt.Errorf("ensure ClickHouse traffic session table: %w", err)
	}
	return nil
}

func (client *HTTPClickHouse) InsertTrafficSession(ctx context.Context, session TrafficSessionRecord) error {
	if client == nil {
		return fmt.Errorf("ClickHouse session client is nil")
	}
	if strings.TrimSpace(session.SessionUID) == "" {
		return fmt.Errorf("traffic session UID is required")
	}
	if session.ObservedAt.IsZero() {
		return fmt.Errorf("traffic session observed time is required")
	}
	if session.Version == 0 {
		session.Version = uint64(time.Now().UTC().UnixNano())
	}
	if session.IngestedAt.IsZero() {
		session.IngestedAt = time.Now().UTC()
	}
	row := clickHouseTrafficSessionRow{
		SessionUID: session.SessionUID, Version: session.Version,
		ObservedAt: session.ObservedAt.UTC().Format("2006-01-02 15:04:05.000000"),
		AgentID:    session.AgentID, SrcIP: session.SrcIP, DstIP: session.DstIP,
		SrcPort: session.SrcPort, DstPort: session.DstPort, Protocol: session.Protocol,
		RawEvent: session.RawEvent, IngestedAt: session.IngestedAt.UTC().Format("2006-01-02 15:04:05.000000"),
	}
	payload, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("encode traffic session %s: %w", session.SessionUID, err)
	}
	query := "INSERT INTO lyflow_traffic_sessions FORMAT JSONEachRow\n" + string(payload)
	if _, err := client.execute(ctx, query); err != nil {
		return fmt.Errorf("insert ClickHouse traffic session %s: %w", session.SessionUID, err)
	}
	return nil
}

func (client *HTTPClickHouse) TrafficSessionCount(ctx context.Context) (uint64, error) {
	if client == nil {
		return 0, fmt.Errorf("ClickHouse session client is nil")
	}
	body, err := client.execute(ctx, "SELECT count() FROM lyflow_traffic_sessions FINAL")
	if err != nil {
		return 0, fmt.Errorf("count ClickHouse traffic sessions: %w", err)
	}
	count, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse ClickHouse traffic session count: %w", err)
	}
	return count, nil
}
