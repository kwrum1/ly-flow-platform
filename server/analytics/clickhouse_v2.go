package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
)

// InsertEventsV2 writes canonical v2 events to ClickHouse using JSONEachRow.
// The caller is responsible for validating events before calling this method.
func (client *HTTPClickHouse) InsertEventsV2(ctx context.Context, events []contracts.EventV2) error {
	if len(events) == 0 {
		return nil
	}
	rows := make([]string, 0, len(events))
	for _, event := range events {
		row := clickHouseEventV2RowFrom(event)
		payload, err := json.Marshal(row)
		if err != nil {
			return fmt.Errorf("encode ClickHouse v2 event %s: %w", event.EventUID, err)
		}
		rows = append(rows, string(payload))
	}
	query := "INSERT INTO lyflow_events_v2 FORMAT JSONEachRow\n" + strings.Join(rows, "\n")
	if _, err := client.execute(ctx, query); err != nil {
		return fmt.Errorf("insert ClickHouse v2 events: %w", err)
	}
	return nil
}

type clickHouseEventV2Row struct {
	EventUID      string  `json:"event_uid"`
	CorrelationID string  `json:"correlation_id"`
	TenantID      string  `json:"tenant_id"`
	Source        string  `json:"source"`
	EventType     string  `json:"event_type"`
	EventAt       string  `json:"event_at"`
	ObservedAt    string  `json:"observed_at"`
	IngestedAt    string  `json:"ingested_at"`
	AssetID       string  `json:"asset_id"`
	UserID        string  `json:"user_id"`
	ProcessPID    int     `json:"process_pid"`
	ProcessExe    string  `json:"process_exe"`
	FileHash      string  `json:"file_hash"`
	SrcIP         string  `json:"src_ip"`
	DstIP         string  `json:"dst_ip"`
	SrcPort       uint16  `json:"src_port"`
	DstPort       uint16  `json:"dst_port"`
	SrcPortKnown  uint8   `json:"src_port_known"`
	DstPortKnown  uint8   `json:"dst_port_known"`
	Proto         string  `json:"proto"`
	RuleID        string  `json:"rule_id"`
	RuleSource    string  `json:"rule_source"`
	Severity      string  `json:"severity"`
	Confidence    float32 `json:"confidence"`
	TacticID      string  `json:"tactic_id"`
	TechniqueID   string  `json:"technique_id"`
	Stage         string  `json:"stage"`
	EvidenceCount uint16  `json:"evidence_count"`
	EvidenceJSON  string  `json:"evidence_json"`
	PayloadJSON   string  `json:"payload_json"`
	RawSchema     string  `json:"raw_schema"`
	RawEventID    string  `json:"raw_event_id"`
	RawSHA256     string  `json:"raw_sha256"`
}

func clickHouseEventV2RowFrom(event contracts.EventV2) clickHouseEventV2Row {
	row := clickHouseEventV2Row{
		EventUID:      event.EventUID,
		CorrelationID: event.CorrelationID,
		TenantID:      event.TenantID,
		Source:        string(event.Source),
		EventType:     event.EventType,
		EventAt:       event.Timestamps.EventAt.UTC().Format("2006-01-02 15:04:05.000"),
		ObservedAt:    event.Timestamps.ObservedAt.UTC().Format("2006-01-02 15:04:05.000"),
		IngestedAt:    event.Timestamps.IngestedAt.UTC().Format("2006-01-02 15:04:05.000"),
		RuleID:        event.Detection.RuleID,
		RuleSource:    event.Detection.RuleSource,
		Severity:      string(event.Detection.Severity),
		Confidence:    float32(event.Detection.Confidence),
		TacticID:      event.Detection.TacticID,
		TechniqueID:   event.Detection.TechniqueID,
		Stage:         string(event.Detection.Stage),
		EvidenceCount: uint16(len(event.Evidence)),
		RawSchema:     event.Raw.NativeSchema,
		RawEventID:    event.Raw.NativeEventID,
		RawSHA256:     event.Raw.PayloadSHA256,
	}
	if event.Entities.Asset != nil {
		row.AssetID = event.Entities.Asset.ID
	}
	if event.Entities.User != nil {
		row.UserID = event.Entities.User.ID
	}
	if event.Entities.Process != nil {
		row.ProcessPID = event.Entities.Process.PID
		row.ProcessExe = event.Entities.Process.Exe
	}
	if event.Entities.File != nil {
		row.FileHash = event.Entities.File.Hash
	}
	if event.Entities.Network != nil {
		row.SrcIP = event.Entities.Network.SrcIP
		row.DstIP = event.Entities.Network.DstIP
		row.SrcPort = clampPort(event.Entities.Network.SrcPort)
		row.DstPort = clampPort(event.Entities.Network.DstPort)
		row.SrcPortKnown = portKnown(event, contracts.QualityMissingSrcPort, event.Entities.Network.SrcPort)
		row.DstPortKnown = portKnown(event, contracts.QualityMissingDstPort, event.Entities.Network.DstPort)
		row.Proto = event.Entities.Network.Proto
	}
	if len(event.Evidence) > 0 {
		if encoded, err := json.Marshal(event.Evidence); err == nil {
			row.EvidenceJSON = string(encoded)
		}
	}
	if len(event.Payload) > 0 {
		row.PayloadJSON = string(event.Payload)
	}
	return row
}

func clampPort(port int) uint16 {
	if port < 0 {
		return 0
	}
	if port > 65535 {
		return 65535
	}
	return uint16(port)
}

// portKnown decides whether the stored port is a real observation. A port is
// unknown when the producer flagged it missing, or when the value is outside
// 1..65535. A zero port is never a real observation: the legacy pipeline used 0
// as the "missing" sentinel.
func portKnown(event contracts.EventV2, missingFlag contracts.QualityFlag, port int) uint8 {
	if event.HasQualityFlag(missingFlag) {
		return 0
	}
	if port <= 0 || port > 65535 {
		return 0
	}
	return 1
}
