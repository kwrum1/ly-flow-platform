package analytics

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestClickHouseEventV2RowFrom(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	event := contracts.EventV2{
		SchemaVersion: contracts.SecurityEventSchemaV2,
		EventUID:      "evt-1",
		CorrelationID: "corr-1",
		TenantID:      "default",
		Source:        contracts.SourceSuricata,
		EventType:     "network.signature",
		Timestamps: contracts.EventTimestamps{
			EventAt: now, ObservedAt: now, IngestedAt: now,
		},
		Entities: contracts.Entities{
			Asset:   &contracts.AssetEntity{ID: "asset-1"},
			User:    &contracts.UserEntity{ID: "user-1"},
			Process: &contracts.ProcessEntity{PID: 1234, Exe: "/bin/sh"},
			File:    &contracts.FileEntity{Hash: "abc"},
			Network: &contracts.NetworkEntity{
				SrcIP: "10.0.0.1", SrcPort: 70000,
				DstIP: "10.0.0.2", DstPort: 443, Proto: "tcp",
			},
		},
		Detection: contracts.Detection{
			RuleID: "1000001", RuleSource: "et-open", Severity: contracts.SeverityHigh,
			Confidence: 0.9, TacticID: "TA0001", TechniqueID: "T1190",
			Stage: contracts.StageInitialAccess,
		},
		Evidence: []contracts.EvidenceRef{{Type: contracts.EvidencePCAP, Ref: "pcap/1", SHA256: strings.Repeat("a", 64)}},
		Payload:  json.RawMessage(`{"http":{"method":"POST"}}`),
		Raw: contracts.RawRef{
			NativeSchema: "suricata.eve.v7", NativeEventID: "native-1",
			Adapter: "adapter", PayloadSHA256: strings.Repeat("b", 64),
		},
	}

	row := clickHouseEventV2RowFrom(event)
	if row.EventUID != "evt-1" || row.AssetID != "asset-1" || row.UserID != "user-1" {
		t.Fatalf("identity mapping failed: %+v", row)
	}
	if row.ProcessPID != 1234 || row.ProcessExe != "/bin/sh" || row.FileHash != "abc" {
		t.Fatalf("entity mapping failed: %+v", row)
	}
	if row.SrcPort != 65535 || row.DstPort != 443 || row.Proto != "tcp" {
		t.Fatalf("network mapping failed: %+v", row)
	}
	if row.SrcPortKnown != 0 || row.DstPortKnown != 1 {
		t.Fatalf("port known flags wrong: src=%d dst=%d", row.SrcPortKnown, row.DstPortKnown)
	}
	if row.EvidenceCount != 1 || row.EvidenceJSON == "" {
		t.Fatalf("evidence mapping failed: %+v", row)
	}
	if row.EventAt != "2026-10-19 12:00:00.000" {
		t.Fatalf("timestamp = %q", row.EventAt)
	}
}
