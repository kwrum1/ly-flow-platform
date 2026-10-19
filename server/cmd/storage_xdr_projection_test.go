package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func projectionFixture() contracts.EventV2 {
	now := time.Now().UTC()
	return contracts.EventV2{
		SchemaVersion: contracts.SecurityEventSchemaV2,
		EventUID:      "evt-projection-1",
		CorrelationID: "corr-projection-1",
		TenantID:      "default",
		Source:        contracts.SourceSuricata,
		EventType:     "network.signature",
		Timestamps: contracts.EventTimestamps{
			EventAt:    now.Add(-time.Minute),
			ObservedAt: now.Add(-time.Minute),
			IngestedAt: now,
		},
		Entities: contracts.Entities{
			Asset: &contracts.AssetEntity{ID: "agent-1", Hostname: "host-1"},
			Network: &contracts.NetworkEntity{
				SrcIP: "10.0.0.10", SrcPort: 12345,
				DstIP: "10.0.0.20", DstPort: 443, Proto: "tcp",
			},
		},
		Detection: contracts.Detection{
			RuleID:      "1000001",
			Severity:    contracts.SeverityHigh,
			Confidence:  0.86,
			TacticID:    "TA0001",
			TechniqueID: "T1190",
			Stage:       contracts.StageInitialAccess,
			Description: "web exploit",
		},
		Payload: json.RawMessage(`{"http":{"method":"POST"}}`),
		Raw: contracts.RawRef{
			NativeSchema:  contracts.NativeSuricataEVE,
			NativeEventID: "evt-1",
			Adapter:       "contracts.suricataEVEAdapter",
			PayloadSHA256: strings.Repeat("a", 64),
		},
		QualityFlags: []contracts.QualityFlag{contracts.QualityNormalized},
		Governance: contracts.GovernanceMetadata{
			Classification: contracts.ClassificationInternal,
			Retention: contracts.RetentionPolicy{
				PolicyID:  contracts.RetentionPolicySecurityEvent30D,
				ExpiresAt: now.Add(30 * 24 * time.Hour),
			},
			Encryption: contracts.EncryptionMetadata{
				Required: true, Algorithm: contracts.EncryptionAlgorithmAES256GCM,
				KeyRef: "kms://lyflow/security-event",
			},
			AccessPolicyID:   contracts.AccessPolicySecurityEventRead,
			DeletionPolicyID: contracts.DeletionPolicySecurityEvent,
			ExportPolicyID:   contracts.ExportPolicySecurityEvent,
		},
	}
}

func TestCanonicalProjectionFromV2CarriesAttackAndNetworkContext(t *testing.T) {
	projection, err := canonicalProjectionFromV2(projectionFixture())
	if err != nil {
		t.Fatalf("projection failed: %v", err)
	}
	if projection.Identity.AgentID != "agent-1" || projection.Identity.PrincipalID != "agent-1" {
		t.Fatalf("identity = %#v, want agent-1", projection.Identity)
	}
	if projection.CorrelationID != "corr-projection-1" {
		t.Fatalf("correlation = %q", projection.CorrelationID)
	}
	if projection.Attack.TacticID != "TA0001" || projection.Attack.TechniqueID != "T1190" {
		t.Fatalf("attack = %#v", projection.Attack)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(projection.Payload, &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if payload["stage_hint"] != "initial_access" || payload["src_ip"] != "10.0.0.10" || payload["dst_ip"] != "10.0.0.20" {
		t.Fatalf("projection payload = %#v", payload)
	}
}

func TestCanonicalProjectionFromV2RequiresAssetIdentity(t *testing.T) {
	event := projectionFixture()
	event.Entities.Asset = nil
	if _, err := canonicalProjectionFromV2(event); err == nil {
		t.Fatal("expected projection without asset identity to be rejected")
	}
}

func TestCanonicalProjectionFromV2FallsBackToEventUIDCorrelation(t *testing.T) {
	event := projectionFixture()
	event.CorrelationID = ""
	projection, err := canonicalProjectionFromV2(event)
	if err != nil {
		t.Fatalf("projection failed: %v", err)
	}
	if projection.CorrelationID != event.EventUID {
		t.Fatalf("correlation = %q, want %q", projection.CorrelationID, event.EventUID)
	}
}
