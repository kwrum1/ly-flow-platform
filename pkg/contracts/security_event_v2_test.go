package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validV2Governance() GovernanceMetadata {
	return GovernanceMetadata{
		Classification: ClassificationInternal,
		Retention: RetentionPolicy{
			PolicyID:  RetentionPolicySecurityEvent30D,
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		},
		Encryption: EncryptionMetadata{
			Required:  true,
			Algorithm: EncryptionAlgorithmAES256GCM,
			KeyRef:    "kms://lyflow/security-event",
		},
		AccessPolicyID:   AccessPolicySecurityEventRead,
		DeletionPolicyID: DeletionPolicySecurityEvent,
		ExportPolicyID:   ExportPolicySecurityEvent,
	}
}

func validV2Raw() RawRef {
	return RawRef{
		NativeSchema:  NativeSuricataEVE,
		NativeEventID: "evt-1",
		Adapter:       "contracts.suricataEVEAdapter",
		PayloadSHA256: strings.Repeat("a", 64),
	}
}

func validV2Event() EventV2 {
	now := time.Now().UTC()
	return EventV2{
		SchemaVersion: SecurityEventSchemaV2,
		EventUID:      "evt-1",
		CorrelationID: "corr-1",
		TenantID:      "default",
		Source:        SourceSuricata,
		EventType:     "network.signature",
		Timestamps: EventTimestamps{
			EventAt:    now.Add(-time.Second),
			ObservedAt: now,
			IngestedAt: now,
		},
		Entities: Entities{
			Asset: &AssetEntity{ID: "agent-1", IP: "10.0.0.10"},
			Network: &NetworkEntity{
				SrcIP: "10.0.0.10", SrcPort: 12345,
				DstIP: "10.0.0.20", DstPort: 443, Proto: "tcp",
			},
		},
		Detection: Detection{
			RuleID:        "1000001",
			RuleVersion:   "7.0.11",
			RuleSource:    "et-open",
			Severity:      SeverityHigh,
			Confidence:    0.86,
			TacticID:      "TA0001",
			TechniqueID:   "T1190",
			Stage:         StageInitialAccess,
			Description:   "web exploit",
			MappingSource: "rule_metadata",
		},
		Evidence: []EvidenceRef{
			{Type: EvidencePCAP, Ref: "pcap/flow-1", SHA256: strings.Repeat("b", 64), Size: 1024},
		},
		Payload: json.RawMessage(`{"http":{"method":"POST"}}`),
		Raw:     validV2Raw(),
		QualityFlags: []QualityFlag{
			QualityNormalized,
		},
		Governance: validV2Governance(),
	}
}

func TestEventV2Validate(t *testing.T) {
	if err := validV2Event().Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
}

func TestEventV2RejectsMissingIdentity(t *testing.T) {
	event := validV2Event()
	event.EventUID = ""
	if err := event.Validate(); err == nil {
		t.Fatal("expected missing event uid to be rejected")
	}
}

func TestEventV2RejectsUnknownSource(t *testing.T) {
	event := validV2Event()
	event.Source = EventSource("unknown")
	if err := event.Validate(); err == nil {
		t.Fatal("expected unknown source to be rejected")
	}
}

func TestEventV2RejectsEmptyEntities(t *testing.T) {
	event := validV2Event()
	event.Entities = Entities{}
	if err := event.Validate(); err == nil {
		t.Fatal("expected empty entities to be rejected")
	}
}

func TestEventV2RejectsInvalidConfidence(t *testing.T) {
	event := validV2Event()
	event.Detection.Confidence = 1.5
	if err := event.Validate(); err == nil {
		t.Fatal("expected confidence > 1 to be rejected")
	}
}

func TestEventV2RejectsInvalidTechnique(t *testing.T) {
	event := validV2Event()
	event.Detection.TechniqueID = "T-1"
	if err := event.Validate(); err == nil {
		t.Fatal("expected invalid technique to be rejected")
	}
}

func TestEventV2RejectsUnknownStage(t *testing.T) {
	event := validV2Event()
	event.Detection.Stage = "not_a_stage"
	if err := event.Validate(); err == nil {
		t.Fatal("expected unknown stage to be rejected")
	}
}

func TestEventV2RejectsEvidenceWithoutHash(t *testing.T) {
	event := validV2Event()
	event.Evidence = []EvidenceRef{{Type: EvidencePCAP, Ref: "pcap/flow-1"}}
	if err := event.Validate(); err == nil {
		t.Fatal("expected pcap without hash to be rejected")
	}
}

func TestEventV2RejectsInvalidRawDigest(t *testing.T) {
	event := validV2Event()
	event.Raw.PayloadSHA256 = "not-a-digest"
	if err := event.Validate(); err == nil {
		t.Fatal("expected invalid raw digest to be rejected")
	}
}

func TestEventV2RejectsDuplicateQualityFlags(t *testing.T) {
	event := validV2Event()
	event.QualityFlags = []QualityFlag{QualityNormalized, QualityNormalized}
	if err := event.Validate(); err == nil {
		t.Fatal("expected duplicate quality flags to be rejected")
	}
}

func TestEventV2RejectsMissingEncryption(t *testing.T) {
	event := validV2Event()
	event.Governance.Encryption = EncryptionMetadata{}
	if err := event.Validate(); err == nil {
		t.Fatal("expected missing encryption to be rejected")
	}
}

func TestStageForTactic(t *testing.T) {
	cases := map[string]AttackStage{
		"TA0043": StageRecon,
		"TA0001": StageInitialAccess,
		"TA0002": StageExecution,
		"TA0003": StagePersistence,
		"TA0004": StagePrivilegeEscalation,
		"TA0005": StageDefenseEvasion,
		"TA0006": StageCredentialAccess,
		"TA0007": StageDiscovery,
		"TA0008": StageLateralMovement,
		"TA0009": StageCollection,
		"TA0011": StageCommandControl,
		"TA0010": StageExfiltration,
		"TA0040": StageImpact,
		"":       StageUnknown,
		"TA9999": StageUnknown,
	}
	for tactic, want := range cases {
		if got := StageForTactic(tactic); got != want {
			t.Errorf("StageForTactic(%q) = %q, want %q", tactic, got, want)
		}
	}
}

func validV1Event() CanonicalSecurityEvent {
	now := time.Now().UTC()
	return CanonicalSecurityEvent{
		SchemaVersion: SecurityEventSchemaVersion,
		EventUID:      "evt-v1",
		CorrelationID: "corr-v1",
		EventType:     "process.exec",
		Severity:      SeverityMedium,
		Identity: SourceIdentity{
			PrincipalID: "agent-1",
			AgentID:     "agent-1",
			Component:   "agent.runtime",
		},
		Timestamps: EventTimestamps{
			EventAt:    now.Add(-time.Second),
			ObservedAt: now,
			IngestedAt: now,
		},
		Provenance: EventProvenance{
			Source:        SourceAgentRuntime,
			NativeSchema:  NativeTelemetryV1,
			NativeEventID: "native-1",
			Adapter:       "contracts.nativeTelemetryAdapter",
			PayloadSHA256: strings.Repeat("c", 64),
		},
		Attack: AttackMapping{
			TacticID:    "TA0002",
			TechniqueID: "T1059",
			Version:     AttackMappingVersion,
		},
		QualityFlags: []QualityFlag{QualityNormalized},
		Governance:   validV2Governance(),
		Payload:      json.RawMessage(`{"process":{"exe":"/bin/sh"}}`),
	}
}

func TestFromCanonicalV1(t *testing.T) {
	v1 := validV1Event()
	if err := v1.Validate(); err != nil {
		t.Fatalf("test v1 event invalid: %v", err)
	}
	v2, err := FromCanonicalV1(v1)
	if err != nil {
		t.Fatalf("adapt v1: %v", err)
	}
	if v2.SchemaVersion != SecurityEventSchemaV2 {
		t.Fatalf("schema = %q, want %q", v2.SchemaVersion, SecurityEventSchemaV2)
	}
	if v2.Detection.Stage != StageExecution {
		t.Fatalf("stage = %q, want %q", v2.Detection.Stage, StageExecution)
	}
	if v2.Entities.Asset == nil || v2.Entities.Asset.ID != "agent-1" {
		t.Fatalf("asset entity not synthesized: %+v", v2.Entities.Asset)
	}
	if err := v2.Validate(); err != nil {
		t.Fatalf("adapted v2 event invalid: %v", err)
	}
}

func TestFromCanonicalV1RejectsInvalid(t *testing.T) {
	v1 := validV1Event()
	v1.EventUID = ""
	if _, err := FromCanonicalV1(v1); err == nil {
		t.Fatal("expected invalid v1 event to be rejected")
	}
}
