package incident

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

func event(uid string, stageName contracts.AttackStage, source contracts.EventSource, severity contracts.AlertSeverity, technique string, at time.Time) contracts.EventV2 {
	return contracts.EventV2{
		SchemaVersion: contracts.SecurityEventSchemaV2,
		EventUID:      uid,
		TenantID:      "default",
		Source:        source,
		EventType:     "test.event",
		Timestamps:    contracts.EventTimestamps{EventAt: at, ObservedAt: at, IngestedAt: at},
		Entities: contracts.Entities{
			Asset:   &contracts.AssetEntity{ID: "asset-1"},
			Process: &contracts.ProcessEntity{PID: 100, Exe: "/bin/sh"},
			Network: &contracts.NetworkEntity{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 443},
		},
		Detection: contracts.Detection{
			RuleID: "rule-" + uid, Severity: severity, Confidence: 0.9,
			TechniqueID: technique, Stage: stageName,
		},
		Payload: []byte(`{"test":true}`),
	}
}

func TestBuildChain(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	events := []contracts.EventV2{
		event("e1", contracts.StageInitialAccess, contracts.SourceSuricata, contracts.SeverityHigh, "T1190", start),
		event("e2", contracts.StageExecution, contracts.SourceAgentRuntime, contracts.SeverityHigh, "T1059", start.Add(time.Minute)),
		event("e3", contracts.StageCommandControl, contracts.SourceSuricata, contracts.SeverityCritical, "T1071.001", start.Add(2*time.Minute)),
	}
	report, err := Builder{Tenant: "default"}.Build("chain-1", "Web 攻击链", events)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if report.Candidate.Severity != "critical" {
		t.Fatalf("severity = %q", report.Candidate.Severity)
	}
	if len(report.Candidate.Evidence) != 3 {
		t.Fatalf("evidence = %d", len(report.Candidate.Evidence))
	}
	if report.Stages.Current != contracts.StageCommandControl {
		t.Fatalf("stage = %q", report.Stages.Current)
	}
	if len(report.Stages.Reached) != 3 {
		t.Fatalf("reached = %+v", report.Stages.Reached)
	}
	if len(report.Techniques) != 3 {
		t.Fatalf("techniques = %+v", report.Techniques)
	}
	if report.Candidate.FirstSeen.After(report.Candidate.LastSeen) {
		t.Fatalf("time order: %+v", report.Candidate)
	}
	if _, err := incidentlifecycle.NewActiveSnapshot(incidentlifecycle.ActiveAlgorithm, []incidentlifecycle.Candidate{report.Candidate}); err != nil {
		t.Fatalf("candidate rejected: %v", err)
	}
}

func TestBuildRejectsEmpty(t *testing.T) {
	if _, err := (Builder{}).Build("chain", "", nil); err != ErrNoEvents {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildRejectsUnmappedStage(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	event := event("e1", contracts.StageUnknown, contracts.SourceSuricata, contracts.SeverityLow, "", start)
	if _, err := (Builder{}).Build("chain", "", []contracts.EventV2{event}); err != ErrNoStage {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildDerivesStageFromTactic(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	event := event("e1", "", contracts.SourceSuricata, contracts.SeverityHigh, "T1190", start)
	event.Detection.TacticID = "TA0001"
	report, err := (Builder{}).Build("chain", "", []contracts.EventV2{event})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if report.Stages.Current != contracts.StageInitialAccess {
		t.Fatalf("stage = %q", report.Stages.Current)
	}
}
