package incident

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestValidatedAttackChains(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		events    []contracts.EventV2
		wantStage contracts.AttackStage
		wantTech  int
	}{
		{
			name: "web exploit to C2",
			events: []contracts.EventV2{
				event("web-1", contracts.StageInitialAccess, contracts.SourceSuricata, contracts.SeverityHigh, "T1190", start),
				event("web-2", contracts.StageExecution, contracts.SourceAgentRuntime, contracts.SeverityHigh, "T1059", start.Add(time.Minute)),
				event("web-3", contracts.StageCommandControl, contracts.SourceSuricata, contracts.SeverityCritical, "T1071.001", start.Add(2*time.Minute)),
			},
			wantStage: contracts.StageCommandControl,
			wantTech:  3,
		},
		{
			name: "credential access to lateral movement",
			events: []contracts.EventV2{
				event("ssh-1", contracts.StageCredentialAccess, contracts.SourceWazuh, contracts.SeverityHigh, "T1110", start),
				event("ssh-2", contracts.StageDiscovery, contracts.SourceAgentLogAudit, contracts.SeverityMedium, "T1046", start.Add(time.Minute)),
				event("ssh-3", contracts.StageLateralMovement, contracts.SourceWazuh, contracts.SeverityCritical, "T1021.004", start.Add(2*time.Minute)),
			},
			wantStage: contracts.StageLateralMovement,
			wantTech:  3,
		},
		{
			name: "webshell to privilege escalation",
			events: []contracts.EventV2{
				event("shell-1", contracts.StageInitialAccess, contracts.SourceSuricata, contracts.SeverityHigh, "T1190", start),
				event("shell-2", contracts.StagePersistence, contracts.SourceAgentRuntime, contracts.SeverityHigh, "T1505.003", start.Add(time.Minute)),
				event("shell-3", contracts.StagePrivilegeEscalation, contracts.SourceAgentRuntime, contracts.SeverityCritical, "T1068", start.Add(2*time.Minute)),
			},
			wantStage: contracts.StagePrivilegeEscalation,
			wantTech:  3,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			report, err := Builder{Tenant: "default"}.Build(testCase.name, testCase.name, testCase.events)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if report.Stages.Current != testCase.wantStage {
				t.Fatalf("stage = %q, want %q", report.Stages.Current, testCase.wantStage)
			}
			if len(report.Candidate.Evidence) != len(testCase.events) {
				t.Fatalf("evidence = %d, want %d", len(report.Candidate.Evidence), len(testCase.events))
			}
			if len(report.Techniques) != testCase.wantTech {
				t.Fatalf("techniques = %+v, want %d", report.Techniques, testCase.wantTech)
			}
			if report.Candidate.Severity != string(contracts.SeverityCritical) {
				t.Fatalf("severity = %q", report.Candidate.Severity)
			}
		})
	}
}
