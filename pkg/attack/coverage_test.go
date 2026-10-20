package attack

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func coverageEvent(technique, tactic string) contracts.EventV2 {
	return contracts.EventV2{Detection: contracts.Detection{TechniqueID: technique, TacticID: tactic}}
}

func TestBuildCoverage(t *testing.T) {
	events := []contracts.EventV2{
		coverageEvent("T1190", "TA0001"),
		coverageEvent("T1059", ""),
		coverageEvent("T1071.001", "TA0011"),
		coverageEvent("T1190", "TA0001"),
	}
	report := BuildCoverage(events)
	if report.ObservedTechniques != 3 {
		t.Fatalf("observed = %d", report.ObservedTechniques)
	}
	if report.KnownTechniques == 0 || report.KnownTactics == 0 {
		t.Fatalf("unexpected known counts: %+v", report)
	}
	if report.Coverage <= 0 || report.Coverage > 1 {
		t.Fatalf("coverage = %v", report.Coverage)
	}
	initialAccess := findTactic(report, "TA0001")
	if initialAccess == nil || initialAccess.Techniques[0].TechniqueID != "T1190" || initialAccess.Techniques[0].Count != 2 {
		t.Fatalf("initial access = %+v", initialAccess)
	}
	execution := findTactic(report, "TA0002")
	if execution == nil || len(execution.Techniques) != 1 || execution.Techniques[0].TechniqueID != "T1059" {
		t.Fatalf("execution = %+v", execution)
	}
}

func TestBuildCoverageIgnoresUnknown(t *testing.T) {
	report := BuildCoverage([]contracts.EventV2{coverageEvent("T9999", ""), coverageEvent("", "")})
	if report.ObservedTechniques != 0 {
		t.Fatalf("observed = %d", report.ObservedTechniques)
	}
	if len(report.Tactics) != len(Tactics) {
		t.Fatalf("tactics = %d", len(report.Tactics))
	}
}

func findTactic(report Coverage, id string) *TacticCoverage {
	for index := range report.Tactics {
		if report.Tactics[index].TacticID == id {
			return &report.Tactics[index]
		}
	}
	return nil
}
