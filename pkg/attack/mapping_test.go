package attack

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestResolveMetadataTechnique(t *testing.T) {
	mapping := Resolve(Input{
		Metadata: map[string]string{
			"mitre_technique_id": "T1190",
			"mitre_tactic_id":    "TA0001",
		},
	})
	if mapping.TechniqueID != "T1190" || mapping.TacticID != "TA0001" {
		t.Fatalf("unexpected ids: %+v", mapping)
	}
	if mapping.Stage != contracts.StageInitialAccess || mapping.Confidence != 0.8 || mapping.Source != "metadata" {
		t.Fatalf("unexpected mapping: %+v", mapping)
	}
}

func TestResolveDerivesTacticFromTechnique(t *testing.T) {
	mapping := Resolve(Input{
		Metadata: map[string]string{"attack.technique": "T1059.004"},
	})
	if mapping.TacticID != "TA0002" || mapping.Stage != contracts.StageExecution {
		t.Fatalf("unexpected mapping: %+v", mapping)
	}
}

func TestResolveTagTechnique(t *testing.T) {
	mapping := Resolve(Input{Tags: []string{"web_attack", "attack.technique:T1505.003"}})
	if mapping.TechniqueID != "T1505.003" || mapping.TacticID != "TA0003" || mapping.Stage != contracts.StagePersistence {
		t.Fatalf("unexpected mapping: %+v", mapping)
	}
	if mapping.Source != "tag" {
		t.Fatalf("source = %q", mapping.Source)
	}
}

func TestResolveTacticOnly(t *testing.T) {
	mapping := Resolve(Input{Tags: []string{"attack.tactic:TA0008"}})
	if mapping.TacticID != "TA0008" || mapping.Stage != contracts.StageLateralMovement {
		t.Fatalf("unexpected mapping: %+v", mapping)
	}
	if mapping.Confidence != 0.6 {
		t.Fatalf("confidence = %v", mapping.Confidence)
	}
}

func TestResolveFallback(t *testing.T) {
	fallbacks := map[string]Mapping{
		"31101": {TacticID: "TA0001", TechniqueID: "T1190", Stage: contracts.StageInitialAccess, Confidence: 0.5, Source: "rule_id"},
	}
	mapping := ResolveWithFallback(Input{RuleID: "31101"}, fallbacks)
	if mapping.TechniqueID != "T1190" || mapping.Source != "rule_id" {
		t.Fatalf("unexpected fallback: %+v", mapping)
	}
}

func TestResolveUnknown(t *testing.T) {
	mapping := Resolve(Input{RuleID: "unknown"})
	if mapping.Stage != contracts.StageUnknown || mapping.Confidence != 0 || mapping.Source != "unmapped" {
		t.Fatalf("unexpected mapping: %+v", mapping)
	}
}

func TestLookups(t *testing.T) {
	if tactic, ok := TacticByID("ta0001"); !ok || tactic.Name != "Initial Access" {
		t.Fatalf("tactic lookup failed: %+v %v", tactic, ok)
	}
	if technique, ok := TechniqueByID("t1190"); !ok || technique.TacticID != "TA0001" {
		t.Fatalf("technique lookup failed: %+v %v", technique, ok)
	}
}
