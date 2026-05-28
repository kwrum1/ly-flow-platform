package rules

import "testing"

func TestDefaultSyncSourcesMarksRASPStatic(t *testing.T) {
	sources := DefaultSyncSources()
	foundRASP := false
	foundWazuh := false
	for _, source := range sources {
		switch source.Name {
		case "rasp":
			foundRASP = true
			if source.Updatable || !source.Static {
				t.Fatalf("RASP source should be static and not updatable: %#v", source)
			}
		case "wazuh":
			foundWazuh = true
			if !source.Updatable || source.Static {
				t.Fatalf("Wazuh source should be updatable: %#v", source)
			}
		}
	}
	if !foundRASP || !foundWazuh {
		t.Fatalf("expected both rasp and wazuh sources, got %#v", sources)
	}
}

func TestDryRunRequiresOperatorApproval(t *testing.T) {
	result, err := DryRunSync("sigma")
	if err != nil {
		t.Fatalf("DryRunSync() error = %v", err)
	}
	if !result.DryRun || !result.RequiresApproval {
		t.Fatalf("expected dry-run approval gate: %#v", result)
	}
}

func TestRuleLifecycleEnableAndRollback(t *testing.T) {
	state := EnableRule(LifecycleState{RuleID: "r1", Version: 3, Source: "sigma"}, "operator")
	if !state.Enabled || len(state.Audit) == 0 {
		t.Fatalf("expected enabled audited state: %#v", state)
	}
	rolledBack, err := RollbackRule(state, 2, "operator")
	if err != nil {
		t.Fatalf("RollbackRule() error = %v", err)
	}
	if rolledBack.Version != 2 || rolledBack.Enabled {
		t.Fatalf("unexpected rollback state: %#v", rolledBack)
	}
}

func TestDryRunSyncRejectsRASP(t *testing.T) {
	if _, err := DryRunSync("rasp"); err == nil {
		t.Fatal("expected RASP dry-run sync to be rejected")
	}
}

func TestDryRunSyncForWazuhIsSafe(t *testing.T) {
	result, err := DryRunSync("wazuh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Source != "wazuh" || !result.DryRun {
		t.Fatalf("unexpected dry-run result: %#v", result)
	}
}
