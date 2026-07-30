package main

import "testing"

func TestMergeCompiledRuntimeRules_replacesSourceRulesAndPreservesCoverage(t *testing.T) {
	base := []compiledRuntimeRule{
		{ID: "shared", Category: "runtime", Name: "old"},
		{ID: "traffic-rule", Category: "traffic", Name: "traffic"},
	}
	updates := []compiledRuntimeRule{
		{ID: "shared", Category: "runtime", Name: "new"},
		{ID: "rasp-rule", Category: "rasp", Name: "rasp"},
	}

	merged := mergeCompiledRuntimeRules(base, updates)
	if len(merged) != 3 {
		t.Fatalf("merged rule count = %d, want 3", len(merged))
	}
	byID := map[string]compiledRuntimeRule{}
	for _, rule := range merged {
		byID[rule.ID] = rule
	}
	if byID["shared"].Name != "new" || byID["traffic-rule"].Name != "traffic" || byID["rasp-rule"].Name != "rasp" {
		t.Fatalf("unexpected merged rules: %+v", merged)
	}
}
