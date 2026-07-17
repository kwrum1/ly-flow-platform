package rasp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadElkeidRules_decodes_yaml_rules(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "rules.yaml")
	contents := []byte("version: \"1\"\nsource: fixture\nrules:\n  - id: E1\n    category: command_exec\n    name: inert fixture\n    severity: high\n    languages: [python]\n    action: detect\n    enabled: true\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// When
	rules, err := LoadElkeidRules(path)

	// Then
	if err != nil {
		t.Fatalf("load YAML rules: %v", err)
	}
	if len(rules.Rules) != 1 || rules.Rules[0].ID != "E1" || rules.Rules[0].Languages[0] != "python" {
		t.Fatalf("decoded rules = %#v", rules.Rules)
	}
}

func TestLoadElkeidRules_decodes_packaged_policy_rules(t *testing.T) {
	// Given
	path := filepath.Join("..", "..", "..", "rules", "rasp", "elkeid_rasp_rules.yaml")

	// When
	rules, err := LoadElkeidRules(path)

	// Then
	if err != nil {
		t.Fatalf("load packaged YAML rules: %v", err)
	}
	if rules.Version == "" || len(rules.Rules) == 0 {
		t.Fatalf("packaged rules incomplete: version=%q count=%d", rules.Version, len(rules.Rules))
	}
}
