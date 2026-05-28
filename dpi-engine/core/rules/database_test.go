package rules

import (
	"path/filepath"
	"testing"

	"ly-flow-platform/dpi-engine/model"
)

func TestLoadDatabaseRulesLoadsMountedPack(t *testing.T) {
	engine := New()
	if err := engine.LoadDatabaseRules(filepath.Join("..", "..", "rules", "database")); err != nil {
		t.Fatalf("load database rules: %v", err)
	}
	if engine.RuleCount() == 0 {
		t.Fatal("expected database rules to be loaded")
	}
}

func TestLoadDatabaseRulesMissingDirectoryReturnsError(t *testing.T) {
	if err := New().LoadDatabaseRules(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected missing database rules directory to return an error")
	}
}

func TestDatabaseRuleMatchesDatabasePort(t *testing.T) {
	engine := New()
	if err := engine.LoadDatabaseRules(filepath.Join("..", "..", "rules", "database")); err != nil {
		t.Fatalf("load database rules: %v", err)
	}
	matches := engine.Match(&model.FlowData{Protocol: "tcp", AppProtocol: "mysql union select password from users", DstPort: 3306})
	if len(matches) == 0 {
		t.Fatal("expected mysql database rule to match tcp/3306 flow")
	}
}
