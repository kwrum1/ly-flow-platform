package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveXDRRulesDirUsesEnvironmentOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDR_RULES_DIR", dir)

	if got := resolveXDRRulesDir(); got != dir {
		t.Fatalf("resolveXDRRulesDir() = %q, want %q", got, dir)
	}
}

func TestResolveXDRRulesDirFallsBackToRepositoryRules(t *testing.T) {
	t.Setenv("XDR_RULES_DIR", "")
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	repoRoot := filepath.Join("..", "..")
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}

	if got := resolveXDRRulesDir(); got != filepath.Join("rules", "xdr") {
		t.Fatalf("resolveXDRRulesDir() = %q, want %q", got, filepath.Join("rules", "xdr"))
	}
}
