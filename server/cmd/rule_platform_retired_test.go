package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRetiredDefaultRuleID(t *testing.T) {
	for _, id := range []string{"dpi-admin-access-default", "log-collector-heartbeat-default"} {
		if !retiredDefaultRuleID(id) {
			t.Fatalf("%s should be retired", id)
		}
	}
	for _, id := range []string{"dpi-scanner-user-agent-default", "rasp-sqli-default", ""} {
		if retiredDefaultRuleID(id) {
			t.Fatalf("%s should not be retired", id)
		}
	}
}

func TestRetiredDefaultRulesAreNotBundled(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "security-engine", "default-bundle.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read default bundle: %v", err)
	}
	var bundle compiledBundleFile
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("decode default bundle: %v", err)
	}
	for _, rule := range bundle.Rules {
		if retiredDefaultRuleID(rule.ID) {
			t.Fatalf("retired rule %s is still shipped in default-bundle.json", rule.ID)
		}
	}
}
