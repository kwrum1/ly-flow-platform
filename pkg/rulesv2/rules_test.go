package rulesv2

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestRuleEnvelopeValidate(t *testing.T) {
	rule := RuleEnvelope{SchemaVersion: SchemaVersion, ID: "rasp-1", Name: "SQLi", Category: contracts.TelemetryRASP, Enabled: true, Source: RuleSource{Origin: "internal"}, Support: RuleSupport{Level: SupportFull}, Classification: RuleClassification{Stage: "initial_access"}, Scoring: RuleScoring{BaseScore: 90, Severity: "critical"}, RASP: &RaspRuleSpec{Languages: []string{"java"}, HookTypes: []string{"sql"}, Conditions: []MatchCondition{{Field: "query", Operator: "regex", Value: "(?i)union select", Regex: true}}}, HotReloadable: true}
	if err := rule.Validate(); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	rule.DPI = &DpiRuleSpec{}
	if err := rule.Validate(); err == nil {
		t.Fatal("expected multiple specs to be rejected")
	}
}

func TestUnsupportedEnabledRuleRejected(t *testing.T) {
	rule := RuleEnvelope{SchemaVersion: SchemaVersion, ID: "bad", Name: "bad", Category: contracts.TelemetryRuntime, Enabled: true, Support: RuleSupport{Level: SupportUnsupported}, Scoring: RuleScoring{BaseScore: 0}, Runtime: &RuntimeRuleSpec{Conditions: []MatchCondition{{Field: "cmd", Operator: "contains", Value: "x"}}}}
	if err := rule.Validate(); err == nil {
		t.Fatal("expected unsupported enabled rule to be rejected")
	}
}
