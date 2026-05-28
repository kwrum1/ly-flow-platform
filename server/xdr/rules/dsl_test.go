package rules

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestConvertRuleToBehavior(t *testing.T) {
	rule := models.Rule{ID: 81005, Name: "RASP SQLi", Level: 10, Source: "rasp", Match: "union select", IsRegex: true, Groups: []string{"attack_chain:initial_access"}, Description: "SQL injection"}
	converted, err := ConvertRuleToBehavior(rule, "wazuh")
	if err != nil {
		t.Fatalf("ConvertRuleToBehavior() error = %v", err)
	}
	if converted.Metadata.ID != "wazuh-81005" || converted.Score.Severity != "high" || converted.Action.Type != "create_incident" {
		t.Fatalf("unexpected conversion: %#v", converted)
	}
	if converted.Match.When[0].Operator != "regex" || converted.Sequence[0].Match[0].Value != "rasp" {
		t.Fatalf("conversion lost behavior constraints: %#v", converted)
	}
	if len(converted.Tests.Positive) == 0 || len(converted.Tests.Negative) == 0 {
		t.Fatalf("expected positive and negative fixtures: %#v", converted.Tests)
	}
}

func TestConvertRuleToBehaviorRequiresIdentity(t *testing.T) {
	if _, err := ConvertRuleToBehavior(models.Rule{Name: "missing id"}, "sigma"); err == nil {
		t.Fatal("expected missing id error")
	}
}
