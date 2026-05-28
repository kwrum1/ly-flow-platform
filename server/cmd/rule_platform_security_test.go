package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/guardmode"
)

func TestValidateRuleSourceURLRejectsLocalSchemesAndMetadata(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"/tmp/rules.yaml",
		"http://127.0.0.1/rules.yaml",
		"http://localhost/rules.yaml",
		"http://169.254.169.254/latest/meta-data",
		"gopher://example.com/rules",
	} {
		t.Run(raw, func(t *testing.T) {
			if err := validateRuleSourceURL(raw); err == nil {
				t.Fatalf("expected %q to be rejected", raw)
			}
		})
	}
}

func TestCompiledRuntimeRuleValidRejectsInvalidRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule compiledRuntimeRule
	}{
		{name: "unsupported operator", rule: compiledRuntimeRule{ID: "bad-op", Category: "traffic", Field: "payload", Operator: "sequence", Value: "x"}},
		{name: "invalid regex", rule: compiledRuntimeRule{ID: "bad-regex", Category: "traffic", Field: "payload", Operator: "regex", Value: "[", Regex: true}},
		{name: "missing field", rule: compiledRuntimeRule{ID: "missing-field", Category: "traffic", Operator: "contains", Value: "x"}},
		{name: "invalid condition", rule: compiledRuntimeRule{ID: "bad-condition", Category: "traffic", Conditions: []map[string]interface{}{{"field": "payload", "operator": "regex", "value": "[", "regex": true}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if compiledRuntimeRuleValid(tc.rule) {
				t.Fatalf("%s should be filtered before bundle compilation", tc.name)
			}
		})
	}
}

func TestCompileDetectionRuleKeepsValidRulesValid(t *testing.T) {
	raw, err := json.Marshal(map[string]interface{}{"id": "good", "category": "traffic", "field": "dns_query", "operator": "regex", "value": "(?i)evil\\.example", "regex": true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rule, err := compileDetectionRule("good", "traffic", "Good", string(raw))
	if err != nil {
		t.Fatalf("compileDetectionRule: %v", err)
	}
	if !compiledRuntimeRuleValid(rule) {
		t.Fatal("valid detection rule should remain eligible for bundle compilation")
	}
}

func TestResponseCandidatesEndpointRejectsMutation(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/response/candidates", nil)
		rec := httptest.NewRecorder()
		responseCandidatesHandler(&Config{}).ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status=%d, want 405", method, rec.Code)
		}
	}
}

func TestGuardModeRequiresApprovalSignals(t *testing.T) {
	decision, err := guardmode.ParseDecision([]byte(`{"action":"temporary_block","confidence":0.99,"target_ip":"203.0.113.10"}`))
	if err != nil {
		t.Fatalf("parse decision: %v", err)
	}
	allowed := guardmode.Allowed(decision, guardmode.SafetyContext{Severity: "critical", RuleHit: true, MultiSignal: false, WhitelistPassed: true, AllowedWindow: true}, 0.9)
	if allowed {
		t.Fatal("temporary block must not be allowed without full safety context")
	}
}
