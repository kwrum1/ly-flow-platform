package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/guardmode"
)

func TestRulePlatformSyncHandler_rejects_oversized_inline_body_before_persistence(t *testing.T) {
	// Given
	body := append([]byte(`{"source_id":"custom-rasp-rules","version":"v1","sha256":"`+strings.Repeat("0", 64)+`","content":"`), bytes.Repeat([]byte("x"), int(rulePlatformSyncBodyLimit)+1)...)
	body = append(body, []byte(`"}`)...)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rule-platform/sync", bytes.NewReader(body))
	recorder := httptest.NewRecorder()

	// When
	rulePlatformSyncHandler(&Config{}).ServeHTTP(recorder, request)

	// Then
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s, want 413", recorder.Code, recorder.Body.String())
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
