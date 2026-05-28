package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSafeRuleFilenameRejectsTraversal(t *testing.T) {
	bad := []string{"../../bad.yaml", "/tmp/bad.yaml", "rules/../bad.yaml", "bad.txt", ""}
	for _, filename := range bad {
		if safeRuleFilename(filename) {
			t.Fatalf("safeRuleFilename(%q) = true, want false", filename)
		}
	}
	if !safeRuleFilename("xdr/custom.yaml") {
		t.Fatal("expected nested safe yaml filename to be accepted")
	}
}

func TestRulesStatsLoadsNonzeroXDRRules(t *testing.T) {
	rules, err := loadXDRRulePack()
	if err != nil {
		t.Fatalf("load XDR rules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("expected nonzero XDR rules")
	}
}

func TestRulesHandlerRejectsTraversalFilename(t *testing.T) {
	body := bytes.NewBufferString(`{"filename":"../../bad.yaml","rule":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", body)
	rec := httptest.NewRecorder()
	rulesHandler(&Config{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload["error_code"] != "invalid_rule_filename" {
		t.Fatalf("unexpected response: %#v", payload)
	}
}

func TestRuleTestHandlerMatchesFixture(t *testing.T) {
	body := bytes.NewBufferString(`{"source":"rasp","message":"RASP blocked SQL injection union select password from users"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/test", body)
	rec := httptest.NewRecorder()
	ruleTestHandler(&Config{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			Matched bool `json:"matched"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if !payload.Data.Matched {
		t.Fatalf("expected fixture to match a rule: %s", rec.Body.String())
	}
}
