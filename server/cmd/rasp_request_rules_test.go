package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRASPRequestRulePackCoversCRSCategories(t *testing.T) {
	pack := getRASPRequestRulePack(2)
	if len(pack.Rules) < 20 {
		t.Fatalf("rule_count=%d, want at least 20 executable CRS rules", len(pack.Rules))
	}
	if pack.SchemaVersion != raspRequestRulesSchema {
		t.Fatalf("schema=%q", pack.SchemaVersion)
	}
	if pack.Digest == "" {
		t.Fatal("pack digest is empty")
	}
	seen := map[string]bool{}
	categories := map[string]int{}
	for _, rule := range pack.Rules {
		if seen[rule.ID] {
			t.Fatalf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Paranoia < 1 || rule.Paranoia > 2 {
			t.Fatalf("%s paranoia=%d, want PL1-2 only", rule.ID, rule.Paranoia)
		}
		if len(rule.Targets) == 0 {
			t.Fatalf("%s has no probe targets", rule.ID)
		}
		switch rule.Operator {
		case "rx":
			if rule.Pattern == "" {
				t.Fatalf("%s has an empty pattern", rule.ID)
			}
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				t.Fatalf("%s pattern no longer compiles: %v", rule.ID, err)
			}
			if isMatchAllRegex(rule.Pattern) {
				t.Fatalf("%s would match every request", rule.ID)
			}
		case "pm":
			if len(rule.Phrases) == 0 {
				t.Fatalf("%s pm rule has no phrases", rule.ID)
			}
		default:
			t.Fatalf("%s unknown operator %q", rule.ID, rule.Operator)
		}
		if rule.Action != "block" || rule.Source != raspRequestRulesSource {
			t.Fatalf("%s action/source=%q/%q", rule.ID, rule.Action, rule.Source)
		}
		categories[rule.Category]++
	}
	for _, want := range []string{"sqli", "xss", "path_traversal", "lfi", "rfi", "rce", "webshell", "scanner"} {
		if categories[want] == 0 {
			t.Fatalf("category %q missing from pack: %#v", want, categories)
		}
	}
	if !seen["owasp-crs-942270"] || !seen["owasp-crs-930110"] || !seen["owasp-crs-941110"] || !seen["owasp-crs-913100"] {
		t.Fatalf("expected representative CRS rules missing: %v", seen)
	}

	pl1 := getRASPRequestRulePack(1)
	for _, rule := range pl1.Rules {
		if rule.Paranoia > 1 {
			t.Fatalf("PL1 pack leaked %s (PL%d)", rule.ID, rule.Paranoia)
		}
	}
	if len(pl1.Rules) >= len(pack.Rules) {
		t.Fatalf("PL1 rules=%d, PL2 rules=%d; PL1 must be a strict subset", len(pl1.Rules), len(pack.Rules))
	}
}

func TestRASPRequestRulePatternsAreProbeCompatible(t *testing.T) {
	// Go's RE2 and Python's re disagree on lookarounds/backreferences and on
	// PCRE-only escapes. The pack must stay in the common subset because both
	// the Go status handler and the Python probe consume it.
	for _, rule := range getRASPRequestRulePack(2).Rules {
		if strings.Contains(rule.Pattern, "(?=") || strings.Contains(rule.Pattern, "(?!") ||
			strings.Contains(rule.Pattern, "(?<=") || strings.Contains(rule.Pattern, "(?<!") {
			t.Fatalf("%s uses a lookaround unsupported by runtime probes", rule.ID)
		}
		if strings.Contains(rule.Pattern, `\x{`) {
			t.Fatalf("%s uses PCRE-only \\x{...} escapes", rule.ID)
		}
	}
}

func TestRASPRequestRulesStatusHandler(t *testing.T) {
	handler := raspRequestRulesStatusHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rasp/request-rules/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code != 0 || body.Data["schema_version"] != raspRequestRulesSchema {
		t.Fatalf("unexpected payload: %#v", body)
	}
	if body.Data["rule_count"].(float64) < 20 {
		t.Fatalf("rule_count=%v", body.Data["rule_count"])
	}
	if body.Data["digest"] == "" || body.Data["enabled"] != true {
		t.Fatalf("digest/enabled missing: %#v", body.Data)
	}
	categories, ok := body.Data["categories"].(map[string]interface{})
	if !ok || categories["sqli"] == nil || categories["xss"] == nil {
		t.Fatalf("categories=%#v", body.Data["categories"])
	}
}

func TestRASPRequestRulesDownloadHandlerContract(t *testing.T) {
	handler := raspRequestRulesDownloadHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rasp/request-rules/download", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("content-type=%q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "lyflow-rasp-request-rules.json") {
		t.Fatalf("content-disposition=%q", got)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	var pack raspRequestRulePack
	if err := json.Unmarshal(rec.Body.Bytes(), &pack); err != nil {
		t.Fatalf("pack is not valid JSON: %v", err)
	}
	if pack.Digest == "" || pack.ParanoiaLevel != 2 || len(pack.Rules) == 0 {
		t.Fatalf("unexpected pack: digest=%q pl=%d rules=%d", pack.Digest, pack.ParanoiaLevel, len(pack.Rules))
	}

	// Conditional download must not re-send the body.
	conditional := httptest.NewRequest(http.MethodGet, "/api/v1/rasp/request-rules/download", nil)
	conditional.Header.Set("If-None-Match", etag)
	conditionalRec := httptest.NewRecorder()
	handler.ServeHTTP(conditionalRec, conditional)
	if conditionalRec.Code != http.StatusNotModified {
		t.Fatalf("conditional status=%d", conditionalRec.Code)
	}

	pl1 := httptest.NewRequest(http.MethodGet, "/api/v1/rasp/request-rules/download?paranoia=1", nil)
	pl1Rec := httptest.NewRecorder()
	handler.ServeHTTP(pl1Rec, pl1)
	var pl1Pack raspRequestRulePack
	if err := json.Unmarshal(pl1Rec.Body.Bytes(), &pl1Pack); err != nil {
		t.Fatalf("decode pl1: %v", err)
	}
	if pl1Pack.ParanoiaLevel != 1 || len(pl1Pack.Rules) >= len(pack.Rules) {
		t.Fatalf("pl1 pack=%d rules, pl2=%d rules", len(pl1Pack.Rules), len(pack.Rules))
	}

	bad := httptest.NewRequest(http.MethodGet, "/api/v1/rasp/request-rules/download?paranoia=9", nil)
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad paranoia status=%d", badRec.Code)
	}
}

func TestRASPRequestRulePackArtifactMatchesGenerator(t *testing.T) {
	path := filepath.Join("..", "..", "rules", "rasp", "request_rules.json")
	pack := getRASPRequestRulePack(raspRequestRulesMaxParanoia)
	generated, err := encodeRASPRequestRulePack(pack)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if os.Getenv("LY_RASP_WRITE_REQUEST_RULES") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, generated, 0o644); err != nil {
			t.Fatalf("write artifact: %v", err)
		}
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed pack (run with LY_RASP_WRITE_REQUEST_RULES=1 to regenerate): %v", err)
	}
	if string(committed) != string(generated) {
		t.Fatalf("rules/rasp/request_rules.json is stale; regenerate with LY_RASP_WRITE_REQUEST_RULES=1 go test ./cmd -run TestRASPRequestRulePackArtifactMatchesGenerator")
	}
}
