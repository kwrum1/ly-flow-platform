package main

import (
	"strings"
	"testing"
)

// A Sigma selection is an AND of its fields. Flattening it into one regex
// turned "method GET and uri ~1 and status 200" into "GET|~1|200", which
// matched every web log line.
func TestSigmaSelectionKeepsAndSemantics(t *testing.T) {
	detection := map[string]interface{}{
		"condition": "selection",
		"selection": map[string]interface{}{
			"user":            "root",
			"cs-uri-stem":     "~1",
			"http.status_code": 200,
		},
	}

	conditions := sigmaConditions(detection)
	if len(conditions) != 3 {
		t.Fatalf("selection fields must stay separate conditions, got %#v", conditions)
	}
	for _, condition := range conditions {
		value := asString(condition["value"])
		if strings.Contains(value, "|") && strings.Contains(value, "(?i)") {
			t.Fatalf("selection was flattened into an alternation: %#v", condition)
		}
	}
}

func TestSigmaKeywordAlternationRejectsGenericBranch(t *testing.T) {
	detection := map[string]interface{}{
		"condition": "keywords",
		"keywords":  []interface{}{"a.aspx", "GET", "OPTIONS", "~1"},
	}

	if conditions := sigmaConditions(detection); len(conditions) != 0 {
		t.Fatalf("generic branch must drop the rule, got %#v", conditions)
	}
}

func TestSigmaKeywordAlternationKeepsSpecificBranches(t *testing.T) {
	detection := map[string]interface{}{
		"condition": "keywords",
		"keywords":  []interface{}{"win32_process_create", "meterpreter_reverse_tcp"},
	}

	conditions := sigmaConditions(detection)
	if len(conditions) != 1 {
		t.Fatalf("expected one alternation condition, got %#v", conditions)
	}
	value := asString(conditions[0]["value"])
	if !strings.Contains(value, "win32_process_create") || !strings.Contains(value, "meterpreter_reverse_tcp") {
		t.Fatalf("alternation lost branches: %q", value)
	}
}

func TestSigmaOrOfMultiFieldSelectionIsRejected(t *testing.T) {
	detection := map[string]interface{}{
		"condition": "1 of them",
		"one": map[string]interface{}{
			"user":           "root",
			"cs-uri-stem":    "/admin",
		},
		"two": map[string]interface{}{
			"user": "nobody",
		},
	}

	if conditions := sigmaConditions(detection); len(conditions) != 0 {
		t.Fatalf("'one of (A and B)' is not representable, got %#v", conditions)
	}
}

func TestParseSigmaRulesDropsShortnameFuzzCatchAll(t *testing.T) {
	content := `title: Successful IIS Shortname Fuzzing Scan
id: 7cb02516-6d95-4ffc-8eee-162075e111ac
level: medium
logsource:
  category: webserver
detection:
  keywords:
    - 'a.aspx'
    - 'GET'
    - 'OPTIONS'
    - '~1'
  condition: keywords
`

	if rules := parseSigmaRules(content); len(rules) != 0 {
		t.Fatalf("catch-all Sigma rule must not be converted: %#v", rules)
	}
}

func TestParseSigmaRulesKeepsMultiFieldSelection(t *testing.T) {
	content := `title: Failed password for invalid user
id: 11111111-2222-3333-4444-555555555555
level: high
logsource:
  product: linux
  service: sshd
detection:
  selection:
    user: invaliduser
    message|contains: Failed password
  condition: selection
`

	rules := parseSigmaRules(content)
	if len(rules) != 1 {
		t.Fatalf("expected one converted rule, got %d", len(rules))
	}
	conditions := mapSlice(rules[0]["conditions"])
	if len(conditions) < 2 {
		t.Fatalf("AND conditions were collapsed: %#v", conditions)
	}
}

func TestParseSigmaRulesKeepsRuleWhenOneFieldIsWeak(t *testing.T) {
	content := `title: WordPress wp2shell endpoint exploitation
id: 22222222-3333-4444-5555-666666666666
level: high
logsource:
  category: webserver
detection:
  selection:
    cs-method: POST
    cs-uri-stem|contains: /wp-json/wp/v2/users
  condition: selection
`

	rules := parseSigmaRules(content)
	if len(rules) != 1 {
		t.Fatalf("a specific AND field must keep the rule, got %d", len(rules))
	}
	if conditions := mapSlice(rules[0]["conditions"]); len(conditions) != 2 {
		t.Fatalf("expected method and path conditions, got %#v", conditions)
	}
}

func TestParseSigmaRulesDropsWeakAlternationNextToSpecificField(t *testing.T) {
	content := `title: Generic verb alternation
id: 33333333-4444-5555-6666-777777777777
level: high
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains:
      - /admin/upload
      - GET
  condition: selection
`

	if rules := parseSigmaRules(content); len(rules) != 0 {
		t.Fatalf("weak alternation branch must drop the rule: %#v", rules)
	}
}

func TestSigmaWeakAlternationDetection(t *testing.T) {
	weak := []string{
		`(?i)(GET|/remote_agent\.php|action=polldata)`,
		`(?i)(root|/var/opt/microsoft/scx/tmp|/bin/sh)`,
		`(?i)(a\.aspx|GET|OPTIONS|~1)`,
		`(?i)(true|some_specific_literal)`,
	}
	for _, value := range weak {
		condition := map[string]interface{}{"field": "message", "operator": "regex", "regex": true, "value": value}
		if !sigmaConditionHasWeakAlternation(condition) {
			t.Fatalf("weak branch not detected in %q", value)
		}
	}
	specific := map[string]interface{}{"field": "message", "operator": "regex", "regex": true, "value": `(?i)(/remote_agent\.php|action=polldata)`}
	if sigmaConditionHasWeakAlternation(specific) {
		t.Fatalf("specific alternation was rejected: %q", specific["value"])
	}
}

func TestRetiredConvertedRules(t *testing.T) {
	for _, id := range retiredConvertedRuleIDs {
		if !retiredDetectionRuleID(id) {
			t.Fatalf("converted rule %s must stay retired", id)
		}
	}
	if retiredDetectionRuleID("snort-community-1000000") {
		t.Fatal("unrelated converted rule must not be retired")
	}
	if retiredDetectionRuleID("lyflow-default-scan-default") {
		t.Fatal("curated default rule must not be treated as a retired conversion")
	}
}

func TestMergeSkipsRetiredAndOverBroadUpdates(t *testing.T) {
	base := []compiledRuntimeRule{
		{ID: "lyflow-default-a", Category: "log_audit", Field: "message", Operator: "contains", Value: "specific-literal"},
	}
	updates := []compiledRuntimeRule{
		{ID: "snort-community-51544", Category: "traffic", Field: "http_path", Operator: "contains", Value: "/upload_files"},
		{ID: "sigma-7cb02516-0000", Category: "log_audit", Conditions: []map[string]interface{}{
			{"field": "message", "operator": "regex", "regex": true, "value": `(?i)(a\.aspx|GET)`},
		}},
		{ID: "sigma-keep-0000", Category: "log_audit", Conditions: []map[string]interface{}{
			{"field": "path", "operator": "contains", "value": "/wp-json/wp/v2/users"},
		}},
	}

	merged := mergeCompiledRuntimeRules(base, updates)
	ids := map[string]bool{}
	for _, rule := range merged {
		ids[rule.ID] = true
	}
	if ids["snort-community-51544"] || ids["sigma-7cb02516-0000"] {
		t.Fatalf("retired or over-broad update survived merge: %#v", ids)
	}
	if !ids["sigma-keep-0000"] || !ids["lyflow-default-a"] {
		t.Fatalf("valid rules were dropped: %#v", ids)
	}
}
