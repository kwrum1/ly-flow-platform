package main

import "testing"

func TestParseOWASPCRSPreservesFullRegexAndSkipsMatchAll(t *testing.T) {
	content := `
SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)union\s+select\s+[a-z]" \
    "id:942120,phase:2,deny,status:403,msg:'SQL Injection Attack: SQL Operator Detected',severity:'CRITICAL'"

SecRule REQUEST_URI "@rx (?i)" \
    "id:942140,phase:2,deny,msg:'Broken match-all rule',severity:'CRITICAL'"

SecRule REQUEST_URI "@detectSQLi" \
    "id:942100,phase:2,deny,msg:'SQLi detector',severity:'CRITICAL'"
`
	rules := parseOWASPCRSRules(content)
	if len(rules) != 1 {
		t.Fatalf("rules=%d, want only the usable regex rule: %#v", len(rules), rules)
	}
	if got := asString(rules[0]["value"]); got != `(?i)union\s+select\s+[a-z]` {
		t.Fatalf("pattern=%q, want the full regex", got)
	}
	if asString(rules[0]["id"]) != "owasp-crs-942120" {
		t.Fatalf("id=%q", asString(rules[0]["id"]))
	}
}
