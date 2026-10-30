package main

import "testing"

func TestRulePatternIsSpecific(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		operator string
		want     bool
	}{
		{name: "http method GET", value: "GET", operator: "contains", want: false},
		{name: "http method POST", value: "POST", operator: "contains", want: false},
		{name: "user token", value: "USER", operator: "contains", want: false},
		{name: "tor token", value: "TOR", operator: "contains", want: false},
		{name: "msn token", value: "CAL", operator: "contains", want: false},
		{name: "brows token", value: "BROWS", operator: "contains", want: false},
		{name: "id parameter", value: "id=", operator: "contains", want: false},
		{name: "php suffix", value: ".php", operator: "contains", want: false},
		{name: "php query suffix", value: ".php?", operator: "contains", want: false},
		{name: "two digits", value: "30", operator: "contains", want: false},
		{name: "ipv4 regex", value: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, operator: "regex", want: false},
		{name: "arbitrary byte class", value: `^[\x00-\xff]{10,55}[\x00-\x7f][\x00-\x7f]`, operator: "regex", want: false},
		{name: "symbol alternation", value: `(?:\x3b|\x26|\x7C|%3b|%7c|%26)`, operator: "regex", want: false},
		{name: "optional literal", value: `(^|&)(server)?id=`, operator: "regex", want: false},
		{name: "jpg regex", value: `\x2ejpg([\?\x5c\x2f]|$)`, operator: "regex", want: false},
		{name: "query id class", value: `[?&]id=`, operator: "regex", want: false},
		{name: "bare domain", value: "debian.org", operator: "contains", want: false},
		{name: "common token", value: "server", operator: "contains", want: false},

		{name: "meterpreter", value: "Meterpreter", operator: "contains", want: true},
		{name: "wscript", value: "WScript.Shell", operator: "contains", want: true},
		{name: "proxy authorization", value: "Proxy-Authorization", operator: "contains", want: true},
		{name: "shell application", value: "Shell.Application", operator: "contains", want: true},
		{name: "select from", value: "SELECT * FROM", operator: "contains", want: true},
		{name: "sql regex", value: `(?i)(union\s+select|or\s+1=1)`, operator: "regex", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rulePatternIsSpecific(test.value, test.operator); got != test.want {
				t.Fatalf("rulePatternIsSpecific(%q, %q)=%v, want %v", test.value, test.operator, got, test.want)
			}
		})
	}
}

func TestCompiledTrafficRuleIsGeneric(t *testing.T) {
	tests := []struct {
		name string
		rule compiledRuntimeRule
		want bool
	}{
		{
			name: "pt catch-all regex",
			rule: compiledRuntimeRule{ID: "ptresearch-attackdetection-ptresearch-attackdetection-11003921", Category: "traffic", Field: "payload", Operator: "regex", Regex: true, Value: `^[\x00-\xff]{10,55}[\x00-\x7f][\x00-\x7f]`},
			want: true,
		},
		{
			name: "et GET",
			rule: compiledRuntimeRule{ID: "et-open-2010602", Category: "traffic", Field: "payload", Operator: "contains", Value: "GET"},
			want: true,
		},
		{
			name: "internal rule is never gated",
			rule: compiledRuntimeRule{ID: "lyflow-default-1", Category: "traffic", Field: "payload", Operator: "contains", Value: "GET"},
			want: false,
		},
		{
			name: "runtime category is never gated",
			rule: compiledRuntimeRule{ID: "et-open-2010602", Category: "runtime", Field: "payload", Operator: "contains", Value: "GET"},
			want: false,
		},
		{
			name: "structured condition is kept",
			rule: compiledRuntimeRule{ID: "stamus-lateral-1", Category: "traffic", Field: "dcerpc.iface", Operator: "equals", Value: "367abb81", Conditions: []map[string]interface{}{{"field": "dcerpc.opnum", "operator": "equals", "value": "12"}}},
			want: false,
		},
		{
			name: "specific literal is kept",
			rule: compiledRuntimeRule{ID: "et-open-2000419", Category: "traffic", Field: "payload", Operator: "contains", Value: "Meterpreter"},
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compiledTrafficRuleIsGeneric(test.rule); got != test.want {
				t.Fatalf("compiledTrafficRuleIsGeneric()=%v, want %v", got, test.want)
			}
		})
	}
}

func TestConvertedTrafficRuleRejection(t *testing.T) {
	tests := []struct {
		name string
		rule map[string]interface{}
		op   string
		want string
	}{
		{
			name: "binary content cannot be represented",
			rule: map[string]interface{}{"value": "|0d 0a|Subject:", "operator": "contains"},
			op:   "contains",
			want: "unrepresentable_binary_content",
		},
		{
			name: "bare domain",
			rule: map[string]interface{}{"value": "debian.org", "operator": "contains"},
			op:   "contains",
			want: "bare_domain",
		},
		{
			name: "common token",
			rule: map[string]interface{}{"value": "server", "operator": "contains"},
			op:   "contains",
			want: "common_token",
		},
		{
			name: "short literal",
			rule: map[string]interface{}{"value": "GET", "operator": "contains"},
			op:   "contains",
			want: "pattern_too_generic",
		},
		{
			name: "port constraint lost with weak literal",
			rule: map[string]interface{}{"value": "PRIVMSG", "operator": "contains", "source_dest_port": "!6661:6668"},
			op:   "contains",
			want: "lost_match_constraints",
		},
		{
			name: "offset constraint lost with weak literal",
			rule: map[string]interface{}{"value": "REGISTER", "operator": "contains", "source_match_options": []interface{}{"depth"}},
			op:   "contains",
			want: "lost_match_constraints",
		},
		{
			name: "strong literal survives lost constraints",
			rule: map[string]interface{}{"value": "Installation of SC-KeyLog on host", "operator": "contains", "source_dest_port": "21"},
			op:   "contains",
			want: "",
		},
		{
			name: "no constraints, good literal",
			rule: map[string]interface{}{"value": "Meterpreter", "operator": "contains", "source_dest_port": "any"},
			op:   "contains",
			want: "",
		},
		{
			name: "regex alternation is not binary content",
			rule: map[string]interface{}{"value": "(?i)(sqlmap|nikto|nmap)", "operator": "regex"},
			op:   "regex",
			want: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := convertedTrafficRuleRejection(test.rule, test.op); got != test.want {
				t.Fatalf("convertedTrafficRuleRejection()=%q, want %q", got, test.want)
			}
		})
	}
}

func TestRulePlatformContentDigestBindsParserVersion(t *testing.T) {
	raw := "21face31174cbf1e02dfe7046de130aac72e431959390829b60ad07769117663"
	got := rulePlatformContentDigest(raw)
	if got == raw {
		t.Fatal("digest must not equal the raw upstream digest")
	}
	if len(got) != 64 {
		t.Fatalf("digest length=%d, want 64", len(got))
	}
	if rulePlatformContentDigest(raw) != got {
		t.Fatal("digest must be deterministic")
	}
}

func TestCompiledRuleIsOverBroad(t *testing.T) {
	tests := []struct {
		name string
		rule compiledRuntimeRule
		want bool
	}{
		{
			name: "sigma alternation with generic verb",
			rule: compiledRuntimeRule{ID: "sigma-7cb02516-6d95-4ffc-8eee-162075e111ac", Category: "log_audit", Conditions: []map[string]interface{}{
				{"field": "message", "operator": "regex", "regex": true, "value": `(?i)(a\.aspx|GET|OPTIONS|~1)`},
			}},
			want: true,
		},
		{
			name: "sigma specific path condition",
			rule: compiledRuntimeRule{ID: "sigma-11111111-2222-3333-4444-555555555555", Category: "log_audit", Conditions: []map[string]interface{}{
				{"field": "path", "operator": "contains", "value": "/wp-json/wp/v2/users"},
			}},
			want: false,
		},
		{
			name: "sigma only weak conditions",
			rule: compiledRuntimeRule{ID: "sigma-22222222-3333-4444-5555-666666666666", Category: "log_audit", Conditions: []map[string]interface{}{
				{"field": "message", "operator": "contains", "value": "error"},
			}},
			want: true,
		},
		{
			name: "curated default rule is never filtered",
			rule: compiledRuntimeRule{ID: "lyflow-default-log-1", Category: "log_audit", Field: "message", Operator: "contains", Value: "error"},
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compiledRuleIsOverBroad(test.rule); got != test.want {
				t.Fatalf("compiledRuleIsOverBroad()=%v, want %v", got, test.want)
			}
		})
	}
}
