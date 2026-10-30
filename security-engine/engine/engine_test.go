package engine

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestBundleMatchesRASPEvent(t *testing.T) {
	bundle, err := NewBundle("test", []RuntimeRule{{ID: "rasp-sqli", Name: "RASP SQLi", Category: contracts.TelemetryRASP, Severity: contracts.SeverityCritical, ScoreHint: 90, Field: "query", Value: "(?i)union select", Regex: true, Candidate: true}})
	if err != nil {
		t.Fatal(err)
	}
	env := contracts.TelemetryEnvelope{SchemaVersion: contracts.TelemetrySchemaVersion, ID: "e1", Category: contracts.TelemetryRASP, EventType: "rasp.sql", ObservedAt: time.Now(), Source: "java-probe", Fields: map[string]any{"query": "select * from users union select password"}}
	alerts := bundle.Match(env)
	if len(alerts) != 1 || alerts[0].RuleID != "rasp-sqli" {
		t.Fatalf("unexpected alerts: %#v", alerts)
	}
}

func TestBundleCollapsesMultipleRASPRuleMatchesIntoOneAlert(t *testing.T) {
	bundle, err := NewBundle("test", []RuntimeRule{
		{ID: "owasp-crs-942120", Name: "SQL Operator", Category: contracts.TelemetryRASP, Severity: contracts.SeverityCritical, ScoreHint: 90, Field: "query", Value: "(?i)union select", Regex: true, Candidate: true},
		{ID: "owasp-crs-942140", Name: "DB Names", Category: contracts.TelemetryRASP, Severity: contracts.SeverityCritical, ScoreHint: 90, Field: "query", Value: "(?i)select", Regex: true, Candidate: true},
		{ID: "rasp-sqli", Name: "RASP SQLi", Category: contracts.TelemetryRASP, Severity: contracts.SeverityCritical, ScoreHint: 90, Field: "query", Value: "(?i)union select", Regex: true, Candidate: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := contracts.TelemetryEnvelope{SchemaVersion: contracts.TelemetrySchemaVersion, ID: "e1", Category: contracts.TelemetryRASP, EventType: "rasp.sql", ObservedAt: time.Now(), Source: "python-probe", Fields: map[string]any{"query": "select 1 union select 2", "blocked": true}}

	alerts := bundle.Match(env)

	if len(alerts) != 1 {
		t.Fatalf("one RASP event produced %d alerts: %#v", len(alerts), alerts)
	}
	if alerts[0].RuleID != "rasp-sqli" {
		t.Fatalf("native RASP rule must win, got %s", alerts[0].RuleID)
	}
	if alerts[0].Details["blocked"] != true {
		t.Fatalf("enforcement fields were dropped: %#v", alerts[0].Details)
	}
	if alerts[0].Action != string(contracts.ActionBlock) || alerts[0].PolicyState != contracts.PolicyBlock {
		t.Fatalf("blocked action/policy not preserved: action=%q policy=%q", alerts[0].Action, alerts[0].PolicyState)
	}
}

func TestBundleCounts(t *testing.T) {
	bundle, err := NewBundle("test", []RuntimeRule{{ID: "runtime-1", Category: contracts.TelemetryRuntime}, {ID: "dpi-1", Category: contracts.TelemetryTraffic}})
	if err != nil {
		t.Fatal(err)
	}
	counts := bundle.Counts()
	if counts["runtime"] != 1 || counts["traffic"] != 1 || counts["rasp"] != 0 {
		t.Fatalf("bad counts: %#v", counts)
	}
}

func TestRuntimeRuleOperators(t *testing.T) {
	bundle, err := NewBundle("test", []RuntimeRule{
		{ID: "eq", Name: "eq", Category: contracts.TelemetryLogAudit, Severity: contracts.SeverityLow, ScoreHint: 10, Field: "source", Operator: "equals", Value: "nginx"},
		{ID: "exists", Name: "exists", Category: contracts.TelemetryLogAudit, Severity: contracts.SeverityLow, ScoreHint: 10, Field: "message", Operator: "exists"},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := contracts.TelemetryEnvelope{SchemaVersion: contracts.TelemetrySchemaVersion, ID: "e1", Category: contracts.TelemetryLogAudit, EventType: "log", ObservedAt: time.Now(), Source: "test", Fields: map[string]any{"source": "nginx", "message": "GET /admin"}}
	alerts := bundle.Match(env)
	if len(alerts) != 2 {
		t.Fatalf("expected two operator matches, got %#v", alerts)
	}
}

func TestTrafficNoisePolicySuppressesKnownFalsePositiveRules(t *testing.T) {
	bundle, err := NewBundle("test", []RuntimeRule{
		{ID: "oisf-trafficid-300000001", Name: "SURICATA TRAFFIC-ID: Ubuntu APT-GET", Category: contracts.TelemetryTraffic, Severity: contracts.SeverityMedium, ScoreHint: 50, Field: "payload", Value: "apt-get", Candidate: true},
		{ID: "oisf-trafficid-300000002", Name: "SURICATA TRAFFIC-ID: bing", Category: contracts.TelemetryTraffic, Severity: contracts.SeverityMedium, ScoreHint: 50, Field: "payload", Value: "bing", Candidate: true},
		{ID: "snort-community-27085", Name: "EXPLOIT-KIT Unknown Malvertising exploit kit Hostile Jar pipe.class", Category: contracts.TelemetryTraffic, Severity: contracts.SeverityHigh, ScoreHint: 75, Field: "payload", Value: "pipe.class", Candidate: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := contracts.TelemetryEnvelope{SchemaVersion: contracts.TelemetrySchemaVersion, ID: "traffic-1", Category: contracts.TelemetryTraffic, EventType: "traffic.flow", ObservedAt: time.Now(), Source: "local-mirror-capture", Fields: map[string]any{"payload": "apt-get bing pipe.class"}}
	if alerts := bundle.Match(env); len(alerts) != 0 {
		t.Fatalf("expected noisy traffic rules suppressed, got %#v", alerts)
	}
}
