package main

import (
	"testing"
	"time"
)

func TestXDRResponsePolicySuppressesWhitelist(t *testing.T) {
	event := xdrPolicyTestEvent("evt-1", "203.0.113.10", "victim-1")
	enrichXDREvaluation(event)
	decision := applyXDRResponsePolicy(event, xdrResponsePolicy{WhitelistSources: []string{"203.0.113.10"}, SuppressionWindow: defaultXDRResponsePolicy().SuppressionWindow, DedupWindow: defaultXDRResponsePolicy().DedupWindow})
	if !decision.Suppress || decision.Reason != "whitelist_match" {
		t.Fatalf("expected whitelist suppression, got %#v", decision)
	}
}

func TestXDRResponsePolicyElevatesBlacklistButKeepsCandidateOnly(t *testing.T) {
	event := xdrPolicyTestEvent("evt-1", "198.51.100.66", "victim-1")
	event["severity"] = "medium"
	enrichXDREvaluation(event)
	before := xdrEventScore(event)
	decision := applyXDRResponsePolicy(event, xdrResponsePolicy{BlacklistSources: []string{"198.51.100.66"}, SuppressionWindow: defaultXDRResponsePolicy().SuppressionWindow, DedupWindow: defaultXDRResponsePolicy().DedupWindow})
	if decision.Suppress || decision.Reason != "blacklist_match" {
		t.Fatalf("expected blacklist elevation without suppression, got %#v", decision)
	}
	if after := xdrEventScore(event); after <= before {
		t.Fatalf("expected elevated score, before=%d after=%d", before, after)
	}
	if event["candidate_only"] != true {
		t.Fatalf("expected candidate_only to remain true, got %#v", event["candidate_only"])
	}
}

func TestXDRResponsePolicySuppressesActiveIncidentRuleButNotExpired(t *testing.T) {
	now := time.Now().UTC()
	event := xdrPolicyTestEvent("evt-1", "203.0.113.10", "victim-1")
	enrichXDREvaluation(event)
	policy := xdrResponsePolicy{
		Suppressions: []xdrSuppressionEntry{
			{ID: "active", Scope: "rule", Value: "rasp.sql_injection", Reason: "confirmed false positive", ExpiresAt: now.Add(time.Hour)},
			{ID: "expired", Scope: "rule", Value: "rasp.sql_injection", Reason: "expired", ExpiresAt: now.Add(-time.Hour)},
		},
	}
	decision := applyXDRResponsePolicy(event, policy)
	if !decision.Suppress || decision.Reason != "incident_suppression_match" {
		t.Fatalf("expected active rule suppression, got %#v", decision)
	}
	policy.Suppressions = policy.Suppressions[1:]
	event = xdrPolicyTestEvent("evt-2", "203.0.113.10", "victim-1")
	enrichXDREvaluation(event)
	decision = applyXDRResponsePolicy(event, policy)
	if decision.Suppress {
		t.Fatalf("expired suppression must not suppress: %#v", decision)
	}
}

func TestDedupXDRComponentEventsCollapsesWindowDuplicates(t *testing.T) {
	events := []map[string]interface{}{
		xdrPolicyTestEvent("evt-1", "203.0.113.10", "victim-1"),
		xdrPolicyTestEvent("evt-2", "203.0.113.10", "victim-1"),
		xdrPolicyTestEvent("evt-3", "203.0.113.10", "victim-1"),
	}
	events[0]["created_at"] = "2026-05-15T01:00:00Z"
	events[1]["created_at"] = "2026-05-15T01:02:00Z"
	events[2]["created_at"] = "2026-05-15T01:10:00Z"
	for _, event := range events {
		enrichXDREvaluation(event)
	}
	deduped := dedupXDRComponentEvents(events, defaultXDRResponsePolicy().DedupWindow)
	if len(deduped) != 2 {
		t.Fatalf("expected one duplicate collapsed, got %d events: %#v", len(deduped), deduped)
	}
	if deduped[0]["id"] != "evt-1" || deduped[1]["id"] != "evt-3" {
		t.Fatalf("unexpected dedup order/result: %#v", deduped)
	}
}

func xdrPolicyTestEvent(id, source, victim string) map[string]interface{} {
	return map[string]interface{}{
		"id":                id,
		"metadata":          map[string]interface{}{"source_stream": "alerts:rasp"},
		"component_rule_id": "rasp.sql_injection",
		"rule_name":         "RASP SQL Injection",
		"severity":          "high",
		"confidence":        0.9,
		"message":           "initial_access sql injection",
		"src_ip":            source,
		"hostname":          victim,
		"created_at":        "2026-05-15T01:00:00Z",
	}
}
