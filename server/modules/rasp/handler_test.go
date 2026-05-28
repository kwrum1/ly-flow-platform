package rasp

import "testing"

func TestNormalizeEventMapFillsSharedContract(t *testing.T) {
	event := NormalizeEventMap(map[string]interface{}{
		"type":     "sql_injection",
		"agent_id": "agent-python",
		"blocked":  false,
	})

	if event["type"] != "rasp.attack" {
		t.Fatalf("type = %v", event["type"])
	}
	if event["attack_type"] != "sql_injection" {
		t.Fatalf("attack_type = %v", event["attack_type"])
	}
	if event["language"] != "python" || event["blocked"] != false || event["action"] != "log" {
		t.Fatalf("normalized contract mismatch: %#v", event)
	}
	if event["rule_id"] == "" || event["occurred_at"] == "" {
		t.Fatalf("rule_id/occurred_at missing: %#v", event)
	}
}

func TestNormalizeEventMapProtectModeWhenBlocked(t *testing.T) {
	event := NormalizeEventMap(map[string]interface{}{
		"type":    "command_injection",
		"blocked": true,
	})
	if event["mode"] != "protect" || event["action"] != "block" {
		t.Fatalf("expected protect/block event, got %#v", event)
	}
}
