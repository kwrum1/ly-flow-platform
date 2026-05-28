package security

import "testing"

func TestRedactMapRemovesSecrets(t *testing.T) {
	redacted := RedactMap(map[string]interface{}{"agent_key": "abc", "nested": map[string]interface{}{"jwt_secret": "secret"}, "safe": "ok"})
	if redacted["agent_key"] != "***REDACTED***" || redacted["safe"] != "ok" {
		t.Fatalf("unexpected redaction: %#v", redacted)
	}
	nested := redacted["nested"].(map[string]interface{})
	if nested["jwt_secret"] != "***REDACTED***" {
		t.Fatalf("nested secret not redacted: %#v", nested)
	}
}

func TestValidateAudit(t *testing.T) {
	if !ValidateAudit(AuditEntry{Actor: "admin", Action: "policy.update", Resource: "agent-1", Result: "success"}) {
		t.Fatal("expected valid audit entry")
	}
	if ValidateAudit(AuditEntry{Actor: "admin"}) {
		t.Fatal("expected incomplete audit entry to fail")
	}
}
