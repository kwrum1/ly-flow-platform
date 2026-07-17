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

func TestRedactMapRemovesPrivateSigningKeyMaterial(t *testing.T) {
	// Given
	input := map[string]interface{}{"private_key": "pem-data", "signing_key": "raw-key", "public_fingerprint": "safe"}

	// When
	redacted := RedactMap(input)

	// Then
	if redacted["private_key"] != "***REDACTED***" || redacted["signing_key"] != "***REDACTED***" {
		t.Fatalf("private signer material was not redacted: %#v", redacted)
	}
	if redacted["public_fingerprint"] != "safe" {
		t.Fatalf("public fingerprint must remain visible: %#v", redacted)
	}
}

func TestRedactMapRemovesSecretsInsideNestedSlices(t *testing.T) {
	// Given
	input := map[string]interface{}{"changes": []interface{}{map[string]interface{}{"token": "secret-value"}}}

	// When
	redacted := RedactMap(input)

	// Then
	changes := redacted["changes"].([]interface{})
	item := changes[0].(map[string]interface{})
	if item["token"] != "***REDACTED***" {
		t.Fatalf("nested slice secret was not redacted: %#v", redacted)
	}
}
