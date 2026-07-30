package auth

import "testing"

func TestValidatePasswordPolicyAcceptsSimpleEightCharacterPasswords(t *testing.T) {
	for _, password := range []string{"password", "12345678", "simplepass"} {
		if message := validatePasswordPolicy(password); message != "" {
			t.Fatalf("password %q should be valid, got %q", password, message)
		}
	}
}

func TestValidatePasswordPolicyRejectsShortPasswords(t *testing.T) {
	if message := validatePasswordPolicy("short/"); message != "new password must be at least 8 characters" {
		t.Fatalf("short password error = %q", message)
	}
}
