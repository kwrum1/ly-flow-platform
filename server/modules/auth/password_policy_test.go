package auth

import "testing"

func TestValidatePasswordPolicyAcceptsRequiredSpecialCharacters(t *testing.T) {
	valid := []string{"LyFlow/2026", "LyFlow，2026", "LyFlow。2026"}
	for _, password := range valid {
		if message := validatePasswordPolicy(password); message != "" {
			t.Fatalf("password %q should be valid, got %q", password, message)
		}
	}
}

func TestValidatePasswordPolicyRejectsWeakPasswords(t *testing.T) {
	cases := map[string]string{
		"short/":     "new password must be at least 8 characters",
		"lowercase/": "new password must contain an uppercase letter",
		"LyFlow2026": "new password must contain a special character",
	}
	for password, expected := range cases {
		if message := validatePasswordPolicy(password); message != expected {
			t.Fatalf("password %q expected %q, got %q", password, expected, message)
		}
	}
}
