package main

import "testing"

func TestValidateResponseTargetRestrictsToConfiguredCIDRs(t *testing.T) {
	t.Setenv("RESPONSE_ALLOWED_CIDRS", "203.0.113.0/24,198.51.100.0/24")
	if err := validateResponseTarget("203.0.113.77"); err != nil {
		t.Fatalf("TEST-NET-3 target rejected: %v", err)
	}
	if err := validateResponseTarget("198.51.100.20"); err != nil {
		t.Fatalf("TEST-NET-2 target rejected: %v", err)
	}
	if err := validateResponseTarget("10.1.18.100"); err == nil {
		t.Fatal("management target accepted")
	}
	if err := validateResponseTarget("not-an-ip"); err == nil {
		t.Fatal("invalid target accepted")
	}
}
