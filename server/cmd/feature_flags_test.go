package main

import "testing"

func TestLoadFeatureFlagsDefaultsOff(t *testing.T) {
	t.Setenv("EVENT_SCHEMA_V2_ENABLED", "")
	t.Setenv("QUERY_V2_ENABLED", "")
	t.Setenv("CORRELATION_V2_ENABLED", "")
	t.Setenv("AGENT_FACADE_ENABLED", "")
	t.Setenv("RESPONSE_APPROVAL_ENABLED", "")

	flags := loadFeatureFlags()
	if flags.AnyEnabled() {
		t.Fatalf("expected all feature flags to default off, got %+v", flags)
	}
}

func TestLoadFeatureFlagsEnabled(t *testing.T) {
	t.Setenv("EVENT_SCHEMA_V2_ENABLED", "true")
	t.Setenv("QUERY_V2_ENABLED", "1")
	t.Setenv("CORRELATION_V2_ENABLED", "yes")
	t.Setenv("AGENT_FACADE_ENABLED", "on")
	t.Setenv("RESPONSE_APPROVAL_ENABLED", "TRUE")

	flags := loadFeatureFlags()
	if !flags.EventSchemaV2 || !flags.QueryV2 || !flags.CorrelationV2 || !flags.AgentFacade || !flags.ResponseApproval {
		t.Fatalf("expected all feature flags enabled, got %+v", flags)
	}
	if !flags.AnyEnabled() {
		t.Fatal("expected AnyEnabled to be true")
	}
}
