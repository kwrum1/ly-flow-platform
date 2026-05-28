package main

import "testing"

func TestLegacyXDRMatchingDefaultsDisabled(t *testing.T) {
	t.Setenv("LEGACY_XDR_COMPONENT_MATCHING", "")
	t.Setenv("DB_HOST", "127.0.0.1")
	cfg := &Config{LegacyXDROperatorMatching: toBool(getEnv("LEGACY_XDR_COMPONENT_MATCHING", "false"))}
	if cfg.LegacyXDROperatorMatching {
		t.Fatal("legacy XDR component matching must default to disabled")
	}
}

func TestLegacyStatusLabelsDeprecatedDisabled(t *testing.T) {
	if got := legacyStatus(false); got != "deprecated_disabled" {
		t.Fatalf("legacyStatus(false)=%q", got)
	}
	if got := legacyStatus(true); got != "explicitly_enabled_for_migration" {
		t.Fatalf("legacyStatus(true)=%q", got)
	}
}
