package logcollector

import "testing"

func TestValidateSourceBoundsReads(t *testing.T) {
	if err := ValidateSource(SourceConfig{Path: "/var/log/auth.log", MaxBytes: 65536}); err != nil {
		t.Fatalf("expected valid source: %v", err)
	}
	if err := ValidateSource(SourceConfig{Path: "/var/log/auth.log", MaxBytes: 0}); err == nil {
		t.Fatal("expected max bytes validation error")
	}
	if err := ValidateSource(SourceConfig{Path: "", MaxBytes: 1}); err == nil {
		t.Fatal("expected path validation error")
	}
}
