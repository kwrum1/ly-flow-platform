package main

import (
	"slices"
	"testing"
)

func TestPostgresRetentionStatementsUseCurrentXDRSchema(t *testing.T) {
	statements := postgresRetentionStatements()
	want := "DELETE FROM xdr_events_v2 WHERE observed_at < $1"
	if !slices.Contains(statements, want) {
		t.Fatalf("retention statements missing %q: %v", want, statements)
	}
	legacy := "DELETE FROM xdr_events WHERE created_at < $1"
	if slices.Contains(statements, legacy) {
		t.Fatalf("retention statements still include removed legacy table: %q", legacy)
	}
}

func TestTrafficSessionRetentionDays(t *testing.T) {
	t.Setenv("TRAFFIC_SESSION_RETENTION_DAYS", "3")
	if got := trafficSessionRetentionDays(); got != 3 {
		t.Fatalf("trafficSessionRetentionDays()=%d want 3", got)
	}
	t.Setenv("TRAFFIC_SESSION_RETENTION_DAYS", "0")
	if got := trafficSessionRetentionDays(); got != 7 {
		t.Fatalf("default trafficSessionRetentionDays()=%d want 7", got)
	}
}
