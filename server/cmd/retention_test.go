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
