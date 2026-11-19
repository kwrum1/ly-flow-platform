package main

import (
	"testing"
	"time"
)

func TestDefaultObservabilityFromUsesSevenUTCDays(t *testing.T) {
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	from := defaultObservabilityFrom(now)
	if from == nil {
		t.Fatal("expected a default window")
	}
	want := now.Add(-7 * 24 * time.Hour)
	if !from.Equal(want) {
		t.Fatalf("from=%s, want %s", from, want)
	}
	if from.Location() != time.UTC {
		t.Fatalf("from location=%s, want UTC", from.Location())
	}
}
