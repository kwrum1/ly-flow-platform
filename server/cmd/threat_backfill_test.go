package main

import (
	"reflect"
	"testing"
)

func TestThreatBackfillStreamsUseCanonicalAlertsWithSecurityEngine(t *testing.T) {
	want := []string{"component_alerts:v2"}
	if got := threatBackfillStreams(true); !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical backfill streams = %v, want %v", got, want)
	}
}

func TestThreatBackfillStreamsKeepLegacyFallbackIsolated(t *testing.T) {
	got := threatBackfillStreams(false)
	for _, stream := range got {
		if stream == "component_alerts:v2" {
			t.Fatalf("legacy fallback must not mix canonical stream: %v", got)
		}
	}
	if len(got) == 0 {
		t.Fatal("legacy fallback streams are empty")
	}
}
