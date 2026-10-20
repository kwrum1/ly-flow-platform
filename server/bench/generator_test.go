package bench

import (
	"testing"
	"time"
)

func TestGeneratorEventIsValid(t *testing.T) {
	start := time.Unix(1700000000, 0).UTC()
	generator := NewGenerator(GeneratorConfig{Start: start, Days: 1, EPS: 1, PayloadBytes: 64, Seed: 7})
	event := generator.Event(0)
	if err := event.Validate(); err != nil {
		t.Fatalf("event invalid: %v", err)
	}
	if event.EventUID == "" || event.Entities.Asset == nil || event.Raw.PayloadSHA256 == "" {
		t.Fatalf("event missing identity/entities/raw: %+v", event)
	}
	if len(event.Payload) == 0 {
		t.Fatal("expected payload")
	}
	if !event.Timestamps.EventAt.Equal(start) {
		t.Fatalf("event time = %s, want %s", event.Timestamps.EventAt, start)
	}
}

func TestGeneratorCountAndDistribution(t *testing.T) {
	start := time.Unix(1700000000, 0).UTC()
	generator := NewGenerator(GeneratorConfig{Start: start, Days: 2, EPS: 10})
	if generator.Count() != 2*86400*10 {
		t.Fatalf("count = %d", generator.Count())
	}
	first := generator.Event(0)
	last := generator.Event(generator.Count() - 1)
	if !first.Timestamps.EventAt.Equal(start) {
		t.Fatalf("first = %s", first.Timestamps.EventAt)
	}
	if last.Timestamps.EventAt.Before(start.Add(47 * time.Hour)) {
		t.Fatalf("last event too early: %s", last.Timestamps.EventAt)
	}
}

func TestPercentileNearestRank(t *testing.T) {
	samples := []time.Duration{
		1 * time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond,
		4 * time.Millisecond, 5 * time.Millisecond,
	}
	if got := Percentile(samples, 50); got != 3*time.Millisecond {
		t.Fatalf("p50 = %s", got)
	}
	if got := Percentile(samples, 95); got != 5*time.Millisecond {
		t.Fatalf("p95 = %s", got)
	}
	if got := Percentile(nil, 95); got != 0 {
		t.Fatalf("empty = %s", got)
	}
}
