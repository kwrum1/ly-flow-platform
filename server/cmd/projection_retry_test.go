package main

import (
	"testing"
	"time"
)

func TestProjectionBackoffGrowsAndCaps(t *testing.T) {
	cases := map[int]time.Duration{
		0:  30 * time.Second,
		1:  30 * time.Second,
		2:  60 * time.Second,
		3:  120 * time.Second,
		4:  240 * time.Second,
		20: time.Hour,
	}
	for attempts, want := range cases {
		if got := projectionBackoff(attempts); got != want {
			t.Fatalf("projectionBackoff(%d)=%s want %s", attempts, got, want)
		}
	}
	if got := projectionBackoff(-1); got != 30*time.Second {
		t.Fatalf("negative attempts=%s", got)
	}
}

func TestProjectionNextStatus(t *testing.T) {
	if got := projectionNextStatus(1, false); got != projectionStatusRetrying {
		t.Fatalf("attempt 1 = %s", got)
	}
	if got := projectionNextStatus(projectionMaxAttempts, false); got != projectionStatusPermanent {
		t.Fatalf("max attempts = %s", got)
	}
	if got := projectionNextStatus(1, true); got != projectionStatusPermanent {
		t.Fatalf("permanent flag = %s", got)
	}
}

func TestProjectionStoreNilIsSafe(t *testing.T) {
	var store *projectionRetryStore
	if err := store.EnsureSchema(nil); err != nil {
		t.Fatalf("nil store EnsureSchema: %v", err)
	}
	if err := store.Enqueue(nil, "e1", []byte(`{}`), nil); err != nil {
		t.Fatalf("nil store Enqueue: %v", err)
	}
	jobs, err := store.ClaimDue(nil, 10)
	if err != nil || jobs != nil {
		t.Fatalf("nil store ClaimDue: %v %v", jobs, err)
	}
}
