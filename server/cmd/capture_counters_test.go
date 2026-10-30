package main

import (
	"math"
	"testing"
	"time"
)

func captureTestBaseTime() time.Time {
	return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
}

func TestCaptureCounterWindowNormal(t *testing.T) {
	// Given
	base := captureTestBaseTime()
	previous := captureCounterSnapshot{At: base, KernelDrops: 10, RingFreezes: 1, PublishErrors: 2}
	current := captureCounterSnapshot{At: base.Add(60 * time.Second), KernelDrops: 610, RingFreezes: 3, PublishErrors: 2}

	// When
	window := computeCaptureWindow(previous, current)

	// Then
	if !window.Valid || window.Reason != "" {
		t.Fatalf("normal window valid=%v reason=%q", window.Valid, window.Reason)
	}
	if window.Seconds != 60 {
		t.Fatalf("normal window seconds=%v, want 60", window.Seconds)
	}
	if window.KernelDropDelta != 600 || window.RingFreezeDelta != 2 || window.PublishErrorDelta != 0 {
		t.Fatalf("normal window deltas kernel=%d ring=%d publish=%d, want 600/2/0", window.KernelDropDelta, window.RingFreezeDelta, window.PublishErrorDelta)
	}
	if !window.HasDropRate || window.DropRatePerSecond != 10 {
		t.Fatalf("normal window rate=%v has=%v, want 10/s", window.DropRatePerSecond, window.HasDropRate)
	}
	if !window.From.Equal(previous.At) || !window.To.Equal(current.At) {
		t.Fatalf("normal window bounds from=%v to=%v", window.From, window.To)
	}
	if state := captureVisibilityState(window); state != "degraded" {
		t.Fatalf("normal window state=%q, want degraded", state)
	}
}

func TestCaptureCounterWindowZeroDrop(t *testing.T) {
	// Given
	base := captureTestBaseTime()
	previous := captureCounterSnapshot{At: base, KernelDrops: 42, RingFreezes: 0, PublishErrors: 0}
	current := captureCounterSnapshot{At: base.Add(30 * time.Second), KernelDrops: 42, RingFreezes: 0, PublishErrors: 0}

	// When
	window := computeCaptureWindow(previous, current)

	// Then
	if !window.Valid || window.KernelDropDelta != 0 {
		t.Fatalf("zero drop window valid=%v delta=%d", window.Valid, window.KernelDropDelta)
	}
	if !window.HasDropRate || window.DropRatePerSecond != 0 {
		t.Fatalf("zero drop window rate=%v has=%v, want 0/s reported", window.DropRatePerSecond, window.HasDropRate)
	}
	if state := captureVisibilityState(window); state != "healthy" {
		t.Fatalf("zero drop window state=%q, want healthy", state)
	}
}

func TestCaptureCounterWindowPublishErrors(t *testing.T) {
	// Given
	base := captureTestBaseTime()
	previous := captureCounterSnapshot{At: base, KernelDrops: 0, RingFreezes: 0, PublishErrors: 7}
	current := captureCounterSnapshot{At: base.Add(10 * time.Second), KernelDrops: 0, RingFreezes: 0, PublishErrors: 9}
	dropsPrevious := captureCounterSnapshot{At: base, KernelDrops: 1, RingFreezes: 1, PublishErrors: 7}
	dropsCurrent := captureCounterSnapshot{At: base.Add(10 * time.Second), KernelDrops: 3, RingFreezes: 2, PublishErrors: 9}

	// When
	window := computeCaptureWindow(previous, current)
	mixed := computeCaptureWindow(dropsPrevious, dropsCurrent)

	// Then
	if !window.Valid || window.PublishErrorDelta != 2 {
		t.Fatalf("publish error window valid=%v delta=%d", window.Valid, window.PublishErrorDelta)
	}
	if state := captureVisibilityState(window); state != "partial" {
		t.Fatalf("publish error window state=%q, want partial", state)
	}
	if state := captureVisibilityState(mixed); state != "partial" {
		t.Fatalf("mixed publish error window state=%q, want partial", state)
	}
}

func TestCaptureCounterWindowRingFreezeDegraded(t *testing.T) {
	// Given
	base := captureTestBaseTime()
	previous := captureCounterSnapshot{At: base, KernelDrops: 0, RingFreezes: 4, PublishErrors: 0}
	current := captureCounterSnapshot{At: base.Add(10 * time.Second), KernelDrops: 0, RingFreezes: 6, PublishErrors: 0}

	// When
	window := computeCaptureWindow(previous, current)

	// Then
	if !window.Valid || window.RingFreezeDelta != 2 {
		t.Fatalf("ring freeze window valid=%v delta=%d", window.Valid, window.RingFreezeDelta)
	}
	if state := captureVisibilityState(window); state != "degraded" {
		t.Fatalf("ring freeze window state=%q, want degraded", state)
	}
}

func TestCaptureCounterWindowReset(t *testing.T) {
	cases := []struct {
		name     string
		previous captureCounterSnapshot
		current  captureCounterSnapshot
	}{
		{name: "kernel drops", previous: captureCounterSnapshot{KernelDrops: 1000, RingFreezes: 4, PublishErrors: 2}, current: captureCounterSnapshot{KernelDrops: 12, RingFreezes: 4, PublishErrors: 2}},
		{name: "ring freezes", previous: captureCounterSnapshot{KernelDrops: 1000, RingFreezes: 4, PublishErrors: 2}, current: captureCounterSnapshot{KernelDrops: 1000, RingFreezes: 0, PublishErrors: 2}},
		{name: "publish errors", previous: captureCounterSnapshot{KernelDrops: 1000, RingFreezes: 4, PublishErrors: 2}, current: captureCounterSnapshot{KernelDrops: 1000, RingFreezes: 4, PublishErrors: 0}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// Given
			base := captureTestBaseTime()
			previous := testCase.previous
			previous.At = base
			current := testCase.current
			current.At = base.Add(60 * time.Second)

			// When
			window := computeCaptureWindow(previous, current)

			// Then
			if window.Valid {
				t.Fatal("reset window was reported valid")
			}
			if window.Reason != "counter reset" {
				t.Fatalf("reset window reason=%q, want \"counter reset\"", window.Reason)
			}
			if window.KernelDropDelta != 0 || window.RingFreezeDelta != 0 || window.PublishErrorDelta != 0 {
				t.Fatalf("reset window deltas kernel=%d ring=%d publish=%d, want all zero", window.KernelDropDelta, window.RingFreezeDelta, window.PublishErrorDelta)
			}
			if window.HasDropRate || window.DropRatePerSecond != 0 {
				t.Fatalf("reset window rate=%v has=%v, want no rate", window.DropRatePerSecond, window.HasDropRate)
			}
			if state := captureVisibilityState(window); state != "unknown" {
				t.Fatalf("reset window state=%q, want unknown", state)
			}
		})
	}
}

func TestCaptureCounterResetNeverWraps(t *testing.T) {
	cases := []struct {
		name     string
		previous uint64
		current  uint64
	}{
		{name: "near uint64 maximum", previous: math.MaxUint64 - 2, current: 7},
		{name: "uint32 wrap shape", previous: 4_294_967_290, current: 5},
		{name: "restart to zero", previous: 900, current: 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// Given
			base := captureTestBaseTime()
			previous := captureCounterSnapshot{At: base, KernelDrops: testCase.previous}
			current := captureCounterSnapshot{At: base.Add(30 * time.Second), KernelDrops: testCase.current}

			// When
			window := computeCaptureWindow(previous, current)

			// Then
			if window.KernelDropDelta != 0 {
				t.Fatalf("reset produced delta %d from %d to %d, want 0 (no wrapped delta)", window.KernelDropDelta, testCase.previous, testCase.current)
			}
			if window.Valid {
				t.Fatal("reset window was reported valid")
			}
			if window.HasDropRate || window.DropRatePerSecond != 0 {
				t.Fatalf("reset window rate=%v has=%v, want no rate", window.DropRatePerSecond, window.HasDropRate)
			}
		})
	}
}

func TestCaptureCounterWindowSamplingGap(t *testing.T) {
	// Given
	base := captureTestBaseTime()
	previous := captureCounterSnapshot{At: base, KernelDrops: 100, RingFreezes: 3, PublishErrors: 1}
	current := captureCounterSnapshot{At: base.Add(600 * time.Second), KernelDrops: 700, RingFreezes: 3, PublishErrors: 1}

	// When
	window := computeCaptureWindow(previous, current)

	// Then
	if window.Valid {
		t.Fatal("sampling gap window was reported valid")
	}
	if window.Reason != "sampling gap" {
		t.Fatalf("sampling gap reason=%q, want \"sampling gap\"", window.Reason)
	}
	if window.Seconds != 600 {
		t.Fatalf("sampling gap seconds=%v, want 600", window.Seconds)
	}
	if window.KernelDropDelta != 600 || window.RingFreezeDelta != 0 || window.PublishErrorDelta != 0 {
		t.Fatalf("sampling gap deltas kernel=%d ring=%d publish=%d, want 600/0/0 preserved", window.KernelDropDelta, window.RingFreezeDelta, window.PublishErrorDelta)
	}
	if state := captureVisibilityState(window); state != "unknown" {
		t.Fatalf("sampling gap state=%q, want unknown", state)
	}
}

func TestCaptureCounterWindowSampleGapBoundary(t *testing.T) {
	// Given
	base := captureTestBaseTime()

	// When
	atLimit := computeCaptureWindow(
		captureCounterSnapshot{At: base, KernelDrops: 5},
		captureCounterSnapshot{At: base.Add(300 * time.Second), KernelDrops: 15},
	)
	overLimit := computeCaptureWindow(
		captureCounterSnapshot{At: base, KernelDrops: 5},
		captureCounterSnapshot{At: base.Add(301 * time.Second), KernelDrops: 15},
	)

	// Then
	if !atLimit.Valid || atLimit.Reason != "" || atLimit.KernelDropDelta != 10 {
		t.Fatalf("300s window valid=%v reason=%q delta=%d, want valid with delta 10", atLimit.Valid, atLimit.Reason, atLimit.KernelDropDelta)
	}
	if overLimit.Valid || overLimit.Reason != "sampling gap" || overLimit.KernelDropDelta != 10 {
		t.Fatalf("301s window valid=%v reason=%q delta=%d, want sampling gap with delta 10 preserved", overLimit.Valid, overLimit.Reason, overLimit.KernelDropDelta)
	}
}

func TestCaptureCounterWindowInvalidTimestamps(t *testing.T) {
	base := captureTestBaseTime()
	cases := []struct {
		name     string
		previous time.Time
		current  time.Time
	}{
		{name: "zero previous", previous: time.Time{}, current: base},
		{name: "zero current", previous: base, current: time.Time{}},
		{name: "equal timestamps", previous: base, current: base},
		{name: "current before previous", previous: base, current: base.Add(-time.Minute)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// Given
			previous := captureCounterSnapshot{At: testCase.previous, KernelDrops: 10, RingFreezes: 2, PublishErrors: 1}
			current := captureCounterSnapshot{At: testCase.current, KernelDrops: 20, RingFreezes: 3, PublishErrors: 2}

			// When
			window := computeCaptureWindow(previous, current)

			// Then
			if window.Valid {
				t.Fatal("invalid timestamp window was reported valid")
			}
			if window.Reason != "invalid sample window" {
				t.Fatalf("invalid timestamp reason=%q, want \"invalid sample window\"", window.Reason)
			}
			if window.Seconds != 0 || window.KernelDropDelta != 0 || window.RingFreezeDelta != 0 || window.PublishErrorDelta != 0 {
				t.Fatalf("invalid timestamp window seconds=%v deltas kernel=%d ring=%d publish=%d, want zero", window.Seconds, window.KernelDropDelta, window.RingFreezeDelta, window.PublishErrorDelta)
			}
			if window.HasDropRate || window.DropRatePerSecond != 0 {
				t.Fatalf("invalid timestamp window rate=%v has=%v, want no rate", window.DropRatePerSecond, window.HasDropRate)
			}
			if state := captureVisibilityState(window); state != "unknown" {
				t.Fatalf("invalid timestamp window state=%q, want unknown", state)
			}
		})
	}
}

func TestCaptureCounterWindowSubSecondHasNoDropRate(t *testing.T) {
	// Given
	base := captureTestBaseTime()
	previous := captureCounterSnapshot{At: base, KernelDrops: 3}
	current := captureCounterSnapshot{At: base.Add(500 * time.Millisecond), KernelDrops: 8}

	// When
	window := computeCaptureWindow(previous, current)

	// Then
	if !window.Valid || window.KernelDropDelta != 5 {
		t.Fatalf("sub-second window valid=%v delta=%d, want valid delta 5", window.Valid, window.KernelDropDelta)
	}
	if window.HasDropRate {
		t.Fatalf("sub-second window advertised a per-second rate of %v", window.DropRatePerSecond)
	}
}

func TestCaptureVisibilityState(t *testing.T) {
	validZero := captureCounterWindow{Valid: true}
	cases := []struct {
		name   string
		window captureCounterWindow
		want   string
	}{
		{name: "invalid window", window: captureCounterWindow{Valid: false, Reason: "counter reset"}, want: "unknown"},
		{name: "sampling gap", window: captureCounterWindow{Valid: false, Reason: "sampling gap", KernelDropDelta: 5}, want: "unknown"},
		{name: "all zero", window: validZero, want: "healthy"},
		{name: "publish errors only", window: captureCounterWindow{Valid: true, PublishErrorDelta: 1}, want: "partial"},
		{name: "publish errors with drops", window: captureCounterWindow{Valid: true, KernelDropDelta: 3, PublishErrorDelta: 1}, want: "partial"},
		{name: "kernel drops only", window: captureCounterWindow{Valid: true, KernelDropDelta: 1}, want: "degraded"},
		{name: "ring freezes only", window: captureCounterWindow{Valid: true, RingFreezeDelta: 1}, want: "degraded"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// When
			state := captureVisibilityState(testCase.window)

			// Then
			if state != testCase.want {
				t.Fatalf("visibility state=%q, want %q", state, testCase.want)
			}
		})
	}
}
