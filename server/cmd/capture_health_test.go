package main

import (
	"testing"
	"time"
)

func captureQualityFixture(overrides map[string]interface{}) map[string]interface{} {
	base := map[string]interface{}{
		"enabled":                 true,
		"status":                  "healthy",
		"sensor_status":           "active",
		"interface_status":        "valid",
		"selected_interface":      "ens192",
		"loss_status":             "known",
		"clock_status":            "consistent",
		"publish_status":          "healthy",
		"spool_status":            "ok",
		"kernel_packets":          float64(1000),
		"packets":                 float64(500),
		"kernel_drops":            float64(0),
		"ring_freezes":            float64(0),
		"publish_errors":          float64(0),
		"last_packet_age_seconds": float64(1),
	}
	for key, value := range overrides {
		base[key] = value
	}
	return base
}

func TestEvaluateCaptureHealthHealthyNeedsValidWindow(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	first := evaluateCaptureHealth("agent-1", captureQualityFixture(nil), nil, now)
	if first.State != captureStateUnknown {
		t.Fatalf("first sample without a baseline must be unknown, got %s", first.State)
	}
	if first.Reason != "no_previous_sample" {
		t.Fatalf("reason = %q", first.Reason)
	}

	second := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"kernel_packets": float64(3000),
	}), &first, now.Add(30*time.Second))
	if second.State != captureStateHealthy {
		t.Fatalf("clean window state = %s (%v)", second.State, second.Reasons)
	}
	if second.LastSuccessAt == nil || !second.LastSuccessAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("last success not recorded: %v", second.LastSuccessAt)
	}
	if !second.Window.Valid || !second.Window.HasDropRatio {
		t.Fatalf("window = %+v", second.Window)
	}
	if second.DropRatioPercent == nil || *second.DropRatioPercent != 0 {
		t.Fatalf("clean window ratio = %v", second.DropRatioPercent)
	}
}

func TestEvaluateCaptureHealthPacketLossIsDegraded(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	first := evaluateCaptureHealth("agent-1", captureQualityFixture(nil), nil, now)
	second := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"kernel_packets": float64(2000),
		"kernel_drops":   float64(100),
	}), &first, now.Add(30*time.Second))

	if second.State != captureStateDegraded {
		t.Fatalf("state = %s", second.State)
	}
	if second.Reason != "packet_loss" {
		t.Fatalf("reason = %q", second.Reason)
	}
	if second.DropRatioPercent == nil {
		t.Fatal("drop ratio missing with a measurable denominator")
	}
	// 100 drops / (1000 received + 100 drops) = 9.09%
	if got := *second.DropRatioPercent; got < 9.0 || got > 9.2 {
		t.Fatalf("drop ratio = %.4f", got)
	}
}

func TestEvaluateCaptureHealthMissingDenominatorPublishesNoRatio(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	quality := captureQualityFixture(nil)
	delete(quality, "kernel_packets")
	first := evaluateCaptureHealth("agent-1", quality, nil, now)
	second := evaluateCaptureHealth("agent-1", quality, &first, now.Add(30*time.Second))

	if second.DropRatioPercent != nil {
		t.Fatalf("ratio published without a denominator: %v", *second.DropRatioPercent)
	}
	if second.Window.HasDropRatio {
		t.Fatal("window claimed a drop ratio without a denominator")
	}
	if second.State == captureStateFailed {
		t.Fatal("missing denominator must not be reported as a failure")
	}
}

func TestEvaluateCaptureHealthFallsBackToUserSpaceDenominator(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	quality := captureQualityFixture(map[string]interface{}{
		"kernel_packets": float64(0),
		"packets":        float64(500),
		"sensor_status":  "active",
	})
	first := evaluateCaptureHealth("agent-1", quality, nil, now)
	if first.Snapshot.ReceivedSource != "user_space" {
		t.Fatalf("source = %q", first.Snapshot.ReceivedSource)
	}

	quality["packets"] = float64(900)
	second := evaluateCaptureHealth("agent-1", quality, &first, now.Add(30*time.Second))
	if !second.Window.HasDropRatio || second.DropRatioPercent == nil || *second.DropRatioPercent != 0 {
		t.Fatalf("user-space denominator did not produce a ratio: %+v", second.Window)
	}
	if second.State == captureStateDegraded && second.Reason == "denominator_unknown" {
		t.Fatal("user-space denominator was ignored")
	}
}

func TestEvaluateCaptureHealthUsesMovingDenominator(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	first := evaluateCaptureHealth("agent-1", captureQualityFixture(nil), nil, now)

	// Kernel counter stalls (af_packet clears it on read) while the user-space
	// accepted counter keeps moving: the moving counter is the honest source.
	stalled := captureQualityFixture(map[string]interface{}{
		"kernel_packets": float64(1000),
		"packets":        float64(900),
	})
	second := evaluateCaptureHealth("agent-1", stalled, &first, now.Add(30*time.Second))
	if !second.Window.Valid {
		t.Fatalf("stalled kernel counter invalidated the window: %q", second.Window.Reason)
	}
	if second.Window.ReceivedSource != "user_space" {
		t.Fatalf("source = %q", second.Window.ReceivedSource)
	}
	if second.Window.ReceivedPacketDelta != 400 {
		t.Fatalf("received delta = %d", second.Window.ReceivedPacketDelta)
	}
	if !second.Window.HasDropRatio {
		t.Fatal("moving denominator did not produce a ratio")
	}
}

func TestEvaluateCaptureHealthPublishErrorsArePartial(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	first := evaluateCaptureHealth("agent-1", captureQualityFixture(nil), nil, now)
	second := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"publish_errors": float64(3),
	}), &first, now.Add(30*time.Second))
	if second.State != captureStatePartial {
		t.Fatalf("state = %s", second.State)
	}
	if second.Reason != "publish_errors" {
		t.Fatalf("reason = %q", second.Reason)
	}
}

func TestEvaluateCaptureHealthInterfaceInvalidIsFailed(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	record := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"interface_status": "invalid",
		"interface_error":  "device not found",
	}), nil, now)
	if record.State != captureStateFailed {
		t.Fatalf("state = %s", record.State)
	}
	if record.Interface != "device not found" {
		t.Fatalf("interface error not surfaced: %q", record.Interface)
	}
}

func TestEvaluateCaptureHealthDisabledIsNotHealthy(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	record := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"enabled":       false,
		"sensor_status": "disabled",
	}), nil, now)
	if record.State != captureStateDisabled {
		t.Fatalf("state = %s", record.State)
	}
	if record.Reason != "capture_disabled" {
		t.Fatalf("reason = %q", record.Reason)
	}
}

func TestEvaluateCaptureHealthCounterResetIsUnknown(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	first := evaluateCaptureHealth("agent-1", captureQualityFixture(nil), nil, now)
	second := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"kernel_packets": float64(2000),
		"kernel_drops":   float64(0),
	}), &first, now.Add(30*time.Second))

	// previous snapshot had zero counters as well, so this is a clean window.
	if second.State != captureStateHealthy {
		t.Fatalf("state = %s", second.State)
	}

	prev := captureAgentHealth{Snapshot: captureCounterSnapshot{At: now, ReceivedPackets: 5000, ReceivedSource: "kernel", KernelPackets: 5000, KernelDrops: 10}}
	reset := evaluateCaptureHealth("agent-1", captureQualityFixture(nil), &prev, now.Add(30*time.Second))
	if reset.State != captureStateUnknown {
		t.Fatalf("reset state = %s", reset.State)
	}
	if reset.Reason != "counter reset" {
		t.Fatalf("reset reason = %q", reset.Reason)
	}
}

func TestEvaluateCaptureHealthMissingCountersIsUnknown(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	quality := captureQualityFixture(nil)
	delete(quality, "kernel_drops")
	record := evaluateCaptureHealth("agent-1", quality, nil, now)
	if record.State != captureStateUnknown {
		t.Fatalf("state = %s", record.State)
	}
	if record.Reason != "counters_missing" {
		t.Fatalf("reason = %q", record.Reason)
	}
}

func TestEvaluateCaptureHealthKeepsSinceWhileStateStable(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	first := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"interface_status": "invalid",
	}), nil, now)
	second := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"interface_status": "invalid",
	}), &first, now.Add(60*time.Second))
	if !second.Since.Equal(now) {
		t.Fatalf("since moved while state was stable: %v", second.Since)
	}

	recovered := evaluateCaptureHealth("agent-1", captureQualityFixture(nil), &second, now.Add(90*time.Second))
	if recovered.State == captureStateFailed {
		t.Fatal("recovered sensor still failed")
	}
	if !recovered.Since.Equal(now.Add(90 * time.Second)) {
		t.Fatalf("since not reset on transition: %v", recovered.Since)
	}
}

func TestEvaluateCaptureHealthEngineFallbackIsVisible(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	first := evaluateCaptureHealth("agent-1", captureQualityFixture(nil), nil, now)
	second := evaluateCaptureHealth("agent-1", captureQualityFixture(map[string]interface{}{
		"kernel_packets":   float64(2000),
		"requested_engine": "pf_ring",
		"active_engine":    "af_packet",
		"fallback_reason":  "pf_ring unavailable",
	}), &first, now.Add(30*time.Second))

	if second.State != captureStateDegraded {
		t.Fatalf("fallback state = %s", second.State)
	}
	if second.Reason != "engine_fallback" {
		t.Fatalf("reason = %q", second.Reason)
	}
	if second.RequestedEngine != "pf_ring" || second.ActiveEngine != "af_packet" || second.FallbackReason == "" {
		t.Fatalf("fallback not published: %+v", second)
	}
}

func TestSummarizeCaptureHealthWorstStateWins(t *testing.T) {
	summary := summarizeCaptureHealth([]captureAgentHealth{
		{AgentID: "a", State: captureStateHealthy},
		{AgentID: "b", State: captureStateUnknown, Reason: "no_previous_sample"},
	})
	if summary.State != captureStateUnknown {
		t.Fatalf("state = %s", summary.State)
	}
	if summary.Counts[captureStateHealthy] != 1 || summary.Counts[captureStateUnknown] != 1 {
		t.Fatalf("counts = %v", summary.Counts)
	}

	empty := summarizeCaptureHealth(nil)
	if empty.State != captureStateUnknown || empty.Reason != "no_sensor_report" {
		t.Fatalf("empty summary = %s/%s", empty.State, empty.Reason)
	}
}

func TestCaptureQualityFromCapabilities(t *testing.T) {
	capabilities := map[string]interface{}{
		"traffic_collector": map[string]interface{}{
			"capture_quality": map[string]interface{}{"kernel_drops": float64(1)},
		},
	}
	if _, ok := captureQualityFromCapabilities(capabilities); !ok {
		t.Fatal("capture quality not extracted")
	}
	if _, ok := captureQualityFromCapabilities(map[string]interface{}{}); ok {
		t.Fatal("empty capabilities produced a capture quality")
	}
}
