package main

import "time"

// captureCounterMaxSampleGap is the largest interval two samples may span while
// still describing the same observation window. Anything wider is a sampling
// gap: the deltas remain visible to the caller, but the window is not a valid
// per-second visibility statement.
const captureCounterMaxSampleGap = 300 * time.Second

// captureCounterSnapshot is one point-in-time reading of the capture pipeline
// counters exported by the sensor. The counters are monotonic for the lifetime
// of a sensor process; a process restart or a sensor swap resets them.
type captureCounterSnapshot struct {
	At time.Time `json:"at"`
	// ReceivedPackets is the packet denominator. It prefers the kernel socket
	// counter and falls back to the user-space accepted counter when the
	// kernel counter is unavailable (af_packet reports 0 on some kernels).
	ReceivedPackets uint64 `json:"received_packets"`
	// ReceivedSource records which counter produced ReceivedPackets so a
	// source switch is never mistaken for real traffic growth.
	ReceivedSource string `json:"received_source,omitempty"`
	KernelPackets  uint64 `json:"kernel_packets"`
	UserPackets    uint64 `json:"user_packets"`
	KernelDrops    uint64 `json:"kernel_drops"`
	RingFreezes    uint64 `json:"ring_freezes"`
	PublishErrors  uint64 `json:"publish_errors"`
}

// captureCounterWindow is the delta between two snapshots together with the
// trustworthiness of that delta. Valid is false whenever the window cannot
// support a per-second claim (bad timestamps, counter reset, sampling gap).
type captureCounterWindow struct {
	From                time.Time `json:"from"`
	To                  time.Time `json:"to"`
	Seconds             float64   `json:"seconds"`
	ReceivedPacketDelta uint64    `json:"received_packet_delta"`
	KernelPacketDelta   uint64    `json:"kernel_packet_delta"`
	UserPacketDelta     uint64    `json:"user_packet_delta"`
	ReceivedSource      string    `json:"received_source,omitempty"`
	KernelDropDelta     uint64    `json:"kernel_drop_delta"`
	RingFreezeDelta     uint64    `json:"ring_freeze_delta"`
	PublishErrorDelta   uint64    `json:"publish_error_delta"`
	Valid               bool      `json:"valid"`
	Reason              string    `json:"reason,omitempty"`
	DropRatePerSecond   float64   `json:"drop_rate_per_second"`
	HasDropRate         bool      `json:"has_drop_rate"`
	// DropRatioPercent is drops/(received+drops) over the window. It is only
	// published when the denominator is measurable; a missing denominator must
	// never be rendered as 0%.
	DropRatioPercent float64 `json:"drop_ratio_percent"`
	HasDropRatio     bool    `json:"has_drop_ratio"`
	DropDenominator  uint64  `json:"drop_denominator"`
}

// computeCaptureWindow derives the counter delta between two snapshots.
//
// A counter that moves backwards is treated as a sensor restart, never as a
// wrap-around: the window is invalid, every delta is zero and no rate is
// reported, so a reset can never surface as a huge positive drop delta. A gap
// wider than captureCounterMaxSampleGap invalidates the window but keeps the
// deltas so the caller can still inspect what was observed.
func computeCaptureWindow(previous, current captureCounterSnapshot) captureCounterWindow {
	window := captureCounterWindow{From: previous.At, To: current.At}
	if previous.At.IsZero() || !current.At.After(previous.At) {
		window.Reason = "invalid sample window"
		return window
	}
	if current.KernelDrops < previous.KernelDrops || current.RingFreezes < previous.RingFreezes || current.PublishErrors < previous.PublishErrors ||
		(previous.ReceivedPackets > 0 && current.ReceivedPackets < previous.ReceivedPackets) ||
		(previous.UserPackets > 0 && current.UserPackets < previous.UserPackets) {
		window.Reason = "counter reset"
		return window
	}
	seconds := current.At.Sub(previous.At).Seconds()
	window.Seconds = seconds
	window.KernelPacketDelta = current.KernelPackets - previous.KernelPackets
	window.UserPacketDelta = current.UserPackets - previous.UserPackets
	// af_packet clears the kernel packet counter on every stats read on some
	// kernels, so its delta is only usable when it actually moved. Otherwise
	// the monotonic user-space accepted counter is the honest denominator.
	switch {
	case window.KernelPacketDelta > 0:
		window.ReceivedPacketDelta = window.KernelPacketDelta
		window.ReceivedSource = "kernel"
	case window.UserPacketDelta > 0:
		window.ReceivedPacketDelta = window.UserPacketDelta
		window.ReceivedSource = "user_space"
	default:
		window.ReceivedPacketDelta = 0
		window.ReceivedSource = current.ReceivedSource
	}
	window.KernelDropDelta = current.KernelDrops - previous.KernelDrops
	window.RingFreezeDelta = current.RingFreezes - previous.RingFreezes
	window.PublishErrorDelta = current.PublishErrors - previous.PublishErrors
	window.Valid = true
	// The rate is an average over the observed interval. It is only advertised
	// when the interval is at least one second, except for the exact-zero case
	// where "no drops" is a statement the window can always support.
	window.DropRatePerSecond = float64(window.KernelDropDelta) / seconds
	window.HasDropRate = window.KernelDropDelta == 0 || seconds >= 1
	window.DropDenominator = window.ReceivedPacketDelta + window.KernelDropDelta
	if window.DropDenominator > 0 {
		window.DropRatioPercent = float64(window.KernelDropDelta) / float64(window.DropDenominator) * 100
		window.HasDropRatio = true
	}
	if seconds > captureCounterMaxSampleGap.Seconds() {
		window.Valid = false
		window.Reason = "sampling gap"
	}
	return window
}

// captureVisibilityState maps a window onto the visibility contract used by
// the capture console. Only a valid window can claim health; publish errors
// mean part of the pipeline is blind even when the loss counters look clean.
func captureVisibilityState(window captureCounterWindow) string {
	if !window.Valid {
		return "unknown"
	}
	if window.KernelDropDelta == 0 && window.RingFreezeDelta == 0 && window.PublishErrorDelta == 0 {
		return "healthy"
	}
	if window.PublishErrorDelta > 0 {
		return "partial"
	}
	return "degraded"
}
