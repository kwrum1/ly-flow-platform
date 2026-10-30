package main

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sensor capture health states. They are deliberately distinct: a sensor that
// is switched off is not "healthy", and a sensor with no trustworthy counters
// is not "degraded" — it is unknown, because the platform cannot make a claim.
const (
	captureStateHealthy  = "healthy"
	captureStateDegraded = "degraded"
	captureStatePartial  = "partial"
	captureStateFailed   = "failed"
	captureStateUnknown  = "unknown"
	captureStateDisabled = "disabled"
)

func captureStateRank(state string) int {
	switch state {
	case captureStateFailed:
		return 5
	case captureStatePartial:
		return 4
	case captureStateDegraded:
		return 3
	case captureStateUnknown:
		return 2
	case captureStateHealthy:
		return 1
	default:
		return 0
	}
}

// captureAgentHealth is the server-side verdict for one sensor's capture
// pipeline. Every field is derived from reported data; nothing is defaulted to
// zero to look healthy.
type captureAgentHealth struct {
	AgentID              string                 `json:"agent_id"`
	Hostname             string                 `json:"hostname,omitempty"`
	State                string                 `json:"state"`
	Reason               string                 `json:"reason"`
	Reasons              []string               `json:"reasons"`
	Since                time.Time              `json:"since"`
	LastSampleAt         time.Time              `json:"last_sample_at"`
	LastSuccessAt        *time.Time             `json:"last_success_at,omitempty"`
	Visibility           string                 `json:"visibility"`
	LossKnown            bool                   `json:"loss_known"`
	Window               captureCounterWindow   `json:"window"`
	DropDenominator      uint64                 `json:"drop_denominator"`
	DropRatioPercent     *float64               `json:"drop_ratio_percent"`
	LastPacketAgeSeconds *int64                 `json:"last_packet_age_seconds,omitempty"`
	Interface            string                 `json:"interface,omitempty"`
	SensorStatus         string                 `json:"sensor_status,omitempty"`
	RequestedEngine      string                 `json:"requested_engine,omitempty"`
	ActiveEngine         string                 `json:"active_engine,omitempty"`
	FallbackReason       string                 `json:"fallback_reason,omitempty"`
	BackendStatus        string                 `json:"backend_status,omitempty"`
	LifetimeDrops        *uint64                `json:"lifetime_drops,omitempty"`
	Snapshot             captureCounterSnapshot `json:"-"`
}

// captureHealthStore keeps the latest verdict per agent. It is intentionally
// process-local: after a restart the platform reports "unknown" until the next
// heartbeat rather than reusing a verdict it can no longer justify.
type captureHealthStore struct {
	mu      sync.RWMutex
	byAgent map[string]captureAgentHealth
}

var captureHealthRegistry = &captureHealthStore{byAgent: map[string]captureAgentHealth{}}

func (s *captureHealthStore) get(agentID string) (captureAgentHealth, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.byAgent[agentID]
	return record, ok
}

func (s *captureHealthStore) put(record captureAgentHealth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byAgent[record.AgentID] = record
}

func (s *captureHealthStore) list() []captureAgentHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]captureAgentHealth, 0, len(s.byAgent))
	for _, record := range s.byAgent {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

func (s *captureHealthStore) forget(agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byAgent, agentID)
}

// captureQualityFromCapabilities extracts the traffic collector snapshot that
// the agent sends inside its heartbeat capability model.
func captureQualityFromCapabilities(capabilities map[string]interface{}) (map[string]interface{}, bool) {
	if len(capabilities) == 0 {
		return nil, false
	}
	collector, ok := capabilities["traffic_collector"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	quality, ok := collector["capture_quality"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	return quality, true
}

func captureString(m map[string]interface{}, key string) string {
	value, ok := m[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	}
	return ""
}

// captureUint reports (value, present). A missing counter is never treated as
// zero, because "0 drops" and "no data" have opposite operational meanings.
func captureUint(m map[string]interface{}, key string) (uint64, bool) {
	value, ok := m[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		if typed < 0 {
			return 0, false
		}
		return uint64(typed), true
	case int:
		if typed < 0 {
			return 0, false
		}
		return uint64(typed), true
	case int64:
		if typed < 0 {
			return 0, false
		}
		return uint64(typed), true
	case uint64:
		return typed, true
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}

func captureFloat(m map[string]interface{}, key string) (float64, bool) {
	value, ok := m[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		return typed, true
	case int64:
		return float64(typed), true
	case int:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}

// evaluateCaptureHealth turns one heartbeat snapshot into a verdict. previous
// carries the previous verdict so "since" and "last_success_at" describe
// persistence, not just this sample.
func evaluateCaptureHealth(agentID string, quality map[string]interface{}, previous *captureAgentHealth, now time.Time) captureAgentHealth {
	record := captureAgentHealth{
		AgentID:         agentID,
		LastSampleAt:    now,
		Since:           now,
		Interface:       captureString(quality, "selected_interface"),
		SensorStatus:    captureString(quality, "sensor_status"),
		RequestedEngine: captureString(quality, "requested_engine"),
		ActiveEngine:    captureString(quality, "active_engine"),
		FallbackReason:  captureString(quality, "fallback_reason"),
		BackendStatus:   captureString(quality, "backend_status"),
	}

	enabled := true
	if raw, ok := quality["enabled"].(bool); ok {
		enabled = raw
	}

	reasons := []string{}
	addReason := func(reason string) { reasons = append(reasons, reason) }

	if age, ok := captureUint(quality, "last_packet_age_seconds"); ok {
		ageValue := int64(age)
		record.LastPacketAgeSeconds = &ageValue
	}

	snapshot, countersComplete := captureSnapshotFromQuality(quality, now)
	if countersComplete {
		record.Snapshot = snapshot
		lifetime := snapshot.KernelDrops
		record.LifetimeDrops = &lifetime
	} else {
		addReason("counters_missing")
	}

	if previous != nil && !previous.Snapshot.At.IsZero() && countersComplete {
		record.Window = computeCaptureWindow(previous.Snapshot, snapshot)
	} else if countersComplete {
		record.Window = captureCounterWindow{To: now, Reason: "no_previous_sample"}
	} else {
		record.Window = captureCounterWindow{To: now, Reason: "counters_missing"}
	}
	record.Visibility = captureVisibilityState(record.Window)
	record.LossKnown = captureString(quality, "loss_status") == "known"

	if record.Window.Valid && record.Window.HasDropRatio {
		ratio := record.Window.DropRatioPercent
		record.DropRatioPercent = &ratio
		record.DropDenominator = record.Window.DropDenominator
	}

	state := captureStateHealthy

	switch {
	case !enabled:
		state = captureStateDisabled
		addReason("capture_disabled")
	case captureString(quality, "interface_status") == "invalid":
		state = captureStateFailed
		addReason("interface_invalid")
		if detail := captureString(quality, "interface_error"); detail != "" {
			record.Interface = detail
		}
	case captureString(quality, "spool_status") == "error" || captureString(quality, "spool_error") != "":
		state = captureStateFailed
		addReason("spool_unreadable")
	default:
		switch {
		case !countersComplete:
			state = captureStateUnknown
		case !record.Window.Valid:
			state = captureStateUnknown
			addReason(record.Window.Reason)
		case record.Window.PublishErrorDelta > 0:
			state = captureStatePartial
			addReason("publish_errors")
		case record.Window.KernelDropDelta > 0 || record.Window.RingFreezeDelta > 0:
			state = captureStateDegraded
			addReason("packet_loss")
		case !record.LossKnown:
			state = captureStateDegraded
			addReason("loss_unknown")
		case captureString(quality, "sensor_status") == "stale":
			state = captureStateDegraded
			addReason("sensor_stale")
		case captureString(quality, "clock_status") == "skewed":
			state = captureStateDegraded
			addReason("clock_skewed")
		case captureString(quality, "spool_status") == "pressured":
			state = captureStatePartial
			addReason("spool_pressured")
		}
	}

	// A backend fallback means the requested capture engine is not in use.
	// That is not a failure, but it must not be reported as healthy either.
	if state == captureStateHealthy && record.FallbackReason != "" {
		state = captureStateDegraded
		addReason("engine_fallback")
	}

	record.State = state
	record.Reasons = reasons
	if len(reasons) > 0 {
		record.Reason = reasons[0]
	}

	if previous != nil {
		if previous.State == state {
			record.Since = previous.Since
		}
		record.LastSuccessAt = previous.LastSuccessAt
	}
	if state == captureStateHealthy {
		success := now
		record.LastSuccessAt = &success
	}
	return record
}

func captureSnapshotFromQuality(quality map[string]interface{}, now time.Time) (captureCounterSnapshot, bool) {
	packets, hasPackets := captureUint(quality, "kernel_packets")
	userPackets, hasUserPackets := captureUint(quality, "packets")
	drops, hasDrops := captureUint(quality, "kernel_drops")
	freezes, hasFreezes := captureUint(quality, "ring_freezes")
	publishErrors, hasPublishErrors := captureUint(quality, "publish_errors")
	if !hasDrops || !hasFreezes || !hasPublishErrors {
		return captureCounterSnapshot{}, false
	}
	snapshot := captureCounterSnapshot{
		At:            now,
		KernelPackets: packets,
		UserPackets:   userPackets,
		KernelDrops:   drops,
		RingFreezes:   freezes,
		PublishErrors: publishErrors,
	}
	// The kernel socket counter is authoritative when it moves. Some kernels
	// report zero packets for af_packet while still reporting drops, so fall
	// back to the user-space accepted counter rather than publishing no ratio.
	switch {
	case hasPackets && packets > 0:
		snapshot.ReceivedPackets = packets
		snapshot.ReceivedSource = "kernel"
	case hasUserPackets:
		snapshot.ReceivedPackets = userPackets
		snapshot.ReceivedSource = "user_space"
	default:
		snapshot.ReceivedSource = ""
	}
	return snapshot, true
}

// captureHealthSummary is the aggregate returned by the debug and health
// surfaces. Worst state wins; counts are explicit so a single broken sensor
// cannot hide behind a fleet average.
type captureHealthSummary struct {
	State    string               `json:"state"`
	Reason   string               `json:"reason,omitempty"`
	Counts   map[string]int       `json:"counts"`
	Agents   []captureAgentHealth `json:"agents"`
	Contract string               `json:"contract"`
}

func summarizeCaptureHealth(records []captureAgentHealth) captureHealthSummary {
	summary := captureHealthSummary{
		State:  captureStateUnknown,
		Counts: map[string]int{},
		Agents: records,
		Contract: "healthy 需要有效窗口且零丢包/零发布错误；丢包率分母不可信时不发布比率；" +
			"重启后到下一次心跳之间状态为 unknown，不沿用旧结论。",
	}
	if len(records) == 0 {
		summary.Reason = "no_sensor_report"
		return summary
	}
	worst := captureStateHealthy
	worstReason := ""
	for _, record := range records {
		summary.Counts[record.State]++
		if captureStateRank(record.State) > captureStateRank(worst) {
			worst = record.State
			worstReason = record.Reason
		}
	}
	summary.State = worst
	summary.Reason = worstReason
	return summary
}

// captureDebugPayload is what /api/v1/debug/components publishes.
func captureDebugPayload() captureHealthSummary {
	return summarizeCaptureHealth(captureHealthRegistry.list())
}
