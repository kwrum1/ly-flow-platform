package main

import (
	"errors"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
)

const (
	suricataProfileVersion       = "7.0.11"
	suricataProfileNativeSchema  = "suricata.eve.v7.0.11"
	suricataProfileRulePack      = "lyflow-suricata-profile-rules-v1"
	suricataProfileEnabledEnv    = "SURICATA_PROFILE_ENABLED"
	suricataDeadLetterSuffix     = ".dead-letter.jsonl"
	suricataMaxLineBytes         = 256 * 1024
	suricataMaxDeadLetterBytes   = 4 * 1024 * 1024
	suricataDeadLetterSampleSize = 4 * 1024
)

var (
	errSuricataVersionDrift         = errors.New("suricata profile version drift")
	errUnsupportedSuricataEventType = errors.New("unsupported Suricata EVE event type")
	suricataProfileCoverage         = []string{"flow", "alert", "dns", "http", "tls"}
)

type suricataProfileRuntime struct {
	parsedLines             uint64
	deadLetteredLines       uint64
	malformedLines          uint64
	truncatedLines          uint64
	oversizedLines          uint64
	versionDriftLines       uint64
	unsupportedLines        uint64
	publishErrors           uint64
	deadLetterDropped       uint64
	lastEventUnix           int64
	lastError               atomic.Value
	pendingMu               sync.Mutex
	pendingOffset           int64
	pendingSize             int64
	pendingObservationValid bool
}

func suricataProfileEnabled() bool {
	enabled, err := strconv.ParseBool(os.Getenv(suricataProfileEnabledEnv))
	return err == nil && enabled
}

func (a *Agent) suricataProfileHealth() map[string]interface{} {
	status := "disabled"
	if suricataProfileEnabled() {
		status = "ready"
		if atomic.LoadUint64(&a.suricataProfile.parsedLines) > 0 {
			status = "healthy"
		}
		if atomic.LoadUint64(&a.suricataProfile.deadLetteredLines) > 0 || atomic.LoadUint64(&a.suricataProfile.publishErrors) > 0 {
			status = "degraded"
		}
	}
	return map[string]interface{}{
		"enabled":                   suricataProfileEnabled(),
		"status":                    status,
		"engine_version":            suricataProfileVersion,
		"native_schema":             suricataProfileNativeSchema,
		"rule_pack_version":         suricataProfileRulePack,
		"coverage":                  append([]string(nil), suricataProfileCoverage...),
		"parsed_lines":              atomic.LoadUint64(&a.suricataProfile.parsedLines),
		"dead_lettered_lines":       atomic.LoadUint64(&a.suricataProfile.deadLetteredLines),
		"malformed_lines":           atomic.LoadUint64(&a.suricataProfile.malformedLines),
		"truncated_lines":           atomic.LoadUint64(&a.suricataProfile.truncatedLines),
		"oversized_lines":           atomic.LoadUint64(&a.suricataProfile.oversizedLines),
		"version_drift_lines":       atomic.LoadUint64(&a.suricataProfile.versionDriftLines),
		"unsupported_event_lines":   atomic.LoadUint64(&a.suricataProfile.unsupportedLines),
		"publish_errors":            atomic.LoadUint64(&a.suricataProfile.publishErrors),
		"dead_letter_dropped_lines": atomic.LoadUint64(&a.suricataProfile.deadLetterDropped),
		"last_event_at":             unixSecondsRFC3339(atomic.LoadInt64(&a.suricataProfile.lastEventUnix)),
		"last_error":                atomicString(a.suricataProfile.lastError),
	}
}

func (s *suricataProfileRuntime) observePartial(offset, size int64) bool {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingObservationValid && s.pendingOffset == offset && s.pendingSize == size {
		s.pendingObservationValid = false
		return false
	}
	s.pendingOffset = offset
	s.pendingSize = size
	s.pendingObservationValid = true
	return true
}

func (s *suricataProfileRuntime) clearPartial() {
	s.pendingMu.Lock()
	s.pendingObservationValid = false
	s.pendingMu.Unlock()
}
