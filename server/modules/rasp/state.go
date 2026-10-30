package rasp

import "time"

// RASP lifecycle states. They are deliberately five separate states: an agent
// that is installed but has never reported telemetry is not "detecting".
const (
	StateNotInstalled = "not_installed"
	StateInstalled    = "installed"
	StateCollecting   = "collecting"
	StateDetecting    = "detecting"
	StateBlocking     = "blocking"
)

// StateFacts is everything the platform actually knows about one RASP runtime.
// Unknown fields stay false/zero; nothing is inferred to make a state look
// better than it is.
type StateFacts struct {
	AgentPresent       bool      `json:"agent_present"`
	ProbeReported      bool      `json:"probe_reported"`
	EventsObserved     bool      `json:"events_observed"`
	DetectionsObserved bool      `json:"detections_observed"`
	ProtectionEnabled  bool      `json:"protection_enabled"`
	BlockMode          bool      `json:"block_mode"`
	PolicySigned       bool      `json:"policy_signed"`
	PolicyExpiresAt    time.Time `json:"policy_expires_at,omitempty"`
	EmergencyStop      bool      `json:"emergency_stop"`
	LastEventAt        time.Time `json:"last_event_at,omitempty"`
	Now                time.Time `json:"now"`
}

// ProtectionState is the resolved state plus the reason it was chosen.
type ProtectionState struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

// ResolveProtectionState maps facts onto exactly one of the five states.
// Blocking requires a signed, unexpired policy, an enabled agent and no
// emergency stop; anything less falls back to detecting/collecting.
func ResolveProtectionState(facts StateFacts) ProtectionState {
	now := facts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	switch {
	case !facts.AgentPresent:
		return ProtectionState{State: StateNotInstalled, Reason: "no_agent"}
	case !facts.ProbeReported:
		return ProtectionState{State: StateInstalled, Reason: "probe_not_reporting"}
	case facts.EmergencyStop:
		return ProtectionState{State: StateDetecting, Reason: "emergency_stop"}
	case facts.BlockMode && facts.ProtectionEnabled && facts.PolicySigned && policyUnexpired(facts.PolicyExpiresAt, now) && facts.EventsObserved:
		return ProtectionState{State: StateBlocking, Reason: "signed_policy_enforced"}
	case facts.EventsObserved:
		if facts.ProtectionEnabled {
			return ProtectionState{State: StateDetecting, Reason: "monitor_only"}
		}
		return ProtectionState{State: StateCollecting, Reason: "telemetry_without_detection_policy"}
	default:
		return ProtectionState{State: StateCollecting, Reason: "awaiting_telemetry"}
	}
}

func policyUnexpired(expiresAt, now time.Time) bool {
	if expiresAt.IsZero() {
		return false
	}
	return now.Before(expiresAt)
}
